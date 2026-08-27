# TypeScript verification guide

Use this SDK to verify NEAR AI Cloud attestations and completion signatures.

## Completion signature kinds

`fetchCompletionSignature` exposes Cloud API's `signature_kind` as
`signature.kind`. Cloud API selects one of two kinds for each returned
signature. The kind selects a verification path: it changes the trust boundary
and what a successful verification establishes, not only which key signed.

| `signature.kind` | Trust boundary | A successful response verification establishes | It does not establish |
| --- | --- | --- | --- |
| `provider_tee` | The model-serving TEE | A verified model TEE signer signed the exact request and response bytes. | The Cloud API Gateway's deployment or TLS identity. |
| `gateway` | The NEAR AI Cloud Gateway TEE | A verified Gateway signer signed the exact client-visible request and response bytes. | That an attested model executed or generated the response. |

Cloud API may rewrite a response before returning it—for example, when it
normalizes a stream for OpenAI compatibility. Rewriting changes the
client-visible bytes, so a byte-exact provider signature cannot verify them.
For that case, Cloud API can return a `gateway` signature for the rewritten
bytes. Use the signature kind returned for that completion; a `gateway`
signature is not evidence of model execution.

Use `provider_tee` with the model-response flow below, and `gateway` with the
Gateway-response flow.

## Choose what to verify

Both model and gateway attestations can be verified independently. You need a
completion signature only when the claim is about a particular response.

| Goal | Use it when | SDK calls | A successful result establishes | It does not establish |
| --- | --- | --- | --- | --- |
| Audit a model deployment | You want to inspect a model-serving CVM's TCB status, measurements, GPU evidence, or deployment configuration. | `fetchModelAttestations` → `verifyModelAttestation` | The quote, nonce, signer, measured deployment, and configured policy checks passed. | That any particular response came from this deployment, or that the client connected directly to its CVM. |
| Audit a Gateway endpoint | You want to inspect a Cloud API Gateway deployment and its TLS service identity. | `fetchGatewayAttestation` → `verifyGatewayAttestation` | The Gateway signer and deployment evidence are quote-verified, and the attestation request's observed TLS peer is bound to that evidence. | That any particular completion was served by the Gateway, or that a model executed the request. |
| Verify a model-issued response | The completion signature has `kind: 'provider_tee'`. | `fetchCompletionSignature` → `fetchModelAttestations` → `findModelAttestationForSignature` → `verifyModelAttestation` → `verifyModelResponse` | A verified model TEE signer signed these exact request and response bytes. | The Gateway deployment or its TLS endpoint. |
| Verify a Gateway-issued response | The completion signature has `kind: 'gateway'`. | `fetchCompletionSignature` → `fetchGatewayAttestation` → `verifyGatewayAttestation` → `verifyGatewayResponse` | A verified Gateway signer signed these exact request and response bytes. | That an attested model executed or generated the response. |

`fetchModelAttestations` preserves the Cloud API's `model_attestations` array.
The SDK currently requires exactly one returned attestation. For a deployment
audit, verify that sole item with the returned `nonce`; use
`findModelAttestationForSignature` only when selecting evidence for a
`provider_tee` response signature.

For Cloud request and verification functions, their input fields, and result
types, see the [API reference](./api-reference.md).

For normal inference verification, use the model-response flow. Use an
independent attestation flow when deployment evidence itself is the claim you
need to establish.

## Verify a model response

Use this flow only when the completion signature has `kind: 'provider_tee'`.

Keep the exact bytes sent to and received from the completion endpoint. Do not
parse and serialize them again before verification: changing JSON whitespace,
key ordering, framing, or encoding changes the signed bytes.

Send the completion with `x-no-aliasing: true` and use a canonical model ID.
The SDK uses the `model` field in the original request bytes when it verifies
the model signature.

```ts
import {
  fetchCompletionSignature,
  fetchModelAttestations,
  findModelAttestationForSignature,
  NO_ALIASING_HEADER,
  verifyModelAttestation,
  verifyModelResponse,
} from 'verification-sdk';

const apiKey = process.env.NEARAI_API_KEY;
if (!apiKey) {
  throw new Error('NEARAI_API_KEY is required');
}
const model = 'your-canonical-model-id';

const request = {
  model,
  messages: [{ role: 'user', content: 'Hello' }],
};
const requestBody = new TextEncoder().encode(JSON.stringify(request));

const completionResponse = await fetch(
  'https://cloud-api.near.ai/v1/chat/completions',
  {
    method: 'POST',
    headers: {
      authorization: `Bearer ${apiKey}`,
      'content-type': 'application/json',
      [NO_ALIASING_HEADER]: 'true',
    },
    body: requestBody,
  },
);
if (!completionResponse.ok) {
  throw new Error(`Completion failed: ${completionResponse.status}`);
}

const responseBytes = await completionResponse.arrayBuffer();
const responseBody = new Uint8Array(responseBytes);
const responseText = new TextDecoder().decode(responseBody);
const completion = JSON.parse(responseText);
if (typeof completion.id !== 'string') {
  throw new Error('Completion response did not contain an id');
}

const cloud = { apiKey };

const signature = await fetchCompletionSignature(cloud, {
  completionId: completion.id,
});
if (signature.kind !== 'provider_tee') {
  throw new Error('This completion has a Gateway signature; use the Gateway flow.');
}

const { attestations, nonce } = await fetchModelAttestations(cloud, {
  model,
  signingAlgo: signature.signer.signingAlgo,
  signingAddress: signature.signer.signingAddress,
});
const attestation = findModelAttestationForSignature({
  attestations,
  signature,
});

const verifiedAttestation = await verifyModelAttestation({
  attestation,
  nonce,
});

verifyModelResponse({
  requestBody,
  responseBody,
  signature,
  attestation: verifiedAttestation,
});
```

When `verifyModelResponse` returns, the model signature is valid for those
exact bytes and its signing identity matches `verifiedAttestation.signer`.
`fetchModelAttestations` creates a fresh client nonce, checks the service's
echo, and returns that nonce with the evidence. `findModelAttestationForSignature`
requires exactly one returned attestation to match the signature's signer.

`verifyModelResponse` verifies the response bytes and matches the signature to
`verifiedAttestation.signer`; it does not repeat quote, policy, or deployment
verification. Call `verifyModelAttestation` first. The result is ordinary data,
so your application decides when raw evidence must be verified again after
storage or transfer.

The Cloud fetch helpers retrieve signatures and evidence only. Your application
sends the completion request, retains its raw bytes, and decides whether or
when to retry a completion or signature lookup.

The helpers default to `https://cloud-api.near.ai/v1`, so `{ apiKey }` is
enough for production. Pass `baseUrl` in `cloud` only when you need another
Cloud API environment.

### What the model-attestation result contains

`verifyModelAttestation` checks the nonce, Intel TDX quote, TCB policy, runtime
measurements, and the model signing identity. Its result includes:

- `signer`, the identity that must match the completion signature;
- `tcbStatus` and `advisoryIds` from quote verification;
- `deployment`, containing the measured configuration text and runtime
  measurements;
- `gpuEvidence`, either `verified` or `not_provided`; and
- `deploymentProvenance`, either `verified` when your deployment verifier ran
  successfully or `not_checked` when none was supplied.

`tlsBinding` is `none` when no model TLS data was supplied, or `declared` when
the service declared an SPKI fingerprint. A model declaration is not proof that
the client connected directly to the model CVM.

## Verify a gateway attestation

A gateway attestation binds a verified Cloud API gateway deployment to the
TLS peer observed for its evidence request. The TLS-aware transport that
fetches the attestation must expose that request's SHA-256 SPKI fingerprint.
Browser `fetch` and most ordinary Node `fetch` APIs do not expose the peer
certificate, so this flow needs a backend transport that does. In the example,
`peerSpkiFingerprint` is the value independently captured from that request.

```ts
import {
  fetchGatewayAttestation,
  verifyGatewayAttestation,
} from 'verification-sdk';

const cloud = { apiKey, fetch: tlsAwareFetch };

const { attestation, nonce } = await fetchGatewayAttestation(cloud);

const verifiedGatewayAttestation = await verifyGatewayAttestation({
  attestation,
  nonce,
  peerSpkiFingerprint,
});
```

`tlsAwareFetch` is application code: it must return a fetch-compatible
response and record the peer fingerprint for the attestation request. Never
use the fingerprint declared inside the attestation as
`peerSpkiFingerprint`; that would compare the evidence with itself rather than
with a TLS peer you observed.

For a signature with `kind: 'gateway'`, fetch fresh evidence for the
signature's signing algorithm, verify it with the TLS peer fingerprint observed
for that fetch, then verify the response:

```ts
import {
  fetchGatewayAttestation,
  verifyGatewayAttestation,
  verifyGatewayResponse,
} from 'verification-sdk';

const { attestation, nonce } = await fetchGatewayAttestation(cloud, {
  signingAlgo: signature.signer.signingAlgo,
});
const verifiedGatewayAttestation = await verifyGatewayAttestation({
  attestation,
  nonce,
  peerSpkiFingerprint,
});

verifyGatewayResponse({
  requestBody,
  responseBody,
  signature,
  attestation: verifiedGatewayAttestation,
});
```

This verifies gateway-service provenance and integrity for the exact completion
bytes: the signature is valid and its signer is bound to the verified gateway
deployment evidence. It does not establish model execution; use a
`provider_tee` signature and model evidence for that claim.

Gateway attestation accepts the same quote and deployment policy options as
model verification, except it has no GPU option.

## Set policy and trust roots

The default policy accepts `UpToDate` and `OutOfDate` TCB statuses. GPU
evidence is verified when the report provides it; a report without GPU evidence
is accepted by default. Require GPU evidence when your application needs it:

Add these options to the `verifyModelAttestation` call in the model flow above.

```ts
import type {
  ModelAttestationPolicy,
  ModelAttestationVerifiers,
} from 'verification-sdk';

const policy: ModelAttestationPolicy = {
  acceptedTcbStatuses: ['UpToDate'],
  gpuEvidence: 'required',
};

const verifiers: ModelAttestationVerifiers = {
  // An application function that resolves only for approved deployments.
  deployment: verifyDeploymentRelease,
};

const verifiedAttestation = await verifyModelAttestation({
  attestation,
  nonce,
  policy,
  verifiers,
});
```

Here `verifyDeploymentRelease` is an application function. It receives the
measured deployment and must throw or reject for every deployment that your
release policy does not approve. The SDK provides the raw measured
configuration text; your policy should interpret it according to the
configuration format it expects rather than relying on a derived image list.

Supplying `verifiers.deployment` makes deployment acceptance a required check:
it must resolve for verification to succeed. The SDK authenticates the measured
values, but your verifier decides which deployments are acceptable.

`verifiers.quote` replaces the built-in Intel DCAP quote verifier. For model
evidence, the default NVIDIA verifier delegates to NVIDIA NRAS over HTTPS and
accepts its documented boolean overall result. It does not locally validate the
returned JWT/EAT signature. `verifiers.nvidia` replaces that verifier; supply
it when your application needs local JWT/EAT validation, different trust roots,
or another verification service. Each verifier must resolve only for evidence
it accepts and throw or reject for all other outcomes.

## Handle signature lookup and verification errors

`fetchCompletionSignature` is the simple path: it returns one completion
signature or turns a 2xx unavailable envelope into a structured
`signature.unavailable` error. It requests the service default (`ecdsa`) unless
you explicitly pass `signingAlgo: 'ed25519'`.

Use `lookupCompletionSignature` when the application needs to handle those
2xx unavailable envelopes itself. It returns one of:

- `found`, with a completion signature; or
- `unavailable`, with the service's error code and message.

A pending or unknown signature can instead produce an HTTP 404. That remains a
retryable `api.http_status` error; it is not an `unavailable` result.

For a found signature, `kind` is `provider_tee` or `gateway`, matching Cloud
API's `signature_kind`. A response without a recognized kind is rejected: the
SDK cannot select a trust boundary or response-verification path for it. Pass
the signature unchanged to the verifier that matches its kind.

Cloud API evidence retrieval and selection can throw `ApiError` for transport,
HTTP, response-format, nonce, or candidate-selection failures. Verification
functions and local input or signature-contract checks throw
`VerificationError`. Both expose `failure.code`, typed `failure.details`, and
`retryable`; branch on those fields rather than parsing a human-readable
message.

A 2xx unavailable response from `fetchCompletionSignature` is valid Cloud API
output, so it becomes a `VerificationError` with `signature.unavailable`, not
an `ApiError`.

```ts
import {
  fetchCompletionSignature,
  isApiError,
  isVerificationError,
} from 'verification-sdk';

try {
  await fetchCompletionSignature(cloud, { completionId });
} catch (error) {
  if (isApiError(error)) {
    if (error.retryable) {
      console.log('Cloud API request may succeed if retried');
    }
  } else if (isVerificationError(error)) {
    if (error.failure.code === 'signature.unavailable') {
      console.log('The completion has no usable signature');
    } else {
      console.log(error.failure.code);
    }
  } else {
    throw error;
  }
}
```

`retryable` means the SDK considers the underlying failure potentially
transient. The application still decides whether retrying or replaying a
completion is appropriate.
In particular, a `completion_signature` HTTP 404 is retryable, including when
the signature is still being recorded or is unknown.
