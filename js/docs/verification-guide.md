# TypeScript verification guide

Use this SDK to verify NEAR AI Cloud attestations and completion signatures.

## Choose what to verify

An attestation establishes properties of a deployment. A response signature is
the separate proof that binds the exact request and response bytes to that
deployment's signer.

Both model and gateway attestations can be verified independently. You need a
completion signature only when the claim is about a particular response.

| Goal | Use it when | SDK calls | A successful result establishes | It does not establish |
| --- | --- | --- | --- | --- |
| Audit a model deployment | You want to inspect a model-serving CVM's TCB status, measurements, GPU evidence, or deployment configuration. | `verifyModelAttestation` | The quote, nonce, signer, measured deployment, and configured policy checks passed. | That any particular response came from this deployment, or that the client connected directly to its CVM. |
| Audit a Gateway endpoint | You want to inspect a Cloud API Gateway deployment and its TLS service identity. | `fetchGatewayAttestation` → `verifyGatewayAttestation` | The Gateway signer and deployment evidence are quote-verified, and the attestation request's observed TLS peer is bound to that evidence. | That any particular completion was served by the Gateway, or that a model executed the request. |
| Verify a model-issued response | The completion signature has `kind: 'provider_tee'`. | `fetchCompletionSignature` → `fetchModelAttestations` → `findModelAttestationForSignature` → `verifyModelAttestation` → `verifyModelResponse` | A verified model TEE signer signed these exact request and response bytes. | The Gateway deployment or its TLS endpoint. |
| Verify a Gateway-issued response | The completion signature has `kind: 'gateway'`. | `fetchCompletionSignature` → `fetchGatewayAttestation` → `verifyGatewayAttestation` → `verifyGatewayResponse` | A verified Gateway signer signed these exact request and response bytes. | That an attested model executed or generated the response. |

Never infer `kind` from signed text. Pair a `provider_tee` signature with model
evidence, and a `gateway` signature with Gateway evidence.

For every exported function, input field, result type, and error type, see the
[API reference](./api-reference.md).

For normal inference verification, use the model-response flow. Use an
independent attestation flow when deployment evidence itself is the claim you
need to establish.

## Verify a model response

Keep the exact bytes sent to and received from the completion endpoint. Do not
parse and serialize them again before verification: changing JSON whitespace,
key ordering, framing, or encoding changes the signed bytes.

Send the completion with `x-no-aliasing: true` and use a canonical model ID.
The SDK uses the `model` field in the original request bytes when it verifies
the model signature.

```ts
import {
  findModelAttestationForSignature,
  NO_ALIASING_HEADER,
  NearAiCloudClient,
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

const client = new NearAiCloudClient({ apiKey });

const signature = await client.fetchCompletionSignature({
  completionId: completion.id,
});

const { attestations, nonce } = await client.fetchModelAttestations({
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

`NearAiCloudClient` fetches signatures and evidence only. Your application
sends the completion request, retains its raw bytes, and decides whether or
when to retry a completion or signature lookup.

The client defaults to `https://cloud-api.near.ai/v1`, so `{ apiKey }` is
enough for production. Pass `baseUrl` only when you need another Cloud API
environment.

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
  NearAiCloudClient,
  verifyGatewayAttestation,
} from 'verification-sdk';

const client = new NearAiCloudClient({ apiKey, fetch: tlsAwareFetch });

const { attestation, nonce } = await client.fetchGatewayAttestation();

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

When `signature.kind` is `gateway`, fetch fresh evidence for the signature's
signing algorithm, verify it with the TLS peer fingerprint observed for that fetch,
then verify the response:

```ts
import {
  verifyGatewayAttestation,
  verifyGatewayResponse,
} from 'verification-sdk';

const { attestation, nonce } = await client.fetchGatewayAttestation({
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
evidence, `verifiers.nvidia` replaces the default NVIDIA NRAS verifier. Supply
either when your application uses its own trust roots or verification service.
Each verifier must resolve only for evidence it accepts and throw or reject for
all other outcomes.

## Handle signature lookup and verification errors

`fetchCompletionSignature` is the simple path: it returns one completion
signature or throws a structured error when the signature is unavailable.
It requests the service default (`ecdsa`) unless you explicitly pass
`signingAlgo: 'ed25519'`.

Use `lookupCompletionSignature` when the application needs to handle those
states itself. It returns one of:

- `found`, with a completion signature; or
- `unavailable`, with the service's error code and message.

For a found signature, `kind` is `provider_tee` or `gateway`, matching Cloud
API's `signature_kind`. A response without a recognized `signature_kind` is
rejected; the SDK never infers a kind from the signed text. Most applications
simply pass the signature unchanged to the matching response verifier, which
checks the complete signed payload,
signature, and attested signer.

All SDK failures are `VerificationError` instances, including Cloud API
failures. Branch on `failure.code`, rather than parsing a human-readable error
message:

```ts
import { isVerificationError } from 'verification-sdk';

try {
  await verifyModelAttestation({ attestation, nonce });
} catch (error) {
  if (!isVerificationError(error)) throw error;

  if (error.failure.code === 'policy.tcb_status_not_allowed') {
    console.log('TCB status:', error.failure.details.actual);
  } else if (error.failure.code === 'api.http_status') {
    console.log('HTTP status:', error.failure.details.status);
  } else {
    console.log(error.failure.code);
  }
}
```

`error.retryable` is true only for remote failures that the SDK considers
transient. A failed signature, binding, quote, measurement, GPU, deployment,
or policy check is not automatically safe to retry.
In particular, a `completion_signature` HTTP 404 is retryable because the
signature may still be being recorded.
