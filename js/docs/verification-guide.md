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
| Audit a Gateway endpoint | You want to inspect a Cloud API Gateway deployment and, by default, its TLS service identity. | `fetchGatewayAttestation` → `verifyGatewayAttestation` | The Gateway signer and deployment evidence are verified. With the default TLS policy, the observed TLS peer also matches the fingerprint bound into the quote. | That any particular completion was served by the Gateway, or that a model executed the request. |
| Verify a model-issued response | The completion signature has `kind: 'provider_tee'`. | `fetchCompletionSignature` → `fetchModelAttestations` → `findModelAttestationForSignature` → `verifyModelAttestation` → `verifyModelResponse` | A verified model TEE signer signed these exact request and response bytes. | The Gateway deployment or its TLS endpoint. |
| Verify a Gateway-issued response | The completion signature has `kind: 'gateway'`. | `fetchCompletionSignature` → `fetchGatewayAttestation` → `verifyGatewayAttestation` → `verifyGatewayResponse` | A verified Gateway signer signed these exact request and response bytes. | That an attested model executed or generated the response. |

`fetchModelAttestations` preserves the Cloud API's `model_attestations` array.
The SDK currently requires exactly one returned attestation. For a deployment
audit, verify that sole item with the returned `clientBinding`; use
`findModelAttestationForSignature` only when selecting evidence for a
`provider_tee` response signature.

For Cloud request and verification functions, their parameter fields, and result
types, see the [API reference](./api-reference.md).

For normal inference verification, use the model-response flow. Use an
independent attestation flow when deployment evidence itself is the claim you
need to establish.

## Verify a model response

Use this flow only when the completion signature has `kind: 'provider_tee'`.

The SDK does not send inference requests. Before this flow, your application
must have sent a completion with `x-no-aliasing: true` using a canonical model
ID, then retained that model ID, the completion ID, and the exact request and
response bytes. Do not parse and serialize those bytes again: changing JSON
whitespace, key ordering, framing, or encoding changes the signed bytes.

```ts
import {
  fetchCompletionSignature,
  fetchModelAttestations,
  findModelAttestationForSignature,
  verifyModelAttestation,
  verifyModelResponse,
} from 'verifiable-ai-sdk';

const apiKey = process.env.NEARAI_API_KEY;
if (!apiKey) {
  throw new Error('NEARAI_API_KEY is required');
}

// model, completionId, requestBody, and responseBody were retained by your
// application's inference request.

const signature = await fetchCompletionSignature({
  apiKey,
  completionId,
});
if (signature.kind !== 'provider_tee') {
  throw new Error('This completion has a Gateway signature; use the Gateway flow.');
}

const { attestations, clientBinding } = await fetchModelAttestations({
  apiKey,
  model,
});
const attestation = findModelAttestationForSignature({
  attestations,
  signature,
});

const verifiedAttestation = await verifyModelAttestation({
  attestation,
  clientBinding,
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
echo, and returns it in `clientBinding` with the evidence.
`findModelAttestationForSignature` requires exactly one returned attestation to
match the signature's signer.

`signingAlgo` and `signingAddress` are optional Cloud API request filters. They
can narrow the evidence response, but they do not replace the local signer
match above.

`verifyModelResponse` verifies the response bytes and matches the signature to
`verifiedAttestation.signer`; it does not repeat quote, policy, or deployment
verification. Call `verifyModelAttestation` first. The result is ordinary data,
so your application decides when raw evidence must be verified again after
storage or transfer.

The Cloud fetch helpers retrieve signatures and evidence only. Your application
sends the completion request, retains its raw bytes, and decides whether or
when to retry a completion or signature lookup.

The helpers default to `https://cloud-api.near.ai/v1`, so `{ apiKey }` is
enough for production. Add `baseUrl` to the same params object only when you
need another Cloud API environment.

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

Model fetches always request `include_tls_fingerprint=false`. Cloud API
connects to the model on the client's behalf, so this flow verifies the
signer-and-nonce quote binding but does not establish a client-to-model TLS
binding.

## Verify a gateway attestation

A Gateway attestation verifies a Cloud API Gateway deployment. By default, it
also verifies the Gateway TLS identity: the helper sends a fresh nonce,
requests the TLS fingerprint, and checks it against the TLS peer that served
the evidence request.

```ts
import {
  fetchGatewayAttestation,
  verifyGatewayAttestation,
} from 'verifiable-ai-sdk';

const fetchedGatewayAttestation = await fetchGatewayAttestation({
  apiKey,
});
const verifiedGatewayAttestation = await verifyGatewayAttestation(
  fetchedGatewayAttestation,
);
```

In Node, the package captures the SHA-256 SPKI fingerprint of the TLS peer
that served this evidence request. The default policy (`verifyTlsBinding: true`)
requires it to match the fingerprint bound into the quote. A successful result
then has `tlsBinding.kind: 'attested'`.

Browser fetch does not expose peer certificates. Disable TLS binding when
fetching Gateway evidence; the returned policy is then passed directly to the
verifier with the rest of the fetched result:

```ts
const fetchedGatewayAttestation = await fetchGatewayAttestation({
  apiKey,
  policy: { verifyTlsBinding: false },
});
const verifiedGatewayAttestation = await verifyGatewayAttestation(
  fetchedGatewayAttestation,
);
```

With TLS binding disabled, the fetch request uses
`include_tls_fingerprint=false` and verification checks the signer-and-nonce
quote layout. The result has `tlsBinding.kind: 'none'`; it makes no TLS claim.

For a signature with `kind: 'gateway'`, fetch fresh evidence for the
signature's signing algorithm, verify it, then verify the response:

```ts
import {
  fetchGatewayAttestation,
  verifyGatewayAttestation,
  verifyGatewayResponse,
} from 'verifiable-ai-sdk';

const fetchedGatewayAttestation = await fetchGatewayAttestation({
  apiKey,
  signingAlgo: signature.signer.signingAlgo,
});
const verifiedGatewayAttestation = await verifyGatewayAttestation(
  fetchedGatewayAttestation,
);

verifyGatewayResponse({
  requestBody,
  responseBody,
  signature,
  attestation: verifiedGatewayAttestation,
});
```

For this flow in a browser, fetch Gateway evidence with
`policy: { verifyTlsBinding: false }` as shown above before calling
`verifyGatewayResponse`.

This verifies gateway-service provenance and integrity for the exact completion
bytes: the signature is valid and its signer is bound to the verified gateway
deployment evidence. It does not establish model execution; use a
`provider_tee` signature and model evidence for that claim.

Gateway attestation accepts the same quote and deployment policy options as
model verification, except it has no GPU option. Its
`GatewayAttestationPolicy` also controls whether Gateway TLS binding is used.

## Set policy and trust roots

The default policy accepts `UpToDate` and `OutOfDate` TCB statuses. GPU
evidence is verified when the report provides it; a report without GPU evidence
is accepted by default. Require GPU evidence when your application needs it:

Add these options to the `verifyModelAttestation` call in the model flow above.

```ts
import type {
  ModelAttestationPolicy,
  ModelAttestationVerifiers,
} from 'verifiable-ai-sdk';

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
  clientBinding,
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
signature or throws a structured error. It requests the service default
(`ecdsa`) unless you explicitly pass `signingAlgo: 'ed25519'`.

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

Cloud API request helpers and evidence selection can throw `ApiError` for
transport, HTTP, response-format, nonce, unavailable-signature, or
candidate-selection failures. Verification functions and local input or
signature-contract checks throw `VerificationError`.

| Field | Meaning |
| --- | --- |
| `error.failure.code` | Stable code for a program to branch on. TypeScript narrows `error.failure.details` from this code. |
| `error.failure.details` (when present) | Code-specific diagnostic context, such as a response field, status, or signer-selection count. Do not parse `error.message`. |
| `error.retryable` | A new attempt at the failed external operation may succeed. It does not mean that re-verifying the same evidence will succeed or that an inference should be replayed. |

A 2xx unavailable response from `fetchCompletionSignature` is an `ApiError`
with code `api.completion_signature_unavailable`: the strict helper could not
return the completion signature it promises. Prefer
`lookupCompletionSignature` when this is an ordinary application state.

```ts
import {
  fetchCompletionSignature,
  isApiError,
  isVerificationError,
} from 'verifiable-ai-sdk';

try {
  await fetchCompletionSignature({ apiKey, completionId });
} catch (error) {
  if (isApiError(error)) {
    switch (error.failure.code) {
      case 'api.completion_signature_unavailable':
        console.log('The completion has no usable signature');
        break;
      case 'api.http_status':
        if (error.retryable) {
          console.log('A later signature lookup may succeed');
        }
        break;
    }
  } else if (isVerificationError(error)) {
    console.log(error.failure.code);
  } else {
    throw error;
  }
}
```

A `completion_signature` HTTP 404 is retryable, including when the signature
is still being recorded or is unknown.
