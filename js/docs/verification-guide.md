# TypeScript verification guide

Verify a completion in three stages:

1. Verify the Gateway deployment and target model deployment before sending
   the completion.
2. Send the completion and preserve its exact request and response bytes.
3. Fetch the completion signature and use its `kind` to verify the bytes
   against the corresponding preflight result.

`AttestationClient` retrieves Cloud API evidence and signatures. The SDK does
not send completions itself; your application owns the inference request, raw
bytes, and retry policy.

## Before the completion: verify both deployments

Use a canonical model ID and choose one signing algorithm for this operation.
Verify the Gateway and model evidence before the completion request. The Node
client below also checks the TLS peer for the Gateway evidence request.
Pass the same explicit algorithm to both attestation fetches and the completion
signature fetch: Cloud API's report and signature endpoints have different
defaults.

```ts
import {
  AttestationClient,
  verifyGatewayAttestation,
  verifyModelAttestation,
} from 'verifiable-ai-sdk/node';

const apiKey = process.env.NEARAI_API_KEY;
if (!apiKey) {
  throw new Error('NEARAI_API_KEY is required');
}

const MODEL = 'z-ai/glm-5.2';
const SIGNING_ALGO = 'ecdsa';
const client = new AttestationClient({ apiKey });

const verifiedGatewayAttestation = await verifyGatewayDeployment();
const verifiedModelAttestations = await verifyModelDeployments();

async function verifyGatewayDeployment() {
  const fetched = await client.fetchGatewayAttestation({
    signingAlgo: SIGNING_ALGO,
  });
  return verifyGatewayAttestation({
    attestation: fetched.attestation,
    clientBinding: fetched.clientBinding,
  });
}

async function verifyModelDeployments() {
  const fetched = await client.fetchModelAttestations({
    model: MODEL,
    signingAlgo: SIGNING_ALGO,
  });
  if (fetched.attestations.length === 0) {
    throw new Error('Cloud API returned no model attestations');
  }
  const preflight = [];
  for (const attestation of fetched.attestations) {
    preflight.push({
      attestation,
      verified: await verifyModelAttestation({
        attestation,
        clientBinding: fetched.clientBinding,
      }),
    });
  }
  return preflight;
}
```

Cloud API may return zero or multiple model attestations. The fetch helper
preserves the collection and checks the returned nonce on every item. This
deployment-first flow rejects an empty collection, verifies every candidate,
and retains each candidate with its verified result for receipt selection.

Model evidence always uses the signer-and-nonce quote layout. Cloud API makes
the model connection on the client's behalf, so model verification does not
make a client-to-model TLS claim.

The generic `verifiable-ai-sdk` entry point is suitable when TLS peer
observation is unavailable, including browsers. Its Gateway request uses the
same signer-and-nonce layout and returns `tlsBinding.kind: 'none'`. The Node
entry point above requests and verifies the Gateway TLS SPKI fingerprint by
default.

## Send the completion

Only after both deployment checks succeed, send the completion. Use the same
canonical model ID and `x-no-aliasing: true`. Retain the exact bytes sent and
received; parsing and serializing JSON or SSE again changes the signed payload.

```ts
const { completionId, requestBody, responseBody } = await sendCompletion({
  model: MODEL,
  headers: { 'x-no-aliasing': 'true' },
});
```

`sendCompletion` is application code. It must return the completion ID and
unaltered `Uint8Array` values for the HTTP request and response. For streams,
`responseBody` includes the original SSE framing.

## Verify the completion receipt

Fetch the signature after the completion returns. `signature.kind` selects the
response verifier; it does not decide which deployments to verify. Both
preflight values remain part of the operation.

```ts
import {
  findModelAttestationForSignature,
  verifyGatewayResponse,
  verifyModelResponse,
} from 'verifiable-ai-sdk/node';

const signature = await client.fetchCompletionSignature({
  completionId,
  signingAlgo: SIGNING_ALGO,
});

if (signature.kind === 'provider_tee') {
  const attestation = findModelAttestationForSignature({
    attestations: verifiedModelAttestations.map(
      ({ attestation }) => attestation,
    ),
    signature,
  );
  const selected = verifiedModelAttestations.find(
    (candidate) => candidate.attestation === attestation,
  );
  if (selected === undefined) {
    throw new Error('Selected model attestation was not preflight verified');
  }
  verifyModelResponse({
    requestBody,
    responseBody,
    signature,
    attestation: selected.verified,
  });
} else {
  verifyGatewayResponse({
    requestBody,
    responseBody,
    signature,
    attestation: verifiedGatewayAttestation,
  });
}
```

`verifyModelResponse` requires a `provider_tee` signature and matches its
signer to the selected result in `verifiedModelAttestations`.
`verifyGatewayResponse` requires a
`gateway` signature and matches its signer to `verifiedGatewayAttestation`.
Each verifier also verifies the signature over the exact request and response
bytes. A signer mismatch fails naturally; do not fetch unrelated evidence to
make the check pass.

Cloud API returns `gateway` when it signs client-visible bytes that a provider
signature cannot cover, such as a rewritten response. It returns `provider_tee`
when the model-serving TEE signs those bytes directly.

## Current evidence boundary

The preflight Gateway and model attestations establish two verified deployments.
The completion signature binds the returned bytes to one of their signers,
according to `kind`. They do not yet prove a complete chain from the model's
upstream response through a Gateway transformation to the final bytes.

For a `gateway` signature, a successful result proves that the verified Gateway
signed the exact final bytes. It does not cryptographically prove that the
verified model produced the upstream response. For a `provider_tee` signature,
a successful result proves model-signature provenance for the bytes, but does
not cryptographically bind it to the preflight Gateway evidence.

Cloud API tracks a paired provider signature and Gateway receipt for rewritten
responses in [cloud-api#986](https://github.com/nearai/cloud-api/issues/986).
Until that exists, do not claim the complete chain from these separate pieces of
evidence.

## Set policy and trust roots

The default policy accepts `UpToDate` and `OutOfDate` TCB statuses. Model GPU
evidence is verified when present and is optional by default. Require it when
your application needs that guarantee:

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
  // Resolve only for deployments your application accepts.
  deployment: verifyDeploymentRelease,
};

return verifyModelAttestation({
  attestation,
  clientBinding,
  policy,
  verifiers,
});
```

Use these options in `verifyModelDeployments` when constructing the preflight
result. `verifiers.deployment` receives authenticated measured deployment data
and must reject every deployment your release policy does not accept. The SDK
authenticates measured values; your callback decides which values are trusted.

`verifiers.quote` replaces the built-in Intel DCAP verifier. `verifiers.nvidia`
replaces the default NVIDIA NRAS verifier. Each callback must resolve only for
evidence it accepts and throw or reject every other outcome.

## Handle errors

`fetchCompletionSignature` returns a signature or throws `ApiError`. A 2xx
unavailable result is `api.completion_signature_unavailable` and includes
`providerErrorCode` and `providerMessage`. An HTTP 404 is
`api.http_status`; it is retryable because a request made before a completion
reaches its terminal state can later succeed, although an unknown ID can also
produce 404.

`AttestationClient` and `findModelAttestationForSignature` throw `ApiError`
for caller input, transport, response-format, nonce, or attestation-selection
failures. Handle those calls separately from explicit `verify…` calls, which
throw `VerificationError`. A client or selection handler only needs to handle
`ApiError`; a verification handler only needs to handle `VerificationError`.

```ts
import { ApiError } from 'verifiable-ai-sdk';

try {
  await client.fetchCompletionSignature({ completionId });
} catch (error) {
  if (!(error instanceof ApiError)) throw error;
  console.log(error.failure.code, error.failure.details);
}
```

Use `error.failure.code` for program logic, not the error message.
