# Verifiable AI SDK for TypeScript

This package validates NEAR AI Cloud attestation evidence and completion
signatures. It currently covers the Cloud API's NEAR model and gateway reports.

## What a successful model check establishes

`verifyNearModelAttestation` checks the caller nonce, Intel TDX quote, TCB
policy, report-data binding, RTMR3 event-log replay, raw `app_compose` to
MRCONFIGID binding, and any GPU evidence. It returns verified measurements and
the model signing identity.

It does not by itself say that those measurements are an expected NEAR
deployment. Set `requireDeploymentProvenance: true` and supply a
`provenanceVerifier` to apply your own allowlist or provenance policy. The
result exposes `provenanceVerified` so this distinction is explicit.

## Report-data bindings

The `reportDataBinding` on a verified model result records the layout that
passed. By default, `NearAiCloudClient.fetchNearModelAttestation` does not
request a TLS fingerprint, and a successful result has
`kind: 'signer_nonce'`: the Intel quote binds the model signer and the caller
nonce.

Pass `includeTlsFingerprint: true` when fetching model evidence to request the
fingerprint layout. Its successful result has
`kind: 'signer_declared_tls_nonce'` and exposes the quote-bound
`tlsCertFingerprint`. That fingerprint is declared in the Cloud API report;
because the client TLS connection terminates at the NEAR AI Cloud gateway, it
does not establish a client-to-model TLS connection. When a model report
contains a fingerprint, verification requires the signer-and-fingerprint
layout and never falls back to `signer_nonce`.

## TCB policy

The default policy accepts `UpToDate` and `OutOfDate`.
Set `allowedTcbStatuses` to use a stricter policy:

```ts
const policy = { allowedTcbStatuses: ['UpToDate'] };
```

## Handling verification failures

SDK-defined verification and Cloud API failures are `VerificationError`s. The
`failure` field is a discriminated, machine-readable contract; do not branch
on `message`.
`failure.code` identifies the failed check, `failure.phase` identifies the
verification stage, and `failure.details` carries safe context such as a TCB
status, field path, byte length, or HTTP status. It never includes API keys,
nonces, quotes, prompts, or completion bytes.

```ts
import {
  isVerificationError,
  verifyNearModelAttestation,
} from 'verification-sdk';

try {
  await verifyNearModelAttestation(input);
} catch (error) {
  if (!isVerificationError(error)) throw error;

  switch (error.failure.code) {
    case 'policy.tcb_status_not_allowed':
      console.log(error.failure.details.actual);
      break;
    case 'api.http_status':
      console.log(error.failure.details.status);
      break;
    default:
      console.log(error.failure.code, error.failure.details);
  }
}
```

Codes are grouped by phase: `input.*`, `api.*`, `quote.*`, `binding.*`,
`measurement.*`, `policy.*`, `gpu.*`, `provenance.*`, `signature.*`, and
`runtime.*`. `error.retryable` is `true` only for a transient remote-service
failure; a verification or policy failure is never retried automatically.
The underlying implementation error remains available as `error.cause` for
debugging, but is not part of the SDK contract.

## Model response flow

Use the exact bytes sent to and received from the completion endpoint. The
recommended order is:

1. Send the completion request with `x-no-aliasing: true` and retain its raw
   request and response bytes.
2. Fetch its signature. Only `provider_tee` can establish model-serving
   evidence; `gateway` is gateway-only evidence.
3. Fetch NEAR model evidence using the `provider_tee` signature's
   `signing_algo` and `signing_address`, plus a fresh nonce and the canonical
   model ID.
4. Verify the report, then verify the `provider_tee` signature against the
   same raw request and response bytes.

`provider=near` selects the evidence returned by the report query. It does
not pin an unrelated later completion request to the NEAR fleet. The response
signature and signer-filtered report are what bind the completed request to
the model evidence.

```ts
import {
  NearAiCloudClient,
  generateNonce,
  requireKnownSignature,
  verifyNearModelAttestation,
  verifyProviderTeeResponse,
} from 'verification-sdk';

const client = new NearAiCloudClient({
  baseUrl: 'https://cloud-api.near.ai/v1',
  apiKey: process.env.NEARAI_API_KEY!,
});

// `requestBody` and `responseBody` are the exact bytes from your completion.
const signature = requireKnownSignature(
  await client.fetchCompletionSignature({
    chatId,
    signingAlgo: 'ed25519',
  }),
);
if (signature.signature_kind !== 'provider_tee') {
  throw new Error('The completion has no model-serving TEE signature');
}

const nonce = generateNonce();
const modelAttestation = await client.fetchNearModelAttestation({
  model: 'your-canonical-model-id',
  nonce,
  signingAlgo: signature.signing_algo,
  signingAddress: signature.signing_address,
});
const verifiedModel = await verifyNearModelAttestation({
  attestation: modelAttestation,
  expectedNonce: nonce,
});

verifyProviderTeeResponse({
  requestBody,
  responseBody,
  signature,
  verifiedModelAttestation: verifiedModel,
});
```

## Gateway evidence

`fetchGatewayAttestation` retrieves gateway evidence without selecting a model
provider. To verify it with `verifyGatewayAttestation`, pass the SHA-256 SPKI
fingerprint from the same live TLS connection that retrieved the report and
served the response you are checking. A normal browser `fetch` cannot expose
that peer certificate or guarantee connection reuse, so `NearAiCloudClient`
does not make this claim for you.

A successful gateway result has
`reportDataBinding.kind === 'signer_peer_tls_nonce'`: the SDK has compared the
quote-bound fingerprint with the fingerprint observed on that same peer
connection.

## GPU evidence

The default NVIDIA adapter submits the payload to NVIDIA NRAS over HTTPS and
accepts only NRAS's documented boolean overall result: `true` succeeds;
`false` and any other shape fail. It does not independently validate the
returned JWT signature. Supply a custom `GpuVerifier` if local JWT/EAT
verification is required.

Third-party provider evidence is not parsed as a NEAR model report.
