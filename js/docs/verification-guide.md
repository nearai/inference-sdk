# TypeScript verification guide

This guide explains how to use the TypeScript SDK to make a specific claim.
Start with the claim, because model evidence and gateway evidence have different
trust boundaries.

- A verified model response establishes that a `provider_tee` signed the exact
  completion bytes and that signer is bound to verified NEAR model evidence.
- A verified gateway response establishes that a gateway report is bound to a
  TLS peer observed by the caller on the same connection. It does not establish
  that a model-serving TEE produced the response.
- Deployment provenance is a separate caller policy. Quote and measurement
  verification alone do not say that a deployment is an expected NEAR release.

The SDK publishes ESM. Node.js 24 is used for development (see `.nvmrc`), while
browser consumers bundle the same package. Public byte inputs use `Uint8Array`,
so Node `Buffer` values work without becoming part of the browser-facing API.
Normalized quote byte values returned by the SDK use `Buffer`. The default Intel
DCAP adapter may require `crypto`, `buffer`, and `stream` polyfills in a browser
bundler. Supply a `QuoteVerifier` when your application uses different trust
roots, bundler configuration, or network controls. If a model report contains
GPU evidence, its default GPU verifier contacts NVIDIA NRAS.

## Develop from this repository

```bash
cd js
pnpm install
pnpm check
```

Biome formats and lints the TypeScript and project configuration files.
Markdown files are intentionally outside `pnpm format` and `pnpm format:check`.

## Verify a model response

Use this flow for an application-visible model response. It is important that
`requestBody` and `responseBody` are the original bytes on the wire. Parsing
and serializing them again can change whitespace, ordering, framing, or
encoding, invalidating the signature.

`verifyProviderTeeResponse` parses `requestBody` to obtain the canonical model
ID. It therefore requires UTF-8 JSON with a non-empty top-level `model` field.
The SDK can verify that body, but cannot prove that your completion client sent
the `x-no-aliasing` header; set that header on the actual request as shown.

1. Send a completion request with `x-no-aliasing: true` and keep its raw bytes.
2. Fetch the completion signature and require `provider_tee`.
3. Fetch a NEAR model report using a fresh nonce and the response signature's
   signer and algorithm.
4. Verify the report.
5. Verify the `provider_tee` signature over the same raw completion bytes.

The example below is for a non-streaming completion. A streaming client follows
the same rule: retain the exact raw SSE bytes rather than reconstructing them
from parsed events.

```ts
import {
  NO_ALIASING_HEADER,
  NearAiCloudClient,
  generateNonce,
  requireKnownSignature,
  verifyNearModelAttestation,
  verifyProviderTeeResponse,
} from 'verification-sdk';
import type { NearVerificationPolicy } from 'verification-sdk';

const baseUrl = 'https://cloud-api.near.ai/v1';
const apiKey = process.env.NEARAI_API_KEY!;
const model = 'your-canonical-model-id';

const request = {
  model,
  messages: [{ role: 'user', content: 'Hello' }],
};
const requestText = JSON.stringify(request);
const requestBody = new TextEncoder().encode(requestText);

const completionResponse = await fetch(`${baseUrl}/chat/completions`, {
  method: 'POST',
  headers: {
    authorization: `Bearer ${apiKey}`,
    'content-type': 'application/json',
    [NO_ALIASING_HEADER]: 'true',
  },
  body: requestBody,
});
if (!completionResponse.ok) {
  throw new Error(`Completion failed: ${completionResponse.status}`);
}

const responseBytes = await completionResponse.arrayBuffer();
const responseBody = new Uint8Array(responseBytes);
const responseText = new TextDecoder().decode(responseBody);
const completionJson = JSON.parse(responseText);
if (typeof completionJson?.id !== 'string') {
  throw new Error('Completion response did not contain an id');
}
const chatId = completionJson.id;

const client = new NearAiCloudClient({ baseUrl, apiKey });
const signatureLookup = await client.fetchCompletionSignature({
  chatId,
  signingAlgo: 'ed25519',
});
const signature = requireKnownSignature(signatureLookup);
if (signature.signature_kind !== 'provider_tee') {
  throw new Error('The completion has no model-serving TEE signature');
}

const nonce = generateNonce();
const modelAttestation = await client.fetchNearModelAttestation({
  model,
  nonce,
  signingAlgo: signature.signing_algo,
  signingAddress: signature.signing_address,
});
const verifiedModelAttestation = await verifyNearModelAttestation({
  attestation: modelAttestation,
  expectedNonce: nonce,
});

const verifiedResponse = verifyProviderTeeResponse({
  requestBody,
  responseBody,
  signature,
  verifiedModelAttestation,
});

console.log(verifiedResponse.scope); // "model_tee"
```

The signature lookup's `signingAlgo` selects the representation requested from
the Cloud API. This example requests `ed25519`; use `ecdsa` when that is the
representation your integration requests. Once a signature is returned, use
its `signing_algo` and `signing_address` unchanged in the model-attestation
request.

`NearAiCloudClient` does not send the completion request and does not poll the
signature endpoint. Keep retry and delivery policy in your application, where
you know whether the completion is still pending, expired, or safe to retry.

## Handle signature lookup states

`fetchCompletionSignature` returns one of three explicit states:

- `found` contains an SDK-recognized `provider_tee` or `gateway` signature.
- `unavailable` carries the Cloud API's error code and message for an absent
  usable signature.
- `unknown_kind` carries a signature type that this SDK cannot use for a
  security claim.

`requireKnownSignature` turns `unavailable` and `unknown_kind` into structured
verification errors. It does not decide which recognized signature scope is
sufficient: require `provider_tee` for model-response verification. A
`gateway` signature remains gateway-only evidence.

Cloud API and verifier errors use `VerificationError`. Branch on
`error.failure.code`, not on `error.message`. `error.retryable` is true only
for transient remote-service failures; a binding, policy, quote, measurement,
GPU, provenance, or signature error is not automatically retryable.

```ts
import { isVerificationError } from 'verification-sdk';

try {
  await verifyNearModelAttestation(input);
} catch (error) {
  if (!isVerificationError(error)) throw error;

  if (error.failure.code === 'policy.tcb_status_not_allowed') {
    console.log(error.failure.details.actual);
  } else if (error.failure.code === 'api.http_status') {
    console.log(error.failure.details.status, error.retryable);
  } else {
    console.log(error.failure.code, error.failure.details);
  }
}
```

The error contract intentionally excludes API keys, nonces, quotes, prompts,
and completion bytes. The underlying exception remains available as `cause`
for debugging, but is not part of the SDK compatibility contract.

## Interpret verified model evidence

`verifyNearModelAttestation` checks the caller nonce, Intel quote, TCB policy,
report-data binding, RTMR3 event-log replay, raw `app_compose` to MRCONFIGID
binding, and any supplied GPU evidence. A successful result contains:

- `signingAddress` and `signingAlgo`, which must match the response signature.
- `appCompose`, the original compose string whose UTF-8 bytes were measured in
  MRCONFIGID. Do not reserialize it before applying provenance policy.
- `runtimeMeasurements`, extracted during RTMR3 replay.
- `imageDigests`, syntactically extracted from the verified compose text. They
  are inputs to provenance policy, not registry or image-attestation verdicts
  produced by the SDK.
- `provenanceVerified`, which is `true` only when a caller provenance verifier
  ran and accepted the deployment. `false` means no provenance policy ran.
- `gpuVerified`, which is present only when GPU evidence was supplied and
  verified. Its absence is not a negative GPU verdict.

### Report-data bindings

The `reportDataBinding` field records which Intel quote layout was verified.

```ts
switch (verifiedModelAttestation.reportDataBinding.kind) {
  case 'signer_nonce':
    // Default model layout: the quote binds the signer and the fresh nonce.
    break;
  case 'signer_declared_tls_nonce':
    // The quote also binds a server-declared TLS fingerprint. This is not a
    // client-observed TLS connection to the model CVM.
    console.log(verifiedModelAttestation.reportDataBinding.tlsCertFingerprint);
    break;
}
```

Model evidence defaults to `signer_nonce`. Pass `includeTlsFingerprint: true`
to `fetchNearModelAttestation` to ask the Cloud API for a fingerprint. Inspect
the returned `reportDataBinding.kind` if your application requires
`signer_declared_tls_nonce`: the SDK selects the layout from the evidence it
actually receives. When a model report declares a TLS fingerprint, the SDK
requires its signer-and-fingerprint layout and never downgrades it to the
legacy signer-only layout.

A model result never produces `signer_peer_tls_nonce`, because the client TLS
connection terminates at the Cloud API gateway rather than the model CVM.

## Apply a policy and custom trust roots

The default policy accepts `UpToDate` and `OutOfDate` TCB statuses, accepts
CPU-only CVMs, and leaves deployment provenance optional. Tighten all three
when your application needs them:

```ts
const policy: NearVerificationPolicy = {
  allowedTcbStatuses: ['UpToDate'],
  requireGpuEvidence: true,
  requireDeploymentProvenance: true,
};
```

`requireGpuEvidence` rejects a model report with no GPU evidence. It does not
make invalid GPU evidence optional: a supplied GPU payload must always verify.

Do not use `requireDeploymentProvenance: true` by itself. Pass a
`provenanceVerifier` with that policy; otherwise verification rejects with
`policy.provenance_verifier_required`.

The SDK exposes three verification hooks. Each is a trust boundary: resolve
only for a fully accepted input and reject or throw for failed or indeterminate
inputs.

- `QuoteVerifier` authenticates the Intel quote and derives its measurements.
  Without one, the SDK uses its Intel DCAP verifier.
- `GpuVerifier` validates NVIDIA evidence. Without one, model GPU evidence is
  sent to the default NVIDIA NRAS verifier.
- `ProvenanceVerifier` receives the verified raw compose string, extracted
  image digests, and replayed runtime measurements. It is where an application
  enforces expected image or deployment provenance.

The SDK deliberately does not embed a deployment allowlist or turn a registry
lookup into a provenance verdict. Set `requireDeploymentProvenance: true` when
a successful model check must include your deployment acceptance policy.

## Verify gateway evidence

Gateway verification is a different claim from model response verification. It
requires a TLS transport you control:

1. Request `/attestation/report` with `include_tls_fingerprint=true`.
2. Read the SHA-256 SPKI fingerprint from the exact live TLS peer that served
   that report.
3. Pass the returned `gateway_attestation`, the same request nonce, and that
   observed fingerprint to `verifyGatewayAttestation`.
4. Establish that the application-visible gateway response you are checking
   used that same TLS connection.

For a Node transport that owns the socket, derive the fingerprint from the
certificate presented on that socket. Call this while handling the same TLS
connection that fetched the report; it does not establish connection reuse on
its own.

```ts
import { createHash, X509Certificate } from 'node:crypto';

function spkiFingerprint(certificateDer: Buffer): string {
  const certificate = new X509Certificate(certificateDer);
  const spki = certificate.publicKey.export({ type: 'spki', format: 'der' });
  const hash = createHash('sha256');
  hash.update(spki);
  return hash.digest('hex');
}

// For example: spkiFingerprint(tlsSocket.getPeerCertificate(true).raw)
```

In the following snippets, `gatewayAttestation` and
`peerFingerprintFromTheSameTlsSocket` come from that controlled report request.
`requestBody`, `responseBody`, and `chatId` are the exact values retained from
the completion flow.

```ts
import {
  verifyGatewayAttestation,
  verifyGatewayResponse,
} from 'verification-sdk';

const verifiedGatewayAttestation = await verifyGatewayAttestation({
  attestation: gatewayAttestation,
  expectedNonce: nonce,
  peerTlsCertFingerprint: peerFingerprintFromTheSameTlsSocket,
});

console.log(verifiedGatewayAttestation.reportDataBinding.kind);
// "signer_peer_tls_nonce"
```

If the application also needs to authenticate the exact response bytes at
gateway scope, require a `gateway` signature and verify it against the gateway
attestation. This still does not produce a model-serving claim.

```ts
const gatewaySignatureLookup = await client.fetchCompletionSignature({
  chatId,
  signingAlgo: 'ed25519',
});
const gatewaySignature = requireKnownSignature(gatewaySignatureLookup);
if (gatewaySignature.signature_kind !== 'gateway') {
  throw new Error('The completion has no gateway signature');
}

const verifiedGatewayResponse = verifyGatewayResponse({
  requestBody,
  responseBody,
  signature: gatewaySignature,
  verifiedGatewayAttestation,
});

console.log(verifiedGatewayResponse.scope); // "gateway"
```

`fetchGatewayAttestation` requests the report fingerprint automatically, but a
normal browser or Node `fetch` API cannot expose the peer certificate or prove
connection reuse. Use a connection-owning TLS transport when making this claim.

Do not pass `gatewayAttestation.tls_cert_fingerprint` as
`peerTlsCertFingerprint`. That would compare the report's declared value with
itself instead of comparing it with a TLS peer you observed.

`fetchNearAiCloudAttestationReport` returns a parsed model-report envelope for
inspection. Its `gateway_attestation` entry is not a substitute for the
same-connection gateway flow: model evidence omits the TLS fingerprint by
default, and `NearAiCloudClient` does not collect a peer certificate.

## Provider scope

Model convenience methods set `provider=near` and send `x-no-aliasing: true`.
This selects NEAR model evidence and keeps the model ID used in the signature
payload canonical. It does not pin a separate future completion request to a
particular CVM. The `provider_tee` signature and signer-filtered attestation
are what bind a completed request to verified model evidence.

The SDK intentionally does not parse third-party provider evidence as a NEAR
model report.
