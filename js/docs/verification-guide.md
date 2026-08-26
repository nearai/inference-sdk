# TypeScript verification guide

Use this SDK when your application needs to verify a NEAR AI Cloud completion.
The usual goal is a **model response** claim: a model-serving TEE signed the
exact request and response bytes, and that signer is bound to fresh, verified
model evidence.

The SDK also supports a separate, advanced **gateway response** claim. It has
different requirements and does not prove that a model-serving TEE produced the
response. Start with the model-response flow below unless you specifically need
to authenticate the Cloud API gateway's TLS connection.

## Verify a model response

Keep the exact bytes sent to and received from the completion endpoint. Do not
parse and serialize them again before verification: changing JSON whitespace,
key ordering, framing, or encoding changes the signed bytes.

Send the completion with `x-no-aliasing: true` and use a canonical model ID.
The SDK uses the `model` field in the original request bytes when it verifies
the model signature.

```ts
import {
  NO_ALIASING_HEADER,
  NearAiCloudClient,
  generateNonce,
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

const nonce = generateNonce();
const attestation = await client.fetchModelAttestation({
  model,
  nonce,
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
exact bytes and its signing identity matches the verified model attestation.
The nonce makes the attestation fresh for this verification attempt.

Keep the exact `verifiedAttestation` object returned by
`verifyModelAttestation` in memory and pass it directly to
`verifyModelResponse`. Do not serialize, clone, or reconstruct it: after a
process or serialization boundary, verify the raw attestation again.

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
- `deployment`, containing the measured compose text, image digests, and
  runtime measurements;
- `gpuEvidence`, either `verified` or `not_provided`; and
- `deploymentProvenance`, either `verified` when your deployment verifier ran
  successfully or `not_checked` when none was supplied.

`tlsBinding` is `none` when no model TLS data was supplied, or `declared` when
the service declared an SPKI fingerprint. A model declaration is not proof that
the client connected directly to the model CVM.

## Set policy and trust roots

The default policy accepts `UpToDate` and `OutOfDate` TCB statuses. GPU
evidence is verified when the report provides it; a report without GPU evidence
is accepted by default. Require GPU evidence when your application needs it:

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
release policy does not approve.

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
`algorithm: 'ed25519'`.

Use `lookupCompletionSignature` when the application needs to handle those
states itself. It returns one of:

- `found`, with a completion signature; or
- `unavailable`, with the service's error code and message.

For a found signature, `source` is `model_tee`, `gateway`, or `unknown` for a
legacy record that did not store its source. Most applications simply pass the
signature unchanged to the chosen response verifier. That verifier checks the
complete signed payload, signature, and attested signer; it rejects an
explicitly incompatible source.

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

## Verify a gateway response (advanced)

Gateway verification makes a different claim: the gateway evidence is bound to
a TLS peer that your application observed. It does not establish that a
model-serving TEE produced the completion.

This flow requires a TLS transport that your application controls. It must:

1. receive the completion response, retain its exact bytes, record the
   SHA-256 SPKI fingerprint of its TLS peer, and keep that connection open;
2. use that same connection to fetch gateway evidence after obtaining the
   completion signature; and
3. pass the recorded fingerprint to `verifyGatewayAttestation`.

Ordinary browser `fetch`, and most ordinary Node `fetch` usage, cannot expose
the peer certificate or prove that a later request reused the connection. In
those environments, do not make the gateway claim. A custom connection-owning
transport must retain that relationship and pass its observed fingerprint to
`verifyGatewayAttestation`.

```ts
// `connection` owns the TLS connection used for this completion. It keeps the
// connection open, exposes its peer SPKI fingerprint, and supplies `fetch`
// for later requests on that same connection.
const completion = await connection.complete(request);

const client = new NearAiCloudClient({
  apiKey,
  fetch: connection.fetch.bind(connection),
});
const signature = await client.fetchCompletionSignature({
  completionId: completion.id,
});

const gatewayNonce = generateNonce();
const gatewayAttestation = await client.fetchGatewayAttestation({
  nonce: gatewayNonce,
  signature,
});

const verifiedGatewayAttestation = await verifyGatewayAttestation({
  attestation: gatewayAttestation,
  nonce: gatewayNonce,
  peerSpkiFingerprint: connection.peerSpkiFingerprint,
});

verifyGatewayResponse({
  requestBody: completion.requestBody,
  responseBody: completion.responseBody,
  signature,
  attestation: verifiedGatewayAttestation,
});
```

Never use a fingerprint declared inside the attestation as
`peerSpkiFingerprint`; that would compare the evidence with itself rather than
with a TLS peer you observed. Gateway verification accepts the same quote and
deployment policy options as model verification, except it has no GPU option.

## Runtime notes

The package publishes ESM. It is developed with Node.js 24, while browser
applications can bundle the same package. Public byte inputs use `Uint8Array`.
The default Intel verifier may need `crypto`, `buffer`, and `stream` polyfills
in a browser bundler. Use a custom quote verifier when your runtime or trust
model requires a different implementation.
