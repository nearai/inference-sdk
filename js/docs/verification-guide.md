# TypeScript verification guide

Use `SecureClient` for Chat Completions with deployment verification and E2EE.
Use `AttestationClient` and the standalone verification functions to manage
the verification steps yourself.

## Send an E2EE chat completion

`SecureClient` uses OpenAI Chat Completions types and enables E2EE by default.
Before sending a request, it verifies Gateway and model evidence or reuses
cached results. A verification failure prevents the request from being sent.

This Node.js example connects directly to the Gateway with a server-side API
key. The Node client verifies the Gateway's TLS identity and pins subsequent
requests to that identity. For browser applications, see
[Connect through an application proxy](#connect-through-an-application-proxy).

```ts
import { SecureClient } from 'verifiable-ai-sdk/node';

const model = 'z-ai/glm-5.3-flash';
const client = new SecureClient({
  apiKey: process.env.NEARAI_API_KEY!,
});

const completion = await client.chat.completions.create({
  model,
  messages: [{ role: 'user', content: 'Hello' }],
});

console.log(completion.choices[0].message.content);
```

To select ECDSA instead of the default Ed25519 protocol:

```ts
const client = new SecureClient({
  apiKey: process.env.NEARAI_API_KEY!,
  signingAlgo: 'ecdsa',
});
```

`signingAlgo` selects the algorithm for attestation, model-key routing, E2EE,
and response signatures. The client verifies all returned model attestations
before selecting a key for that algorithm.

### Cache deployment verification

`attestationCacheTimeToLiveMs` defaults to `900000` (15 minutes). Concurrent
requests for the same model share verification work and cached results.
Increase the value to check deployments less frequently, or set `0` to
verify before every request. Deployment changes are not checked while a cached
result is reused. This setting controls caching, not attestation validity.

The SDK does not check model measurements against an approved-deployment
allowlist by default. If needed, supply a `deploymentPolicy` callback and
throw an error to reject a deployment.

## Connect through an application proxy

A proxy lets your backend keep the NEAR AI API key while users' devices verify
evidence and encrypt prompts. Direct server-to-Gateway integrations do not
need a proxy.

Set `baseUrl` to your backend's API endpoint and `headers` to the credentials
it accepts:

```ts
import { SecureClient } from 'verifiable-ai-sdk';

const client = new SecureClient({
  baseUrl: 'https://api.example.com/v1',
  headers: {
    Authorization: 'Bearer <browser-scoped token>',
  },
});
```

The proxy must forward `/v1/attestation/report`, `/v1/chat/completions`, and
`/v1/signature/{id}`. It authenticates the user and supplies its upstream
NEAR AI credential. Preserve the request and response bodies, model-key routing header,
and encryption headers unchanged so decryption and signature verification work.

Browser Fetch does not expose the TLS peer certificate, so the generic client
does not verify Gateway TLS binding. Depending on the browser build, the default
Intel verifier may need `crypto`, `buffer`, and `stream` polyfills. A custom
quote verifier can be supplied through `gatewayVerification.verifiers.quote`
and `modelVerification.verifiers.quote`.

For a Node client connecting through a proxy, disable Gateway TLS binding
because the observed certificate belongs
to the proxy:

```ts
import { SecureClient } from 'verifiable-ai-sdk/node';

const client = new SecureClient({
  baseUrl: 'https://api.example.com/v1',
  headers: {
    Authorization: 'Bearer <server-scoped token>',
  },
  gatewayVerification: { includeSpkiFingerprint: false },
});
```

## E2EE scope and response handling

The client supports `POST /v1/chat/completions` with a model public key bound
to verified attestation. Responses API and other endpoints are not supported.

Ed25519 uses version 2 field encryption. ECDSA uses the legacy secp256k1 ECDH
and AES-GCM format and omits `X-Encryption-Version: 2`, which selects the
Ed25519 format. Both send `X-Encrypt-All-Fields: true` to enable encryption
of the supported fields below. Other fields are forwarded unchanged.

| Capability | E2EE behavior |
| --- | --- |
| String `messages[].content` | Each string is encrypted independently. |
| Rich message content | An array-valued `messages[].content` is serialized and encrypted as one value. |
| Assistant context | String `reasoning_content`, `reasoning`, and `audio.data` message fields are encrypted. |
| Function and tool fields | Recognized function definitions, function calls, and related message fields are encrypted. Other tool forms are preserved without E2EE transformation. |
| `web_context_search` | The request is forwarded normally; supported search-tool output is decrypted. |
| Other Chat request-body fields | Forwarded without encryption. |
| Streaming Chat | Each complete SSE event is decrypted before it reaches the caller. |

The client checks each encrypted field's authentication tag before decryption.
Use `verifyResponse(id)` separately to verify the response's signing identity.

URL query parameters, headers, and fields outside the table are not encrypted.
Non-2xx responses follow the normal OpenAI error path.

### Stream an E2EE completion

```ts
const stream = await client.chat.completions.create({
  model,
  messages: [{ role: 'user', content: 'Hello' }],
  stream: true,
});

for await (const chunk of stream) {
  process.stdout.write(chunk.choices[0]?.delta.content ?? '');
}
```

### Send plaintext after deployment verification

Set `e2ee: false` to send plaintext. Gateway and model verification,
deployment policy, and response verification remain available.

```ts
const client = new SecureClient({
  apiKey: process.env.NEARAI_API_KEY!,
  e2ee: false,
});
```

Plaintext requests still use a verified model public key for routing, so the
model must expose a key for the configured signing algorithm.
They send `X-Model-Pub-Key` without the encryption headers. Attestation and
signature lookups still use the configured `signingAlgo`.

## Verify a response

The client retains the exact request and response bytes before E2EE decryption.
Display the completion normally, then verify its signature by ID:

```ts
const completion = await client.chat.completions.create({
  model,
  messages: [{ role: 'user', content: 'Hello' }],
});
render(completion.choices[0]?.message.content);
const verified = await client.verifyResponse(completion.id);
console.log(verified.signatureKind);
```

For streams, consume the stream before awaiting verification:

```ts
const stream = await client.chat.completions.create({
  model,
  messages: [{ role: 'user', content: 'Hello' }],
  stream: true,
});
let completionId: string | undefined;
for await (const chunk of stream) {
  completionId = chunk.id;
  renderIncrementally(chunk);
}
if (completionId !== undefined) {
  const verified = await client.verifyResponse(completionId);
  console.log(verified.signatureKind);
}
```

Each ID identifies its own request bytes, response bytes, and verified deployment
evidence. Concurrent requests can finish in any order. Repeated verification of
the same ID shares the in-flight operation and its result. After a retryable
API failure, call `verifyResponse(id)` again to retry the signature lookup.
Successful results and non-retryable failures remain cached.

Response records retain complete bodies in memory. They expire
`responseCacheTimeToLiveMs` after body completion (default: 15 minutes),
independently of the attestation cache. Unknown or expired IDs produce
`ApiError` with code `api.completion_not_found`. For active streams, memory
grows with the received body until the application finishes or cancels reading.

A `provider_tee` signature must match the verified model signer selected for
the request's `X-Model-Pub-Key`.
A `gateway` signature binds them to a verified Gateway signer; it does not
by itself prove model execution.

### Use the official OpenAI SDK

Create both clients once. The same Fetch adapter supports sequential and
concurrent requests, with the standard OpenAI retry behavior:

```ts
import OpenAI from 'openai';

const openai = new OpenAI({
  apiKey,
  baseURL: client.getBaseUrl(),
  fetch: client.fetch,
});
const completion = await openai.chat.completions.create({
  model,
  messages: [{ role: 'user', content: 'Hello' }],
});
render(completion.choices[0]?.message.content);
const verified = await client.verifyResponse(completion.id);
```

Streaming uses the same ID-based verification as the built-in client.

For a proxy configured with `headers.Authorization`, OpenAI's required `apiKey`
can be a placeholder. The secure client's configured authorization takes
precedence for evidence, Chat, and signature requests. Other per-request headers
can override their configured defaults.
With raw `client.fetch()`, consume the returned response body before verification.

## Verify manually

The manual flow has distinct stages:

1. Verify Gateway and model deployment evidence before sending a request.
2. Send the request and retain the exact body bytes sent and received.
3. Fetch the completion signature later and verify it against the retained
   evidence and bytes.

### Verify Gateway and model evidence

```ts
import {
  AttestationClient,
  createPinnedTlsFetch,
  verifyGatewayAttestation,
  verifyModelAttestation,
} from 'verifiable-ai-sdk/node';

const model = 'z-ai/glm-5.3-flash';
const client = new AttestationClient({ apiKey: process.env.NEARAI_API_KEY! });

const fetchedGateway = await client.fetchGatewayAttestation({
  signingAlgo: 'ed25519',
});
const gateway = await verifyGatewayAttestation({
  attestation: fetchedGateway.attestation,
  clientBinding: fetchedGateway.clientBinding,
});
if (gateway.tlsBinding.kind !== 'attested') {
  throw new Error('Expected TLS-bound Gateway evidence');
}
const pinnedTlsFetch = createPinnedTlsFetch(
  gateway.tlsBinding.spkiFingerprint,
);

const fetchedModels = await client.fetchModelAttestations({
  model,
  signingAlgo: 'ed25519',
});
if (fetchedModels.attestations.length === 0) {
  throw new Error('Gateway returned no model attestation');
}

const models = await Promise.all(
  fetchedModels.attestations.map((attestation) =>
    verifyModelAttestation({
      attestation,
      clientBinding: fetchedModels.clientBinding,
    }),
  ),
);
```

Use `pinnedTlsFetch` instead of `fetch` for raw direct-Gateway requests that
your application sends itself. It performs normal certificate and hostname
verification, then requires each TLS peer to present the attested SPKI.

The generic `verifiable-ai-sdk` entry point requests the no-TLS Gateway quote
layout and is suitable for browsers. The `/node` `AttestationClient` observes
only the peer for its Gateway-attestation request; it does not automatically
apply `pinnedTlsFetch` to its model or signature helpers. Use the Node secure
client when the complete Chat flow—including model evidence, completion, and
receipt signature—must be pinned automatically.

### Optional image build provenance

`fetchImageProvenance` retrieves GitHub Sigstore bundles for an image digest.
`verifyImageProvenance` checks their signatures, certificates, transparency-log
evidence, artifact digest, and signed SLSA source against your repository and
workflow policy. The source commit must match the certificate's authenticated
source SHA. Set `ref` or `commit` to restrict the accepted builds further.

Use a digest from the authenticated deployment configuration. This example
adds an image check to Gateway attestation verification:

```ts
import {
  fetchImageProvenance,
  verifyImageProvenance,
  verifyGatewayAttestation,
} from 'verifiable-ai-sdk';
import type { MeasuredDeployment } from 'verifiable-ai-sdk';

const imagePolicy = {
  repository: 'nearai/cloud-api',
  workflow: '.github/workflows/build.yml',
  ref: 'refs/heads/main',
};

async function checkGatewayImages(deployment: MeasuredDeployment): Promise<void> {
  // Application code: select a required, explicit image@sha256:... reference.
  const digest = selectCloudApiDigest(deployment.appCompose);
  const bundles = await fetchImageProvenance({
    repository: imagePolicy.repository,
    digest,
  });
  await verifyImageProvenance({ bundles, digest, policy: imagePolicy });
}

const gateway = await verifyGatewayAttestation({
  attestation: fetchedGateway.attestation,
  clientBinding: fetchedGateway.clientBinding,
  verifiers: { deployment: checkGatewayImages },
});
```

The application supplies `selectCloudApiDigest`: it parses its compose format
and rejects missing or unresolved required image references. A variable's
default image is not proof of its resolved value. For `SecureClient`, supply the
same callback as `gatewayVerification.verifiers.deployment`.

One complete matching bundle is sufficient; other bundles for the digest may
come from different builds. The helpers do not maintain an approved-image list,
rebuild images, or prove which containers are currently running. They are not
enabled automatically. Trust roots are refreshed through Sigstore's TUF service.
The TypeScript verifier accepts Rekor `dsse` entries, as used by current GitHub
build attestations; legacy Rekor `intoto` entries are not supported.

Fetch failures throw `ApiError`. Verification failures throw `VerificationError`
with `provenance.image_verification_failed` and machine-readable `details.reasons`.
The optional `githubToken` is a GitHub token, not a Gateway API key.

### Verify the response signature

`signature.kind` identifies the signer and therefore the proof made by a
successful verification:

| Kind | Verify with | Establishes |
| --- | --- | --- |
| `provider_tee` | A matching verified model attestation | The model-serving TEE signer signed the exact request and response body bytes. |
| `gateway` | The verified Gateway attestation | The Gateway signer signed the exact client-visible request and response body bytes. |

For an E2EE request, preserve the encrypted JSON body bytes—not the plaintext
object after decryption. Do not parse and reserialize either body before
verification.

```ts
import {
  findModelAttestationForSignature,
  verifyGatewayResponse,
  verifyModelResponse,
} from 'verifiable-ai-sdk/node';

const signature = await client.fetchCompletionSignature({
  completionId,
  signingAlgo: 'ed25519',
});

if (signature.kind === 'provider_tee') {
  const attestation = findModelAttestationForSignature({
    attestations: models,
    signature,
  });
  verifyModelResponse({
    requestBody,
    responseBody,
    signature,
    attestation,
  });
} else {
  verifyGatewayResponse({
    requestBody,
    responseBody,
    signature,
    attestation: gateway,
  });
}
```

A Gateway signature does not establish which model generated the response.
A model signature does not authenticate the Gateway deployment. Verify both
deployments before sending the request.

The default NVIDIA verifier submits evidence to NRAS, then verifies the overall
JWT's ES384 signature against NVIDIA's JWKS, issuer, expiration, not-before and
issued-at times, and signed `eat_nonce`. The overall verdict must be `true`.
It does not consume detached per-device claims. See [NVIDIA's claims reference](https://docs.nvidia.com/attestation/advanced-documentation/latest/claims-guide/gpu_claims.html).

## Handle errors

`AttestationClient` and selection helpers throw `ApiError` for SDK-classified
request, response, nonce, and selection problems. Explicit `verify…` calls
and E2EE integrity-check or decryption failures throw `VerificationError`.
Check the stable `failure.code` rather than parsing an error message.

```ts
import { ApiError } from 'verifiable-ai-sdk';

try {
  await client.fetchCompletionSignature({ completionId });
} catch (error) {
  if (!(error instanceof ApiError)) throw error;
  console.log(error.failure.code);
}
```
