# TypeScript verification guide

Use `InferenceClient` for Chat Completions with deployment verification and optional E2EE.
Use `AttestationClient` and the standalone verification functions to manage
the verification steps yourself.

These clients connect through the NEAR AI Cloud Gateway. For a model's own
`*.completions.near.ai` endpoint, the
[direct clients](#use-a-direct-model-endpoint) are experimental and not
recommended for production. Use Gateway clients for production integrations.

`InferenceClient` always verifies Gateway evidence. On a model-session cache
miss, it reads model metadata from `GET /v1/model/{model}` using a URL-encoded
model ID. Models with `providerType: 'vllm'` and `attestationSupported: true`
require all returned NEAR model reports to pass before key routing. Other models
use Incognito mode: the SDK verifies the Gateway without verifying model evidence.
A metadata lookup error, malformed metadata, or failed model verification stops
Chat without falling back to Gateway-only mode.

## Send an E2EE chat completion

`InferenceClient` uses OpenAI Chat Completions types. Set `e2ee: true` to
encrypt supported fields to an attested model. Before sending a request, the
client verifies Gateway and model evidence or reuses cached results. A
verification failure prevents the request from being sent.

This Node.js example connects directly to the Gateway with a server-side API
key. The Node client verifies the Gateway's TLS identity and pins subsequent
requests to that identity. For browser applications, see
[Connect through an application proxy](#connect-through-an-application-proxy).

```ts
import { InferenceClient } from '@nearai/inference-sdk/node';

const model = 'z-ai/glm-5.3-flash';
const client = new InferenceClient({
  apiKey: process.env.NEARAI_API_KEY!,
  e2ee: true,
});

const completion = await client.chat.completions.create({
  model,
  messages: [{ role: 'user', content: 'Hello' }],
});

console.log(completion.choices[0].message.content);
```

To select ECDSA instead of the default Ed25519 protocol:

```ts
const client = new InferenceClient({
  apiKey: process.env.NEARAI_API_KEY!,
  signingAlgo: 'ecdsa',
  e2ee: true,
});
```

`signingAlgo` selects the algorithm for attestation, model-key routing, E2EE,
and response signatures. The Gateway returns model attestations for the
requested model. The client verifies every returned report before
selecting a key for the chosen algorithm.

### Use OHTTP

Set `ohttp: true` to encapsulate Chat requests and responses in OHTTP. Both
`InferenceClient` and `DirectInferenceClient` support this option for ordinary
and streaming completions:

```ts
const client = new InferenceClient({
  apiKey: process.env.NEARAI_API_KEY!,
  ohttp: true,
});
```

OHTTP is disabled by default and requires `signingAlgo: 'ed25519'` (the default).
The client verifies the advertised OHTTP key configuration against the attested
Gateway signer, or the serving model signer for a direct endpoint. Missing or
invalid OHTTP evidence prevents the inference request from being sent. The
authenticated configuration is cached with the deployment verification result.

`e2ee` is independent and defaults to `false` for both clients.
Through the Gateway, OHTTP protects the HTTP exchange to the Gateway, while E2EE
encrypts supported Chat fields to the model.
Gateway OHTTP also works with Incognito models; it does not provide model
encryption. With a direct endpoint, both terminate at the model service.

Chat and Gateway Responses can use OHTTP; metadata, attestation, and signature
requests keep their normal HTTP paths. Your endpoint or proxy must support
`/ohttp` at the configured origin.
Authorization and explicitly configured custom headers are also sent on this
outer request so the endpoint can authenticate it. OHTTP does not hide these
outer headers or the client's network address from the endpoint.

Chat calls and `verifyResponse(id)` do not change. Response verification uses
the inner request and response bodies, before E2EE decryption, not the OHTTP
ciphertext. Node TLS pinning still checks the outer connection.

### Cache deployment verification

Call `verify(model)` when the user selects a model or opens a chat to complete
deployment verification before their first message:

```ts
const result = await client.verify(model);

// Populate your verification UI from these results.
console.log('Gateway TCB status:', result.gateway.tcbStatus);
for (const attestation of result.models) {
  console.log('Model TCB status:', attestation.tcbStatus);
  console.log('Intel quote:', attestation.report.intelQuote);
}

// Later, send the user's message using the same client and model.
const completion = await client.chat.completions.create({
  model,
  messages: [{ role: 'user', content: 'Hello' }],
});
```

`verify(model)` sends no Chat request. It performs the same Gateway and model
checks as Chat, including configured policies, and rejects if they fail.
It returns the verified Gateway, every verified model report, and `verifiedAt`
(Unix time in milliseconds). For Incognito models, only the Gateway is verified
and `models` is empty. Results share the cache and in-flight verification with
Chat, so opening a details view can call `verify(model)` without fetching and
verifying evidence again while the result is cached. It also works
when using the client's `fetch` with the OpenAI SDK. `DirectInferenceClient`
returns the full verified direct-attestation set, endpoint TLS binding, and
`verifiedAt` through the same method.

Each verified attestation includes its original input under `report`, including
the quote, event log, and any NVIDIA payload. The sibling fields such as
`signer`, `tcbStatus`, and `deployment` contain the verification conclusions.
Endpoint metadata in `report` is not an additional authenticated claim.

`attestationCacheTimeToLiveMs` defaults to `3600000` (60 minutes). Concurrent
requests for the same model share verification work and cached results across
`verify(model)`, Chat, Responses, and System One.
The TTL starts when verification succeeds. Cache hits preserve `verifiedAt`,
so the UI can show when the evidence was actually verified. A later Chat request
reuses that result while it is cached. Increase the value to check deployments less
frequently, or set `0` to verify before every request, even after `verify(model)`.
Deployment changes are not checked while a cached result is reused.
This setting controls caching, not attestation validity.

This verifies the deployment, not a particular reply. Use `verifyResponse(completion.id)`
after receiving the reply to verify its signature.

The SDK does not check model measurements against an approved-deployment
allowlist by default. If needed, supply a `deploymentPolicy` callback and
throw an error to reject a deployment.

Reusable deployment checks can also be passed through
`gatewayVerification.verifiers.deployment` and
`modelVerification.verifiers.deployment`. For models, this check runs before
`deploymentPolicy`, which also receives the requested model name. If both are
configured, both must pass.

Gateway verification runs concurrently with model metadata retrieval and model
attestation verification. With Node TLS binding enabled, model metadata and
evidence requests are pinned to the TLS fingerprint observed when fetching the
Gateway report. Gateway verification must authenticate that same fingerprint
before the session is cached or Chat is sent. All required checks must pass.
If preflight fails, pending model metadata and attestation requests are aborted.
Already-running third-party or custom verifiers without cancellation support
may still finish in the background.

CPU and GPU checks run concurrently. Deployment callbacks run only after the
CPU quote and deployment measurements have been verified. Checks for different
model reports may also run concurrently.

<!-- Messages support is deferred until a later release.

## Messages API

The Gateway client supports `POST /v1/messages` with attestation preflight,
TLS binding where available, and optional OHTTP (Ed25519). Requests preserve
Anthropic system/content blocks, tools, tool results, and other JSON fields;
available features depend on the Gateway and model. `anthropic-version` and
`anthropic-beta` headers are preserved. The built-in interface defaults to
`anthropic-version: 2023-06-01`.

Verify the top-level message `id` after JSON consumption, or
`message_start.message.id` after consuming the complete SSE stream through
`message_stop`. Tool-use IDs and the billing `Inference-Id` header are separate.
Verification uses the original request and response bytes and requires a
`gateway` receipt. This authenticates the Gateway's observation, not external
Anthropic model execution inside a TEE. Failed, incomplete, and cancelled streams
cannot yield a verified complete response. If receipt lookup is temporarily
unavailable, retry verification without sending inference again.

Messages field-level E2EE and Direct clients are rejected before network I/O,
matching the server's supported contract. Only Messages creation is supported.

```ts
const message = await client.messages.create({
  model: 'anthropic/claude-haiku-4-5',
  max_tokens: 128,
  messages: [{ role: 'user', content: 'Hello' }],
});
const receipt = await client.verifyResponse(message.id);
console.log(receipt.signatureKind, message.content);
```

Set `stream: true` for typed Anthropic events. `InferenceMessages` exposes the
official `create` overloads. An external `@anthropic-ai/sdk` client can use
`fetch: client.fetch` and `maxRetries: 0`. Set its `baseURL` to
`https://cloud-api.near.ai` (Anthropic appends `/v1/messages`); configure the
inference client's `baseUrl` as `https://cloud-api.near.ai/v1/`. The transport uses
the inference client's configured authentication for both inference and evidence.
See the [native example](../../examples/example-js/gateway/messages.ts) and
[official SDK example](../../examples/example-js/gateway/messages-anthropic-sdk.ts)
for JSON and streaming calls with receipt verification.

-->

## Responses API

The Gateway client supports `POST /v1/responses` with the same authentication,
attestation preflight, TLS settings, and optional OHTTP as Chat. It preserves
input items, function tools, reasoning fields, and output events. The SDK forwards
`store: false` unchanged; stateless behavior is provided by the server. For
client-managed context, replay function calls with their matching outputs in
subsequent requests. Available features depend on the server and model.

Responses receipts must have `signature_kind: gateway`: they authenticate the
Gateway's exact request/response bytes, not a model signature over the final
Responses object. Receipt persistence is best-effort. A successful inference can
still have an unavailable receipt; retry receipt lookup when appropriate without
repeating inference. Consume the entire SSE stream before verifying its nested
`event.response.id`; output item IDs are not receipt IDs.

Field-level E2EE and Direct Responses are rejected before network I/O. OHTTP is
supported with Ed25519. Provider `reasoning.encrypted_content` is passed through
as opaque data and is separate from NEAR field encryption. Only creation is
supported; response retrieval, cancellation, deletion, and history endpoints are
outside this transport.

```ts
const response = await client.responses.create({
  model: 'z-ai/glm-5.3-flash',
  input: 'Reply with the word ok.',
  store: false,
});
const receipt = await client.verifyResponse(response.id);
console.log(receipt.signatureKind, response.output_text);
```

Set `stream: true` and iterate the returned stream for typed Responses events.
The same API works with an external OpenAI client using `fetch: client.fetch`.
`InferenceResponses` exposes the official OpenAI `create` overloads.

## System One decisions

Use `systemone.create()` for Jev decision models. It verifies the required
deployments before sending state, using the client's attestation cache and
policies. Use a Gateway client with `e2ee: false` and `ohttp: false`;
System One returns a complete JSON response.

```ts
import { InferenceClient } from '@nearai/inference-sdk/node';

const client = new InferenceClient({ apiKey, baseUrl, e2ee: false, ohttp: false });
const result = await client.systemone.create({
  model: canonicalModelId,
  state: { message: 'I was charged twice.' },
  questions: {
    billing: { type: 'noul', instructions: 'Is this about billing?' },
  },
});

const verified = await client.verifyResponse(result.decisionId);
console.log(verified.signatureKind, result.data.answers);
```

`result.decisionId` comes from `X-Generation-Id`. Call `verifyResponse()` before
using the answers; it checks the exact bytes captured by the client. Gateway
receipts authenticate Gateway signing; provider TEE receipts authenticate the
model signer selected before the request. Self-hosted models use
`x-model-pub-key` routing, which the endpoint must support.

Response retention and receipt retries follow the same lifecycle as Chat.
If a receipt is temporarily unavailable, retry `verifyResponse(result.decisionId)`.
Pass an `AbortSignal` in the create method's second argument to cancel the call.

### Use the official Jev SDK

Install `@typesafe-ai/sdk` and pass the Gateway client's `fetch` to
`TypeSafeClient`. Its API root excludes `/v1`; the NEAR client includes `/v1/`.
Use a canonical Jev model ID from your endpoint's catalog.

```ts
import { InferenceClient } from '@nearai/inference-sdk/node';
import { TypeSafeClient, noul } from '@typesafe-ai/sdk';

const inference = new InferenceClient({
  apiKey,
  baseUrl: 'https://cloud-api.near.ai/v1/',
  e2ee: false,
  ohttp: false,
});
const jev = new TypeSafeClient({
  apiKey,
  baseURL: 'https://cloud-api.near.ai',
  fetch: inference.fetch,
  compression: false,
  retry: { maxRetries: 0 },
  timeout: 60_000,
});
const { data, response } = await jev.systemOne({
  model,
  state: 'I was charged twice.',
  questions: { billing: noul('Is this about billing?') },
}).withResponse();
const id = response.headers.get('x-generation-id');
if (!id) throw new Error('Missing System One receipt ID');
await inference.verifyResponse(id);
console.log(data.answers.billing.noul);
```

The adapter accepts uncompressed, nonstreaming JSON requests at the configured
System One endpoint. Keep E2EE, OHTTP, request compression and automatic inference
retries disabled; multipart uploads and other official SDK endpoints are outside
this adapter's scope. Retry a transient receipt lookup through `verifyResponse(id)`.

`X-Generation-Id` identifies the NEAR receipt; the official SDK's `requestId`
identifies the upstream request. Verification uses the exact captured bytes.
Self-hosted requests route with the preselected attested `x-model-pub-key`.
Provider receipts must match that identity; external models use Gateway receipts. The Node transport
also pins Gateway TLS, as it does for Chat.

See the [runnable official SDK example](../../examples/example-js/gateway/jev-sdk.ts).
Its [reusable helpers](../../examples/example-js/gateway/jev-helpers.ts) keep the
verified transport configuration and receipt-ID extraction together. See the
[live E2E instructions](../../e2e/README.md#official-jev-sdk-integration) for
credential-gated validation against a deployed Gateway.

## Connect through an application proxy

A proxy lets your backend keep the NEAR AI API key while users' devices verify
evidence and encrypt prompts. Direct server-to-Gateway integrations do not
need a proxy.

Set `baseUrl` to your backend's API endpoint and `headers` to the credentials
it accepts:

```ts
import { InferenceClient } from '@nearai/inference-sdk';

const client = new InferenceClient({
  baseUrl: 'https://api.example.com/v1',
  e2ee: true,
  headers: {
    Authorization: 'Bearer <browser-scoped token>',
  },
});
```

The proxy must forward `/v1/model/{model}`, `/v1/attestation/report`,
`/v1/chat/completions`, `/v1/responses` and `/v1/signature/{id}`. For System One
decisions, also forward `POST /v1/systemone`. Preserve the URL-encoded model and
completion IDs. The proxy authenticates the user and supplies its upstream NEAR AI credential.
Preserve the request and response bodies, model-key routing header, and encryption
headers unchanged so decryption and signature verification work. Forward the
`X-Generation-Id` response header for System One and expose it through
`Access-Control-Expose-Headers` when the proxy is cross-origin.

Browser Fetch does not expose the TLS peer certificate, so the generic client
does not verify Gateway TLS binding. Depending on the browser build, the default
Intel verifier may need `crypto`, `buffer`, and `stream` polyfills. A custom
quote verifier can be supplied through `gatewayVerification.verifiers.tdxQuote`
and `modelVerification.verifiers.tdxQuote`.

For a Node client connecting through a proxy, disable Gateway TLS binding
because the observed certificate belongs
to the proxy:

```ts
import { InferenceClient } from '@nearai/inference-sdk/node';

const client = new InferenceClient({
  baseUrl: 'https://api.example.com/v1',
  e2ee: true,
  headers: {
    Authorization: 'Bearer <server-scoped token>',
  },
  gatewayVerification: { includeSpkiFingerprint: false },
});
```

## Configure attestation service URLs

Browser verification uses NEAR AI's proxies for PCCS and NRAS. Node.js uses
Intel and NVIDIA directly. The built-in verifiers use these defaults:

| Service | Browser | Node.js |
| --- | --- | --- |
| PCCS base | `https://cloud.near.ai/api/proxy/pccs` | `https://api.trustedservices.intel.com` |
| NRAS evidence | `https://cloud.near.ai/api/proxy/nras/v3/attest/gpu` | `https://nras.attestation.nvidia.com/v3/attest/gpu` |
| NVIDIA signing keys | `https://nras.attestation.nvidia.com/.well-known/jwks.json` | `https://nras.attestation.nvidia.com/.well-known/jwks.json` |

To use your own services, pass verifier callbacks with custom URLs:

```ts
import {
  createTdxQuoteVerifier,
  createGpuEvidenceVerifier,
} from '@nearai/inference-sdk';

const tdxQuote = createTdxQuoteVerifier({
  pccsUrl: 'https://attestation.example.com/pccs',
});
const gpuEvidence = createGpuEvidenceVerifier({
  nrasUrl: 'https://attestation.example.com/nras/v3/attest/gpu',
});
```

Pass `{ tdxQuote }` to Gateway verification or `{ tdxQuote, gpuEvidence }` to
model verification through `verifiers`. In `InferenceClient`, these are
`gatewayVerification.verifiers` and `modelVerification.verifiers`.

DCAP builds the SGX and TDX collateral paths beneath `pccsUrl`. `nrasUrl` is the
complete GPU evidence POST URL. Signing keys come from NVIDIA; set `jwksUrl`
separately to use another trusted key source.

## E2EE scope and response handling

Field-level E2EE supports `POST /v1/chat/completions` with a model public key bound
to verified attestation. [Responses](#responses-api) supports OHTTP but rejects
field-level E2EE.

Both algorithms use `X-Encryption-Version: 3`. Every encrypted request field
binds the fresh reply public key through AEAD associated data (AAD). V3 requires
all supported fields below to be encrypted and rejects failed decryption; the
optional `X-Encrypt-All-Fields` header cannot disable that policy. Other fields
are forwarded unchanged. The gateway and model proxy must support v3; the SDK
does not downgrade on failure.

Ed25519 uses X25519, HKDF-SHA256, and XChaCha20-Poly1305. ECDSA uses secp256k1
ECDH, HKDF-SHA256, and AES-256-GCM. Response envelopes are unchanged. See the
[wire protocol](https://github.com/nearai/inference-proxy/blob/main/docs/e2ee.md)
for AAD encoding and compatibility.

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

Field-level E2EE does not encrypt URL query parameters, headers, or fields
outside the table.
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

`e2ee: false` is the default. Gateway verification always runs. For attested models,
model verification, deployment policy, and verified-key routing still run.
For Incognito models, the client skips model attestations, model-key routing, and
field encryption; response verification accepts only a Gateway signature.

```ts
const client = new InferenceClient({
  apiKey: process.env.NEARAI_API_KEY!,
  e2ee: false,
});
```

Attested models still use a verified model public key for routing, so the model
must expose a key for the configured signing algorithm. These requests send
`X-Model-Pub-Key` without field-encryption headers. Signature lookups use the
configured `signingAlgo` in both modes.

The `chat.completions.create()` and `verifyResponse(id)` calls stay the same.
Setting `e2ee: true`, `deploymentPolicy`, `modelVerification.policy`, or
`modelVerification.verifiers.deployment` requires model attestation and rejects
Incognito models before Chat with `policy.model_attestation_required`. An empty
`modelVerification` or quote/GPU verifier overrides alone are allowed, so proxy
configuration can be shared across models.

## Verify a response

The client retains the exact request and response bytes before E2EE decryption.
Display the completion normally, then verify its signature by ID:

```ts
const completion = await client.chat.completions.create({
  model,
  messages: [{ role: 'user', content: 'Hello' }],
});
const verified = await client.verifyResponse(completion.id);
render(completion.choices[0]?.message.content);
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
API failure or `api.completion_signature_unavailable`, call `verifyResponse(id)`
again to retry the signature lookup. Successful results and other non-retryable
failures remain cached.

Response records retain complete bodies in memory. They expire
`responseCacheTimeToLiveMs` after body completion (default: 60 minutes),
independently of the attestation cache. Unknown or expired IDs produce
`ApiError` with code `api.completion_not_found`. For active streams, memory
grows with the received body until the application finishes or cancels reading.

A `provider_tee` signature must match the verified model signer selected for
the request's `X-Model-Pub-Key`.
A `gateway` signature binds them to a verified Gateway signer; it does not
by itself prove model execution. Incognito model sessions accept only this kind;
successful Gateway verification does not imply that the model runs in a TEE.

### Use the official OpenAI SDK

Create both clients once. The same Fetch adapter supports sequential and
concurrent requests. Disable automatic inference retries:

```ts
import OpenAI from 'openai';

const openai = new OpenAI({
  apiKey,
  baseURL: client.getBaseUrl(),
  fetch: client.fetch,
  maxRetries: 0,
});
const completion = await openai.chat.completions.create({
  model,
  messages: [{ role: 'user', content: 'Hello' }],
});
const verified = await client.verifyResponse(completion.id);
render(completion.choices[0]?.message.content);
```

Streaming uses the same ID-based verification as the built-in client.

Configure authentication on the inference client. Its `apiKey` or
`headers.Authorization` supplies bearer authorization for evidence, Chat, and
signature requests. Without either, no Authorization header is sent, including
when an external OpenAI client adds one. OpenAI's required `apiKey` can therefore
be a placeholder when a proxy uses custom headers. Other per-request headers can
override their configured defaults.
With raw `client.fetch()`, consume the returned response body before verification.

## Use a direct model endpoint

> **Experimental — not recommended for production.** This applies to both
> `DirectInferenceClient` and `DirectAttestationClient` in the browser and Node
> entry points. Use the Gateway `InferenceClient` or `AttestationClient` for production.

Known endpoint limitations affect the direct flow:

- `all_attestations` may contain only the instance handling the attestation
  request. Preflight can therefore miss other CVMs, including a later serving
  instance with a different TLS key, and cannot establish a complete set of
  fleet TLS pins. Verifying all returned reports does not verify every backend CVM.
- Completion signatures are stored per instance. `/signature/{id}` may return
  `404` when Chat and signature lookup reach different instances.

`DirectInferenceClient` verifies the model endpoint without a Gateway preflight
or model-metadata lookup.
It fetches and verifies every returned model attestation before
sending Chat.
E2EE is opt-in, as with the Gateway client. The example enables it explicitly.
The signing algorithm defaults to Ed25519. Both cache defaults are 60 minutes.

```ts
import { DirectInferenceClient } from '@nearai/inference-sdk/node';

const client = new DirectInferenceClient({
  baseUrl: 'https://glm-5-3-flash.completions.near.ai/v1',
  apiKey: process.env.NEARAI_API_KEY,
  e2ee: true,
});
```

Use `client.chat.completions.create()`, `client.fetch`, and
`client.verifyResponse(id)` as above. Direct endpoints may require different
credentials from the Gateway and use separate fetch and verification APIs.

The client selects a verified model key for routing and E2EE; response signatures
must match that selected signer. Both entry points request
`include_tls_fingerprint=false`. Direct TLS fingerprint binding and pinning are
currently disabled; standard HTTPS certificate validation still applies.

### Verify direct evidence manually

```ts
import {
  DirectAttestationClient,
  verifyDirectModelAttestations,
} from '@nearai/inference-sdk/node';

const client = new DirectAttestationClient({
  baseUrl: 'https://glm-5-3-flash.completions.near.ai/v1',
  apiKey: process.env.NEARAI_API_KEY,
});
const fetched = await client.fetchModelAttestations({ signingAlgo: 'ed25519' });
const verified = await verifyDirectModelAttestations(fetched);
```

Send Chat with `fetch` and retain the exact request and response bytes.
Then fetch its signature with `client.fetchCompletionSignature()` and pass the
signature, bytes, and `verified.attestations` to `verifyDirectModelResponse()`.
It returns all verified attestations sharing the response's signer.

For one attestation, `verifyDirectModelAttestation()` checks its quote, nonce,
measurements, and available GPU evidence. `verifyDirectModelAttestations()`
checks every entry. Reports fetched by `DirectAttestationClient` produce
`tlsBinding.kind: 'none'`.

The runnable [direct/client.ts](../../examples/example-js/direct/client.ts),
[direct/client-openai-sdk.ts](../../examples/example-js/direct/client-openai-sdk.ts),
and [direct/bare.ts](../../examples/example-js/direct/bare.ts) examples each
include streaming and non-streaming calls. The bare example omits E2EE.

## Verify Gateway requests manually

The manual flow below uses a TEE model and has distinct stages:

1. Verify Gateway and model deployment evidence before sending a request.
2. Send the request and retain the exact body bytes sent and received.
3. Fetch the completion signature later and verify it against the retained
   evidence and bytes.

For model capability lookup, `await client.fetchModelMetadata(model)` returns
`providerType` and `attestationSupported`. A `vllm` provider with attestation
support can use NEAR model verification; other models use Gateway-only
verification. Metadata retrieval performs no cryptographic verification;
verify Gateway evidence separately before using that decision.

### Verify Gateway and model evidence

```ts
import {
  AttestationClient,
  createPinnedTlsFetch,
  verifyGatewayAttestation,
  verifyModelAttestation,
} from '@nearai/inference-sdk/node';

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

The generic `@nearai/inference-sdk` entry point requests the no-TLS Gateway quote
layout and is suitable for browsers. The `/node` `AttestationClient` observes
only the peer for its Gateway-attestation request; it does not automatically
apply `pinnedTlsFetch` to its model or signature helpers. Use the Node secure
client when the complete Chat flow—including model evidence, completion, and
response signature—must be pinned automatically.

### Encrypt a raw Chat request

`prepareE2eeChatRequest` accepts a model public key and its signing algorithm.
Obtain them from verified model evidence before preparing the request. The
helper creates fresh client keys and sets the encryption and model-routing
headers; it sends no requests and performs no attestation or completion-signature
verification.

```ts
import { prepareE2eeChatRequest } from '@nearai/inference-sdk/node';

const modelAttestation = models.find(
  (attestation) => attestation.signingPublicKey !== undefined,
);
if (
  modelAttestation === undefined ||
  modelAttestation.signingPublicKey === undefined
) {
  throw new Error('No verified model key is available');
}
const request = new Request('https://cloud-api.near.ai/v1/chat/completions', {
  method: 'POST',
  headers: {
    Authorization: `Bearer ${process.env.NEARAI_API_KEY!}`,
    'Content-Type': 'application/json',
    'Accept-Encoding': 'identity',
  },
  body: JSON.stringify({
    model,
    messages: [{ role: 'user', content: 'Hello' }],
  }),
});
const prepared = await prepareE2eeChatRequest({
  request,
  modelKey: {
    signingAlgo: modelAttestation.signer.signingAlgo,
    publicKey: modelAttestation.signingPublicKey,
  },
});
const requestBytes = await prepared.request.clone().arrayBuffer();
const requestBody = new Uint8Array(requestBytes);
const encryptedResponse = await pinnedTlsFetch(prepared.request);
const verificationResponse = encryptedResponse.clone();
const response = await prepared.decryptResponse(encryptedResponse);
const [responseBytes, plaintext] = await Promise.all([
  verificationResponse.arrayBuffer(),
  response.text(),
]);
const responseBody = new Uint8Array(responseBytes);
console.log(plaintext);
```

Pass the captured `requestBody` and `responseBody` to the response-signature
functions below. With `stream: true`, `decryptResponse` returns a decrypted
SSE `Response`; consume its body as events arrive while retaining the encrypted
response clone for signature verification. HTTP error responses pass through
unchanged. The [bare example](../../examples/example-js/gateway/bare.ts) demonstrates
both response modes without handling protocol keys or encryption headers.

### Optional image build provenance

`verifyDeploymentImageProvenance` reads image digests from `appCompose`, fetches
their GitHub Sigstore bundles, and verifies them against your build policies.
Use it in a deployment callback so the quote and configuration binding are
checked first:

```ts
import {
  verifyDeploymentImageProvenance,
  verifyGatewayAttestation,
  type ImageProvenancePolicy,
} from '@nearai/inference-sdk';

const imagePolicies: Record<string, ImageProvenancePolicy> = {
  'nearaidev/cloud-api': {
    repository: 'nearai/cloud-api',
    workflow: '.github/workflows/build.yml',
  },
};

const gateway = await verifyGatewayAttestation({
  attestation: fetchedGateway.attestation,
  clientBinding: fetchedGateway.clientBinding,
  verifiers: {
    deployment: ({ appCompose }) =>
      verifyDeploymentImageProvenance({ appCompose, imagePolicies }),
  },
});
```

Each map key is a required container image repository; its value identifies the
trusted GitHub repository and workflow. Every reference to a listed image must
have a literal SHA-256 digest. Tags alongside digests are accepted, but tags
alone are not. Image variables are not resolved. Other literal images are not
verified. For `InferenceClient`, pass the same callback as
`gatewayVerification.verifiers.deployment`; see the runnable
[client example](../../examples/example-js/gateway/client.ts) and
[bare example](../../examples/example-js/gateway/bare.ts), which require build provenance
for four Gateway images.

The checks cover signatures, certificates, transparency-log evidence, artifact
digests, and signed SLSA source. Each source commit must match the certificate's
authenticated source SHA. Set `ref` or `commit` to restrict builds further.
For individual digests or other configuration formats, use
`fetchImageProvenance` and `verifyImageProvenance` directly.

For a reusable signing workflow in another repository, set `signerIdentity` to
its exact certificate SAN URI. Keep `repository`, `workflow`, `ref`, and `commit`
pointing to the source and caller workflow:

```ts
const imagePolicy: ImageProvenancePolicy = {
  repository: 'example/app',
  workflow: '.github/workflows/release.yml',
  ref: 'refs/heads/main',
  signerIdentity:
    'https://github.com/example/build-workflows/.github/workflows/build.yml@refs/tags/v1',
};
```

The signer URI can use a ref or a full workflow commit SHA. Without this option,
the signer must be the source workflow at the same ref. In both cases, the
certificate's source repository, ref, and commit must match the signed source.
Proofs are still fetched from the source repository, not the signer repository.

One complete matching bundle is sufficient; other bundles for the digest may
come from different builds. The helpers do not maintain an approved-image list,
rebuild images, or prove which containers are currently running. They are not
enabled automatically. Trust roots are refreshed through Sigstore's TUF service.
The TypeScript verifier accepts Rekor `dsse` entries, as used by current GitHub
build attestations; legacy Rekor `intoto` entries are not supported.

`verifyDeploymentImageProvenance` throws `VerificationError` for invalid image
configuration, failed proof retrieval, or failed proof verification. A retrieval
failure preserves the underlying `ApiError` as its cause and its retryability.
Calling `fetchImageProvenance` directly still throws `ApiError`.

#### Model images deployed by Compose Manager

A model's measured `appCompose` can describe its launcher rather than the
model-serving containers deployed later. Use
`verifyComposeManagerDeploymentImageProvenance` for those images:

```ts
import {
  verifyComposeManagerDeploymentImageProvenance,
  verifyModelAttestation,
  type ImageProvenancePolicy,
} from '@nearai/inference-sdk';

const modelImagePolicies: Record<string, ImageProvenancePolicy> = {
  'nearaidev/vllm-proxy-rs': {
    repository: 'nearai/inference-proxy',
    workflow: '.github/workflows/build.yml',
  },
};

for (const attestation of fetchedModels.attestations) {
  await verifyModelAttestation({
    attestation,
    clientBinding: fetchedModels.clientBinding,
    verifiers: {
      deployment: deployment =>
        verifyComposeManagerDeploymentImageProvenance({
          deployment,
          imagePolicies: modelImagePolicies,
          composeManagerImagePolicy: {
            imageRepository: 'nearaidev/compose-manager',
            repository: 'nearai/compose-manager',
            workflow: '.github/workflows/build.yml',
          },
        }),
    },
  });
}
```

This callback requires the configured image builds in the authenticated
deployment record, including the manager's startup image.

Use `composeFile` to select a project's file and `composeRepository` to change the
trusted repository. Configure this callback as `modelVerification.verifiers.deployment`
on Gateway or Direct inference clients. The policy runs for every model report
and requires Compose Manager evidence in each one.

The evidence covers recorded deployment actions and the configured image builds;
current runtime state requires separate evidence. See the
[API reference](./api-reference.md#verifycomposemanagerdeploymentimageprovenance)
for options and evidence fields.

#### GitHub API access

Requests use `https://api.github.com` by default, with optional `githubToken`
authentication. When using a GitHub token in a frontend is impractical, set
`githubApiUrl` to a GitHub-compatible endpoint on your backend. The backend
supplies the GitHub credentials; the SDK ignores `githubToken` when
`githubApiUrl` is set.

The API base URL must be absolute HTTP(S), without credentials, a query, or
a fragment. The SDK preserves its path prefix and appends these GitHub API routes:

| Path appended to the API URL | Response |
| --- | --- |
| `/repos/{owner}/{repo}/attestations/{digest}?per_page=100` | GitHub JSON with inline `attestations[].bundle` and a `Link` header for pagination. |
| `/repos/{owner}/{repo}/contents/{file}?ref={commit}` | Exact file bytes, requested with `Accept: application/vnd.github.raw+json`. |

Preserve status codes and pagination cursors, and return content directly.
All pages are fetched through the configured endpoint. For browser callers, allow
`Accept` and `X-GitHub-Api-Version` and expose `Link` through CORS.
Keep GitHub credentials on the server and restrict the backend to the required
repositories and read-only routes. Bundle signatures, image policies, and file
hashes are verified locally by the SDK.

### Verify the response signature

`signature.kind` identifies the signer and therefore the proof made by a
successful verification:

| Kind | Verify with | Establishes |
| --- | --- | --- |
| `provider_tee` | The verified model attestation selected for the request | The model-serving TEE signer signed the exact request and response body bytes. |
| `gateway` | The verified Gateway attestation | The Gateway signer signed the exact client-visible request and response body bytes. |

For an E2EE request, preserve the encrypted JSON body bytes—not the plaintext
object after decryption. Do not parse and reserialize either body before
verification.

```ts
import {
  findModelAttestationForSignature,
  verifyGatewayResponse,
  verifyModelResponse,
} from '@nearai/inference-sdk/node';

const signature = await client.fetchCompletionSignature({
  completionId,
  signingAlgo: 'ed25519',
});

if (signature.kind === 'provider_tee') {
  const attestation = findModelAttestationForSignature({
    attestations: [modelAttestation],
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
import { ApiError } from '@nearai/inference-sdk';

try {
  await client.fetchCompletionSignature({ completionId });
} catch (error) {
  if (!(error instanceof ApiError)) throw error;
  console.log(error.failure.code);
}
```
