# TypeScript verification guide

Use `InferenceClient` for Chat Completions with deployment verification and optional E2EE.
Use `AttestationClient` and the standalone verification functions to manage
the verification steps yourself.

The Gateway client verifies Gateway evidence and every returned model report
before inference. Models without model attestation use Gateway-only (Incognito)
verification. E2EE and model deployment policies require model attestation.

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

await client.verifyResponse(completion.id);
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

`signingAlgo` selects the algorithm for attestation, E2EE, and response signatures.

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

OHTTP requires Ed25519 and an endpoint serving `/ohttp`.

OHTTP encrypts encapsulated requests and responses to the Gateway or Direct
endpoint. `Authorization` and configured forwarded headers remain on the outer
HTTP request. E2EE encrypts supported Chat fields to the model; both options can
be enabled independently or together.

Chat calls and `verifyResponse(id)` use the same interfaces with OHTTP enabled.

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

`verify(model)` returns the verified Gateway, all model reports, and the
verification time. `models` is empty for Gateway-only models.

Each verified attestation includes the original `report` alongside verified
fields such as `signer`, `tcbStatus`, and `deployment`.

Set `attestationCacheTimeToLiveMs` to control deployment verification reuse;
`0` verifies every request. The default is one hour.

Use `deploymentPolicy` to restrict accepted model deployments; throw to reject.

Reusable deployment checks can also be passed through
`gatewayVerification.verifiers.deployment` and
`modelVerification.verifiers.deployment`. For models, this check runs before
`deploymentPolicy`, which also receives the requested model name. If both are
configured, both must pass.

## Messages API

Gateway clients support Messages creation as JSON or SSE, with optional OHTTP
(Ed25519). Use field-level E2EE disabled.

Verify the message `id` after reading a JSON response, or `message_start.message.id`
after consuming the stream. Messages use Gateway receipts.

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
the inference client's configured authentication for inference and signatures;
Gateway attestation requests omit authentication headers; model reports use configured authentication.
See the [native example](../../examples/example-js/gateway/messages.ts) and
[official SDK example](../../examples/example-js/gateway/messages-with-anthropic-sdk.ts)
for JSON and streaming calls with receipt verification.

## Responses API

Gateway clients support Responses creation as JSON or SSE, with optional OHTTP
(Ed25519). Use field-level E2EE disabled.

Verify the response `id` after reading a JSON response, or `event.response.id`
after consuming the stream. Responses use Gateway receipts.

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

`result.decisionId` comes from `X-Generation-Id`. Pass it to `verifyResponse()`
before using the answers.

### Use the official TypeSafe SDK

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
const typesafe = new TypeSafeClient({
  apiKey,
  baseURL: 'https://cloud-api.near.ai',
  fetch: inference.fetch,
  compression: false,
  retry: { maxRetries: 0 },
  timeout: 60_000,
});
const { data, response } = await typesafe.systemOne({
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
retries disabled. Retry a transient receipt lookup through `verifyResponse(id)`.

Use `X-Generation-Id` as the receipt ID.

See the [runnable official SDK example](../../examples/example-js/gateway/systemone-with-typesafe-sdk.ts).

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
`/v1/chat/completions`, `/v1/responses`, `/v1/messages`, and `/v1/signature/{id}`. For System One
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

E2EE requests use `X-Encryption-Version: 3`, binding the reply public key and
field label through authenticated data. The endpoint must support v3. See the
[wire protocol](https://github.com/nearai/inference-proxy/blob/main/docs/e2ee.md)
for the format and supported fields.

Field-level E2EE supports `POST /v1/chat/completions` with a model public key bound
to verified attestation. [Responses](#responses-api) supports OHTTP but rejects
field-level E2EE.

| Capability | E2EE behavior |
| --- | --- |
| String `messages[].content` | Each string is encrypted independently. |
| Rich message content | An array-valued `messages[].content` is serialized and encrypted as one value. |
| Assistant context | String `reasoning_content`, `reasoning`, and `audio.data` message fields are encrypted. |
| Function and tool fields | Recognized function definitions, function calls, and related message fields are encrypted. Other tool forms are preserved without E2EE transformation. |
| `web_context_search` | The request is forwarded normally; supported search-tool output is decrypted. |
| Other Chat request-body fields | Forwarded without encryption. |
| Streaming Chat | Each complete SSE event is decrypted before it reaches the caller. |

### Stream an E2EE completion

Set `stream: true` and iterate the decrypted chunks. After consuming the stream,
verify its completion ID as shown in [Verify a response](#verify-a-response).

### Send plaintext after deployment verification

`e2ee: false` disables field encryption while retaining deployment and response
verification. This is also the setting for Gateway-only models.

```ts
const client = new InferenceClient({
  apiKey: process.env.NEARAI_API_KEY!,
  e2ee: false,
});
```

## Verify a response

Call `verifyResponse()` before using a JSON answer:

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

If signature retrieval fails transiently, retry `verifyResponse(id)` for the
existing completion.

`verified.attestations` contains all verified reports sharing the model signer.
For a Gateway receipt, use `verified.attestation`.

### Use the official OpenAI SDK

Pass the client's Fetch adapter to the OpenAI SDK and disable its automatic
inference retries:

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

Configure credentials on `InferenceClient`. With raw `client.fetch()`, consume
the response body before verification.

## Use a direct model endpoint

`DirectInferenceClient` connects to a model endpoint and verifies every returned
model report. Set `e2ee: true` to enable encryption. Direct clients are
experimental. The Node client pins requests to the verified model TLS fingerprints.

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

### Verify direct evidence manually

```ts
import {
  createPinnedTlsFetch,
  DirectAttestationClient,
  verifyDirectModelAttestations,
} from '@nearai/inference-sdk/node';

const baseUrl = 'https://glm-5-3-flash.completions.near.ai/v1';
const bootstrap = new DirectAttestationClient({ baseUrl });
const fetched = await bootstrap.fetchModelAttestations({ signingAlgo: 'ed25519' });
const verified = await verifyDirectModelAttestations(fetched);
const pinnedFetch = createPinnedTlsFetch(verified.spkiFingerprints);
const client = new DirectAttestationClient({
  baseUrl,
  apiKey: process.env.NEARAI_API_KEY,
  fetch: pinnedFetch,
});
```

Send Chat with `pinnedFetch` and retain the exact request and response bytes.
Use `client.fetchCompletionSignature({ completionId, signingAlgo: 'ed25519' })`
and pass the signature, bytes, and `verified.attestations` to `verifyDirectModelResponse()`.
It returns all verified attestations sharing the response's signer.

`verifyDirectModelAttestation()` verifies one report;
`verifyDirectModelAttestations()` verifies the returned set.

The runnable [direct/chat-completions.ts](../../examples/example-js/direct/chat-completions.ts),
[direct/chat-completions-with-openai-sdk.ts](../../examples/example-js/direct/chat-completions-with-openai-sdk.ts),
and [direct/chat-completions-bare.ts](../../examples/example-js/direct/chat-completions-bare.ts) examples each
include streaming and non-streaming calls. The bare example omits E2EE.

## Verify Gateway requests manually

The manual flow below uses a TEE model and has distinct stages:

1. Verify Gateway and model deployment evidence before sending a request.
2. Send the request and retain the exact body bytes sent and received.
3. Fetch the completion signature later and verify it against the retained
   evidence and bytes.

`fetchModelMetadata(model)` returns the model's provider and attestation support.

### Verify Gateway and model evidence

```ts
import {
  AttestationClient,
  createPinnedTlsFetch,
  verifyGatewayAttestation,
  verifyModelAttestation,
} from '@nearai/inference-sdk/node';

const model = 'z-ai/glm-5.3-flash';
const apiKey = process.env.NEARAI_API_KEY!;
const bootstrapClient = new AttestationClient({ apiKey });

const fetchedGateway = await bootstrapClient.fetchGatewayAttestation({
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
const client = new AttestationClient({ apiKey, fetch: pinnedTlsFetch });

const fetchedModelAttestations = await client.fetchModelAttestations({
  model,
  signingAlgo: 'ed25519',
});
if (fetchedModelAttestations.attestations.length === 0) {
  throw new Error('Gateway returned no model attestation');
}

const modelAttestations = await Promise.all(
  fetchedModelAttestations.attestations.map((attestation) =>
    verifyModelAttestation({
      attestation,
      clientBinding: fetchedModelAttestations.clientBinding,
    }),
  ),
);
```

Use `pinnedTlsFetch` instead of `fetch` for raw direct-Gateway requests that
your application sends itself. It performs normal certificate and hostname
verification, then requires each TLS peer to present the attested SPKI.

### Encrypt a raw Chat request

`prepareE2eeChatRequest` encrypts a Chat request using a verified model public key
and its signing algorithm. It returns the request and a paired response decryptor.

```ts
import { prepareE2eeChatRequest } from '@nearai/inference-sdk/node';

const selectedModelAttestation = modelAttestations.find(
  (attestation) =>
    attestation.signer.signingAlgo === 'ed25519' &&
    attestation.signingPublicKey !== undefined,
);
if (
  selectedModelAttestation === undefined ||
  selectedModelAttestation.signingPublicKey === undefined
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
    signingAlgo: selectedModelAttestation.signer.signingAlgo,
    publicKey: selectedModelAttestation.signingPublicKey,
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
```

Pass the captured `requestBody` and `responseBody` to the response-signature
functions below. With `stream: true`, `decryptResponse` returns a decrypted
SSE `Response`; consume its body as events arrive while retaining the encrypted
response clone for signature verification. HTTP error responses pass through
unchanged. The [bare example](../../examples/example-js/gateway/chat-completions-bare.ts) demonstrates
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
[client example](../../examples/example-js/gateway/chat-completions.ts) and
[bare example](../../examples/example-js/gateway/chat-completions-bare.ts), which require build provenance
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

for (const attestation of fetchedModelAttestations.attestations) {
  await verifyModelAttestation({
    attestation,
    clientBinding: fetchedModelAttestations.clientBinding,
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

See the [API reference](./api-reference.md#verifycomposemanagerdeploymentimageprovenance)
for file selection and GitHub access options.

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

The custom endpoint must preserve GitHub status codes, pagination, and response
bodies. For browser access, allow `Accept` and `X-GitHub-Api-Version` and expose
`Link` through CORS.

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
  findModelAttestationsForSignature,
  verifyGatewayResponse,
  verifyModelResponse,
} from '@nearai/inference-sdk/node';

const signature = await client.fetchCompletionSignature({
  completionId,
  signingAlgo: 'ed25519',
});

if (signature.kind === 'provider_tee') {
  // Preserve the routing/encryption key selected before sending the request.
  verifyModelResponse({
    requestBody,
    responseBody,
    signature,
    attestation: selectedModelAttestation,
  });
  const matchingAttestations = findModelAttestationsForSignature({
    attestations: modelAttestations,
    signature,
  });
  console.log(`Verified signature against ${matchingAttestations.length} matching reports.`);
} else {
  verifyGatewayResponse({
    requestBody,
    responseBody,
    signature,
    attestation: gateway,
  });
}
console.log(plaintext);
```

Gateway clients return the matching model reports in `result.attestations`.

## Handle errors

Request and evidence-selection failures use `ApiError`; verification failures use
`VerificationError`. Handle errors by `failure.code`. For exceptions wrapped by
OpenAI or Anthropic, use `getSdkError()` as shown in the
[API reference](./api-reference.md#errors-wrapped-by-official-sdks).

```ts
import { ApiError } from '@nearai/inference-sdk';

try {
  await client.fetchCompletionSignature({ completionId });
} catch (error) {
  if (!(error instanceof ApiError)) throw error;
  console.log(error.failure.code);
}
```
