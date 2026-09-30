# NEAR AI Inference SDK for TypeScript

`@nearai/inference-sdk` provides OpenAI-compatible Chat Completions with
Gateway and model attestation verification, response signature verification,
and optional encryption. Use `InferenceClient` to get started in Node.js or
[browser applications](#browser-applications).

## Install

Requires Node.js 24 or later for Node usage. The package publishes ESM.
Install with npm:

```sh
npm install @nearai/inference-sdk
```

## Send and verify a Chat completion

Set your NEAR AI Cloud API key in your server environment:

```sh
export NEARAI_API_KEY='your-api-key'
```

Save this example as `chat.mjs` and run it with `node chat.mjs`:

```js
import { InferenceClient } from '@nearai/inference-sdk/node';

const apiKey = process.env.NEARAI_API_KEY;
if (!apiKey) throw new Error('Set NEARAI_API_KEY before running this example');

const client = new InferenceClient({
  apiKey,
  e2ee: true,
});

const completion = await client.chat.completions.create({
  model: 'z-ai/glm-5.3-flash',
  messages: [{ role: 'user', content: 'Hello!' }],
});

// Verify the completion signature before using the answer.
const verified = await client.verifyResponse(completion.id);
console.log(`Verified ${verified.signatureKind} response`);
console.log(completion.choices[0]?.message.content ?? '');
```

The client connects to the NEAR AI Cloud Gateway by default. This example
explicitly enables E2EE, which encrypts supported Chat fields to an attested
model and decrypts its response. Choose a model that supports NEAR model
attestation; E2EE rejects unsupported models before sending Chat.

The Node entry point verifies the Gateway's TLS identity against its attestation
and pins subsequent requests to that identity.

## When verification happens

1. **Before sending Chat:** the client verifies Gateway evidence and checks
   the requested model's attestation support. Supported models require every
   returned model report to pass. The client can reuse cached verification;
   a failed required check stops the request.
2. **After receiving the response:** call `verifyResponse(completion.id)` to
   verify the completion signature against the exact request and response bytes
   and the evidence retained for that request. Receiving a completion does not
   automatically verify its signature.
3. **For streaming:** consume the entire stream before calling `verifyResponse()`.
   Any output displayed before that call succeeds is not yet signature-verified.
   See the [streaming example](./docs/verification-guide.md#stream-an-e2ee-completion).

To verify when a user selects a model, before they send a message, call
`await client.verify(model)`. It sends no Chat request and uses the same
configured checks, cache, and in-flight verification as Chat. It resolves
with verified Gateway and model reports for your UI, or rejects if verification
fails. This optional preflight verifies the deployment; you still call `verifyResponse()` to verify
a particular reply. See [deployment preverification and caching](./docs/verification-guide.md#cache-deployment-verification).

## Verification and encryption

These defaults apply to the Gateway `InferenceClient`:

| Feature | Purpose | Default |
| --- | --- | --- |
| Attestation | Verify Gateway evidence and model evidence when supported | Enabled |
| Response verification | Check the completion signature against its exact request and response bytes | Explicit `verifyResponse()` call |
| E2EE | Encrypt supported Chat fields to the attested model | Disabled; set `e2ee: true` |
| OHTTP | Encrypt the Chat HTTP exchange to the attested Gateway | Disabled; set `ohttp: true` |

E2EE and OHTTP are independent. OHTTP requires Ed25519 and also works with
Gateway-only models. See [OHTTP configuration and scope](./docs/verification-guide.md#use-ohttp)
and [which fields E2EE protects](./docs/verification-guide.md#e2ee-scope-and-response-handling).

Gateway attestation verifies the Gateway's trusted execution environment (TEE)
and signing identity. Model attestation verifies the model deployment's TEE,
signing identity, measurements, and available GPU evidence.

A `provider_tee` response signature binds the request and response bytes to an
attested model signer. A `gateway` signature binds them to an attested Gateway
signer; it does not prove execution inside a model TEE. Models without supported
model attestation use the **Incognito** flow: Gateway verification only.
E2EE and configured model deployment policies reject this flow before Chat.

Attestation verification does not approve particular deployment measurements
by default. Supply a deployment policy to require an approved deployment, or
image provenance policies to check its images against required GitHub builds.
See [deployment policies](./docs/verification-guide.md#cache-deployment-verification)
and [image build provenance](./docs/verification-guide.md#optional-image-build-provenance).

Verification results are cached for 60 minutes after successful verification
by default. `verify(model)` and Chat share this cache; Chat reuses a preflight
result while it remains cached. Set `attestationCacheTimeToLiveMs: 0` to check
before every request, even after a successful `verify(model)`. Response records
are retained separately for 60 minutes; call `verifyResponse()` before they
expire. See the [API reference](./docs/api-reference.md) for cache settings and
signing algorithm options.

## Browser applications

Import from `@nearai/inference-sdk` in browsers.

Browser Fetch does not expose the TLS peer certificate, so the browser client
cannot perform the attested TLS identity check provided by the Node entry point.
Standard HTTPS certificate validation still applies.

## Use the OpenAI SDK

`InferenceClient` provides a reusable `fetch` transport for the official OpenAI
SDK, including streaming. Follow the
[OpenAI SDK integration example](./docs/verification-guide.md#use-the-official-openai-sdk)
to configure it and verify responses.

## Advanced APIs

- **Manual verification:** `AttestationClient` fetches metadata, evidence, and
  signatures. Use the [standalone verification functions](./docs/verification-guide.md#verify-gateway-requests-manually)
  when your application needs to control each step.
- **Standalone E2EE:** [`prepareE2eeChatRequest`](./docs/verification-guide.md#encrypt-a-raw-chat-request)
  encrypts a raw Chat request and supplies a JSON/SSE response decryptor.
  Your application verifies the model key and response signature separately.
- **Direct model endpoints (experimental):** `DirectInferenceClient` and
  `DirectAttestationClient` connect to model endpoints without Gateway
  verification. They are not recommended for production in either entry point;
  direct TLS fingerprint binding is currently disabled. Use Gateway clients
  for production and review the [direct-endpoint limitations](./docs/verification-guide.md#use-a-direct-model-endpoint).

## Documentation

- [Verification guide](./docs/verification-guide.md): encryption, streaming,
  proxies, deployment policies, response verification, and error handling.
- [API reference](./docs/api-reference.md): public functions, parameters,
  defaults, and result fields.
- [Runnable examples](../examples/README.md): Gateway and direct-model clients,
  standalone verification, and OpenAI SDK integration.
