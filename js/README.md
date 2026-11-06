# NEAR AI Inference SDK for TypeScript

`@nearai/inference-sdk` provides Chat Completions, Responses, Messages, and System One
with deployment attestation, response signature verification, and optional encryption.

## Install

Node.js 24.22.1+ or a modern browser. The package uses ESM.

```sh
npm install @nearai/inference-sdk
```

## Send and verify a Chat completion

Set `NEARAI_API_KEY`, then send a request with E2EE enabled:

```sh
export NEARAI_API_KEY='your-api-key'
```

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

The client uses the NEAR AI Cloud Gateway by default. It verifies the Gateway and
every returned model report before inference. Call `verifyResponse(id)` to verify
the response signature; consume streaming responses completely first.

In Node.js, import from `@nearai/inference-sdk/node` for attested Gateway TLS
pinning. In browsers, import from `@nearai/inference-sdk`; browser Fetch does not
expose the TLS peer certificate.

## Configuration

| Feature | Default |
| --- | --- |
| Gateway and supported model attestation | Enabled |
| Signing algorithm | Ed25519; ECDSA also supported |
| E2EE for supported Chat models | Disabled; enable with `e2ee: true` |
| OHTTP for Chat, Responses, and Messages | Disabled; enable with `ohttp: true`; requires Ed25519 |

Call `await client.verify(model)` to verify a deployment before sending a prompt.
Use deployment and image provenance policies to restrict accepted deployments.
Models without model attestation use Gateway-only verification with E2EE disabled.

## Documentation

- [Verification guide](./docs/verification-guide.md): streaming, official SDK integration,
  encryption, deployment policies, and standalone verification.
- [API reference](./docs/api-reference.md): options, methods, and result fields.
- [Runnable examples](../examples/README.md#javascript-setup): Gateway and Direct workflows.
- [Development checks](../TESTING.md#validation) and [live E2E tests](../e2e/README.md).
