# NEAR AI Inference SDK for TypeScript

Chat with NEAR AI models using an OpenAI-compatible client. The SDK verifies
deployment attestations before sending a prompt, supports end-to-end encryption
to the model, and can verify the signature of each response.

Works in Node.js and browsers. You can use the built-in Chat client, connect it
to the OpenAI SDK, or use the verification functions with your own HTTP code.

## Install

```sh
npm install @nearai/inference-sdk
```

Node.js applications require Node.js 24 or later. The package uses ESM.

## Quick start

Set your API key, save the code below as `chat.mjs`, and run `node chat.mjs`:

```sh
export NEARAI_API_KEY='your-api-key'
```

```js
import { InferenceClient } from '@nearai/inference-sdk/node';

async function main() {
  const apiKey = process.env.NEARAI_API_KEY;
  if (!apiKey) throw new Error('Set NEARAI_API_KEY');

  const client = new InferenceClient({
    apiKey,
    e2ee: true,
  });

  const completion = await client.chat.completions.create({
    model: 'z-ai/glm-5.3-flash',
    messages: [{ role: 'user', content: 'Hello!' }],
  });

  // Check the response signature before displaying the answer.
  const verified = await client.verifyResponse(completion.id);
  console.log(`Verified ${verified.signatureKind} response`);
  console.log(completion.choices[0]?.message.content ?? '');
}

await main();
```

This example enables E2EE with a model that supports it. Encryption is off by
default. Deployment verification runs with or without encryption, but response
signature verification requires the explicit call shown above.

## What is verified?

- **Gateway:** its Intel TDX attestation, signing identity, and measured
  deployment configuration. In Node.js, the client also verifies and pins its
  TLS identity.
- **Model:** every returned model attestation, including deployment measurements
  and NVIDIA GPU evidence when present. Models without supported model
  attestation use Gateway-only verification and cannot use E2EE.
- **Response:** a signature over the exact request and response bytes, checked
  against the verified model or Gateway signer.

The SDK checks that the evidence is authentic. It does not ship an approved
release allowlist; applications can supply their own deployment and image-build
policies. The [guide](https://github.com/nearai/inference-sdk/blob/main/js/docs/verification-guide.md#what-verification-proves)
explains these checks and the different guarantees of model and Gateway signatures.

Successful deployment checks are cached for 60 minutes. Response bytes are kept
separately for 60 minutes after completion, so verify responses before they expire.
Both durations are configurable.

## Documentation

- [Guide](https://github.com/nearai/inference-sdk/blob/main/js/docs/verification-guide.md) — streaming, OpenAI integration, encryption, policies, and errors.
- [API reference](https://github.com/nearai/inference-sdk/blob/main/js/docs/api-reference.md) — parameters, defaults, and return values.
- [Examples](https://github.com/nearai/inference-sdk/tree/main/examples#javascript-nodejs) — runnable client and manual-verification projects.
- [Browser setup](https://github.com/nearai/inference-sdk/blob/main/js/docs/verification-guide.md#connect-through-an-application-proxy) — use your backend for credentials and attestation-service access.

Direct model endpoints are [experimental](https://github.com/nearai/inference-sdk/blob/main/js/docs/verification-guide.md#use-a-direct-model-endpoint).
Use the Gateway client above for production.
