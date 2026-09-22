# Browser Private TEE chat

A deliberately small, one-model-at-a-time example using the **browser** entry point of
`@nearai/inference-sdk`. It sends streaming Chat Completions with E2EE enabled,
checks fresh Gateway evidence, and verifies each finished response by completion
ID. The UI has separate Gateway, model/E2EE, and per-message receipt states.

## Run

Use Node.js 24 or later and pnpm. From the repository root:

```sh
pnpm --dir js install --frozen-lockfile
pnpm --dir js build
pnpm --dir examples/example-browser install --frozen-lockfile
pnpm --dir examples/example-browser dev
```

Open `http://127.0.0.1:5173`. The Cloud API URL defaults to
`https://cloud-api.near.ai/v1`; you can edit it before sending. Enter a key
accepted by that endpoint, choose a model, and send a message. **The key is
sent to the URL you enter**, so use only an endpoint you trust. The URL and key
are kept in tab memory, not persisted. Non-HTTPS URLs are rejected except for
loopback development addresses. Changing the URL or key starts a new SDK
session and conversation.

The example loads the public model catalog from the selected URL without the
key and lists ready text-chat models marked as verifiable
vLLM deployments with attestation support. If the catalog cannot be reached,
`z-ai/glm-5.3-flash` remains the built-in default; the SDK still verifies its
evidence before sending. Changing models starts a new conversation. With the
default URL, the Vite development server does not receive the key or Chat
prompts. A custom URL determines their destination—including if you point it
at a local server. The browser sends authenticated evidence and Chat requests
directly to that selected endpoint.

To compile the example against this repository's built SDK:

```sh
pnpm --dir examples/example-browser build
```

## What the UI means

1. **Gateway evidence verified**: the example independently fetches a fresh
   Gateway quote with `AttestationClient` and passes it to
   `verifyGatewayAttestation`. This exposes signer, TCB status, and deployment
   measurements. The `InferenceClient` separately verifies Gateway and model
   evidence before it sends each Chat request (or reuses its verified session
   within the configured attestation-cache lifetime).
2. **Model evidence verified · E2EE**: `InferenceClient` accepted the model
   evidence and bound its E2EE public key before the Chat request was sent.
   `e2ee: true` is explicit in the example, although it is the SDK default.
3. **Model response verified**: only after the entire stream is consumed does
   the example call `client.verifyResponse(completionId)` on the **same client**
   that sent it. A `provider_tee` signature is shown as model-verified. If only
   a Gateway signature is verified, the UI warns that it is **not** a model
   receipt, and the reply is not added to trusted conversation history. A
   failed or missing receipt is never labeled verified.

Verification errors show the SDK's structured failure code. Transient evidence
services can fail; that does not make an unverified response safe to trust.

## Browser and deployment boundaries

- The browser uses ordinary HTTPS, but Fetch does **not** expose the TLS peer
  certificate. Unlike the Node client, this example cannot attest or pin the
  peer certificate to the Gateway quote. The UI explicitly says so.
- E2EE encrypts the SDK's supported Chat fields to the attested model key. It
  does **not** promise to hide HTTP metadata or arbitrary extra JSON fields.
- NVIDIA NRAS does not accept browser CORS preflights. The Vite server proxies
  **only** the NRAS evidence POST and NVIDIA JWKS GET during local development.
  It removes the browser's `Origin` and other local credentials before forwarding;
  NRAS otherwise rejects the POST with `403 Invalid CORS request`.
  The SDK still verifies NVIDIA's signed JWT, nonce, issuer, and result in the
  browser. This proxy never receives the API key or plaintext Chat prompts.
  Do not publish this unauthenticated development proxy. A production app needs
  a restricted/authenticated evidence relay (or an appropriately CORS-enabled
  upstream), plus a trusted JWKS source.
- A cross-origin Cloud API endpoint must allow the web app's origin for its
  model catalog, authenticated evidence, Chat, and signature requests. The development origin is
  `http://127.0.0.1:5173`; another deployment may require CORS configuration.
- This example does not add an application-specific deployment release
  allowlist, image-provenance policy, OHTTP, or multi-model routing. Add such
  policies before making stronger production claims.
