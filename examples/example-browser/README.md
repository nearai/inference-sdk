# Browser Private TEE chat

A browser example with deployment verification, encrypted streaming Chat, and
per-response signature verification. The verification center shows model and
Gateway hardware evidence and each response's receipt.

## Run

Use Node.js 24 or later and pnpm. From the repository root:

```sh
pnpm --dir js install --frozen-lockfile
pnpm --dir js build
pnpm --dir examples/example-browser install --frozen-lockfile
pnpm --dir examples/example-browser dev
```

Open `http://127.0.0.1:5173`, enter a Cloud API key, choose a model, and send a
message. The endpoint defaults to `https://cloud-api.near.ai/v1`.
The key is sent to the selected endpoint during verification, so choose an
endpoint you trust. The URL and key stay in tab memory. Changing either, or
switching models, starts a new conversation.

The model picker loads ready TEE text models from the endpoint's public catalog.
If discovery fails, it offers `z-ai/glm-5.3-flash`; deployment verification still
runs before Chat.

Build with `pnpm --dir examples/example-browser build`.

## Verification flow

1. `client.verify(model)` verifies the selected model and Gateway before sending.
   Chat and the hardware-details dialog reuse that client's verification cache.
2. Chat encrypts supported fields to the attested model key and streams the reply.
3. After the stream finishes, `client.verifyResponse(completionId)` verifies its
   receipt. Only responses with a verified `provider_tee` receipt enter subsequent
   conversation history. Transient receipt lookup failures offer a retry.

The details dialog shows the evidence's original `verifiedAt` time. Structured
SDK error codes identify failed checks.

## Browser setup

Browser Fetch uses HTTPS but cannot pin the peer certificate to the Gateway
attestation. Applications needing that binding can use the Node client.

The Vite development server relays Intel collateral and NVIDIA NRAS/JWKS
requests for browser access. It strips browser credentials from those requests;
quote and signature verification run in the browser. Production deployments
need restricted relays or CORS-enabled evidence services.

The selected Cloud API must allow the app's origin for catalog, attestation,
Chat, and signature requests. The local origin is `http://127.0.0.1:5173`.
See the SDK's [verification guide](../../js/docs/verification-guide.md) for
deployment policies and the scope of each verification result.
