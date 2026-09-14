# Verifiable AI SDK examples

These projects demonstrate attestation and response-receipt verification
against the canonical `z-ai/glm-5.3-flash` model.

The JavaScript SDK's Node.js example includes two entry points:

- `client.ts` uses `NearAiSecureClient`, which uses Ed25519 for Gateway/model
  evidence and response receipts, and enables E2EE by default. Each Chat
  request supplies its model; the client verifies fresh Gateway and model
  evidence before sending it. Because it imports the Node entry point and
  connects directly to the Gateway, it pins model evidence, Chat, and receipt
  requests to the SPKI bound by its verified Gateway evidence. This does not
  require reuse of the initial TLS connection. The example also verifies a
  response receipt after the completion is available.
- `bare.ts` explicitly verifies Gateway evidence, every returned model
  attestation, and each response receipt. It deliberately sends plaintext Chat
  JSON and does not demonstrate E2EE.

The bare example uses an explicit `ed25519` signing algorithm for Gateway,
model, and response-signature requests. All examples use only the
`NEARAI_API_KEY` environment variable.

```sh
export NEARAI_API_KEY=sk-your-api-key
```

The bare example sends the Chat request itself because receipt verification
needs its original bytes. It sends `x-no-aliasing: true` and
`Accept-Encoding: identity` so the model identity and response bytes are not
silently changed before verification. `NearAiSecureClient` retains those bytes
internally when its `createWithReceipt()` method is used. The response
signature's kind selects which previously verified signer checks the exact
response bytes; it does not replace either deployment verification.

The current API exposes one response signature at a time. Verifying both
deployments and that signature is useful, but does not yet form a complete
cryptographic model-to-Gateway-to-response chain for rewritten responses. That
receipt-chain work is tracked in [cloud-api#986](https://github.com/nearai/cloud-api/issues/986).

## JavaScript (Node.js)

The SDK must be built first because the example imports the local package's
published `dist` files.

```sh
pnpm --dir js install --frozen-lockfile
pnpm --dir js build
pnpm --dir examples/example-js install --frozen-lockfile
pnpm --dir examples/example-js check
pnpm --dir examples/example-js start:client
pnpm --dir examples/example-js start:bare
```

Requires Node.js 24 or later.

## Python

```sh
cd examples/example-py
uv run python main.py
```

Requires Python 3.12 or later and [uv](https://docs.astral.sh/uv/).

## Rust

```sh
cd examples/example-rs
cargo run
```

The Python and Rust projects use the sibling SDK source through local path
dependencies. Replace those dependencies with released package versions when
using these examples outside this repository.
