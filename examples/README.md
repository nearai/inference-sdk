# Verifiable AI SDK examples

These projects verify Gateway and model attestations before sending Chat
Completions, then verify the response signature. The JavaScript examples use
`z-ai/glm-5.3-flash`; Python and Rust use `z-ai/glm-5.2`. All read the API key
from `NEARAI_API_KEY`.

```sh
export NEARAI_API_KEY=sk-your-api-key
```

## JavaScript (Node.js)

All three entry points include non-streaming and streaming calls:

| File | Usage | E2EE |
| --- | --- | --- |
| `bare.ts` | Fetches and verifies evidence, sends requests, and verifies signatures using standalone functions. | Not included |
| `client.ts` | Uses `SecureClient.chat.completions.create()` and `verifyResponse(id)`. | Enabled |
| `openai-sdk-compatible.ts` | Passes `secureClient.fetch` to one reusable OpenAI client, then calls `secureClient.verifyResponse(id)`. | Enabled |

All three verify Gateway TLS identity. The secure clients also pin later
evidence, Chat, and signature requests to that identity. They cache attestation
results for 15 minutes and retain response records for 15 minutes after body
completion. Change `SIGNING_ALGO` from `'ed25519'` to `'ecdsa'` to use ECDSA.

The bare example preserves exact request and response bytes for signature
verification. It sends `x-no-aliasing: true` and `Accept-Encoding: identity`.
The secure clients handle byte capture internally.

The SDK must be built first because the example imports the local package's
published `dist` files.

```sh
pnpm --dir js install --frozen-lockfile
pnpm --dir js build
pnpm --dir examples/example-js install --frozen-lockfile
pnpm --dir examples/example-js check
pnpm --dir examples/example-js start:client
pnpm --dir examples/example-js start:bare
pnpm --dir examples/example-js start:openai-sdk-compatible
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
