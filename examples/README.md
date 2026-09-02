# Verifiable AI SDK examples

Each project sends one non-streaming and one streaming completion to the
canonical `z-ai/glm-5.2` model, keeps the exact request and response bytes,
fetches each completion signature, and verifies the evidence selected by
`signature_kind`. They use only the `NEARAI_API_KEY` environment variable.

```sh
export NEARAI_API_KEY=sk-your-api-key
```

The SDK retrieves and verifies attestation evidence; the examples send the
completion request because applications must retain its original bytes for
response verification. They send `x-no-aliasing: true` and
`Accept-Encoding: identity` so the model identity and response bytes are not
silently changed before verification.

## JavaScript

The JavaScript SDK must be built first because the example imports the local
package's published `dist` files.

```sh
pnpm --dir js install --frozen-lockfile
pnpm --dir js build
pnpm --dir examples/example-js install
pnpm --dir examples/example-js start
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

Cloud API may need a moment to store a completion signature. If the signature
lookup reports that it is unavailable, retry the lookup rather than treating it
as a failed cryptographic verification or reusing altered request/response
bytes.
