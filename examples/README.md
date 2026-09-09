# Verifiable AI SDK examples

Each project follows the same three-stage flow against the canonical
`z-ai/glm-5.2` model:

1. Verify the Gateway deployment and, where the runtime supports it, the TLS
   peer observed while fetching its attestation.
2. Verify every target-model deployment returned by the preflight request.
3. Send one non-streaming and one streaming completion, retain the exact
   request and response bytes, then verify the returned response receipt.

The examples use an explicit ECDSA signing algorithm for all three stages.
The Gateway's report and signature endpoints currently have different defaults,
so relying on those defaults could make the preflight evidence and response
signer differ. They use only the `NEARAI_API_KEY` environment variable.

```sh
export NEARAI_API_KEY=sk-your-api-key
```

The SDK retrieves and verifies attestation evidence; the examples send the
completion request because applications must retain its original bytes for
response verification. They send `x-no-aliasing: true` and
`Accept-Encoding: identity` so the model identity and response bytes are not
silently changed before verification. The returned `signature_kind` selects
which previously verified signer checks the exact response bytes; it does not
replace either deployment preflight.

The current API exposes one response signature at a time. Verifying both
deployments and that signature is useful, but does not yet form a complete
cryptographic model-to-Gateway-to-response chain for rewritten responses. That
receipt-chain work is tracked in [cloud-api#986](https://github.com/nearai/cloud-api/issues/986).

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
