# Live E2E tests

Run the SDKs against staging or production to check deployment attestation,
inference, and response signatures. These tests require a funded test account
and make billable requests.

## Local use

Set `NEARAI_API_KEY` through your local secret manager or shell and set
`NEARAI_BASE_URL` to the matching environment:

| Environment | `NEARAI_BASE_URL` |
| --- | --- |
| Staging | `https://cloud-stg-api.near.ai/v1` |
| Production | `https://cloud-api.near.ai/v1` |

Install Node.js 24 and `jq`, then discover models once from the repository root.
Set `NEARAI_E2E_LANGUAGE` to `javascript`, `python`, `rust`, or `go` to select
one SDK's suites; the default selects all available suites.

```sh
selection=$(node e2e/select-models.mjs)
export NEARAI_E2E_MODELS="$(printf '%s' "$selection" | jq -c '.models')"
export NEARAI_E2E_SYSTEMONE_MODEL="$(printf '%s' "$selection" | jq -r '.systemoneModel')"
```

Run the selected SDK's command from the repository root:

```sh
# JavaScript: Node.js 24 and pnpm
cd js
pnpm install --frozen-lockfile
pnpm build
pnpm typecheck:e2e
pnpm test:e2e
```

```sh
# Python: Python 3.12 and uv
cd py
uv sync --locked
uv run --no-sync pytest e2e -v --tb=short
```

```sh
# Rust: stable toolchain
cd rs
cargo test --locked --test e2e -- --ignored --nocapture --test-threads=1
```

```sh
# Go 1.25.8+; includes the external OpenAI client example
export CGO_ENABLED=0
go -C go test -tags=e2e ./e2e -v -timeout 15m
go -C examples/example-go test -tags=e2e -run '^TestLiveOpenAI$' -v -timeout 5m .
```

Ordinary unit-test commands exclude the live suites. PR CI checks their source
without making live requests.

## CI configuration

Add `NEARAI_STG_API_KEY` and `NEARAI_PRD_API_KEY` as repository Actions secrets.
Both are required. Each test job receives only its environment's key.

The [Live E2E workflow](../.github/workflows/e2e.yml) runs all four SDKs against
both environments after pushes to `main`, daily at 03:00 UTC, and on manual
dispatch from `main`. Releases test the selected SDK in both environments and
block publication on failure.

## Coverage

Each environment selects representative models from its public `/model/list`
catalog. The Chat matrix uses two NEAR TEE models, one Chutes model, and one
external model; all SDKs use the same selection. A missing category fails setup.

| Area | Live checks |
| --- | --- |
| Deployment verification | Gateway quote and TLS identity; model and GPU evidence for NEAR TEE models. |
| Chat and receipts | JSON responses across the catalog; SSE for NEAR and external models; exact-byte signature verification and rejection of altered responses. |
| Encryption | Ed25519 and ECDSA E2EE, plus OHTTP + E2EE, on a NEAR model. |
| Client integration | Integrated and standalone SDK APIs; OpenAI adapters for JavaScript, Python, and Go. |

The suite uses real verifiers and Gateway endpoints. Chutes cases use JSON and
Gateway receipts. Browser/CORS and experimental Direct endpoints have separate
integration requirements.

The four-SDK Chat matrix sends 105 requests per environment before retries,
with at most 1,024 completion tokens each. Responses must contain an answer and
finish with `stop`. Test failures and timeouts fail the workflow.

Receipt lookups retry transient API failures up to five attempts within the
model case's 180 second deadline. A receipt retry does not send another
inference request.
