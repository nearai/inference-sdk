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

Install Node.js 24, then discover models once from the repository root.
Set `NEARAI_E2E_LANGUAGE` to `javascript`, `python`, `rust`, or `go` to select
one SDK's suites; the default selects all available suites.

```sh
export NEARAI_E2E_MODELS="$(node e2e/select-models.mjs)"
```

Run the selected SDK's command from the repository root:

```sh
# Node.js 24
cd js
pnpm install --frozen-lockfile
pnpm build
pnpm typecheck:e2e
pnpm test:e2e
```

```sh
# Python 3.12
cd py
uv sync --locked
uv run --no-sync pytest e2e -v --tb=short
```

```sh
# Rust stable
cd rs
cargo test --locked --test e2e -- --ignored --nocapture --test-threads=1
```

```sh
# Go 1.25.8+
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
dispatch from `main`. Releases test all four SDKs in both environments and
block publication on failure.

## Coverage

Each environment selects representative models from its public `/model/list`
catalog. The Chat matrix uses two NEAR TEE models, one Chutes model, and one
external model; all SDKs use the same selection. The same list includes a hosted
Jev model when the selected SDK has a System One suite. Each entry carries an
`endpoint` (`chat` or `systemone`), and each suite uses only its endpoint. A
missing required category fails setup.

| Area | Live checks |
| --- | --- |
| Deployment verification | Gateway quote and TLS identity; model and GPU evidence for NEAR TEE models. |
| Chat and receipts | JSON responses across the catalog; SSE for NEAR and external models; exact-byte signature verification and rejection of altered responses. |
| Responses | JSON and SSE with `store: false`, using the existing NEAR model selection; Gateway receipts over plain transport and OHTTP. |
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

## Official Jev SDK integration

`js/e2e/systemone.test.ts` and `py/e2e/test_systemone.py` exercise the published
`@typesafe-ai/sdk` and `typesafe-sdk` through NEAR's verified transports. They
send one real decision per case, parse the official response types, extract
`X-Generation-Id`, and verify the captured bytes. Receipt lookups alone may
retry. Compression, E2EE, OHTTP, and automatic inference retries are disabled.
Both Ed25519 and ECDSA are covered.

The official-SDK cases are part of the existing System One live suites and run
through the existing live commands and workflow. They use the same
`NEARAI_API_KEY`, `NEARAI_BASE_URL`, and `NEARAI_E2E_MODELS` configuration as the
native cases. The catalog selector supplies an external Jev model; there are no
separate Jev environment variables or CI steps.

Self-hosted cases use a `provider: "near"`, `endpoint: "systemone"` entry in the
same `NEARAI_E2E_MODELS` selection. Without one they explicitly skip. Running
these cases requires the routing contract from
[cloud-api#1285](https://github.com/nearai/cloud-api/issues/1285) and a suitable
self-hosted deployment. They preverify the selected model and require a provider
receipt matching its attested signing identity. An external model is never
substituted. The current catalog selector chooses only hosted Jev deployments.

Like the existing live tests, these suites require explicit configuration and
are excluded from ordinary unit-test runs. Missing required external-model
configuration or verification failures fail the tests.

The runnable examples use `examples/example-js/gateway/jev-helpers.ts` and
`examples/example-py/gateway/jev_helpers.py` to keep the API root, verified
transport, disabled retries/compression, and receipt-ID extraction together.
The official SDKs remain example/test dependencies only. Python uses
`inference.httpx2_client` to bridge
Jev's HTTPX2 client to the existing verified HTTPX transport.
