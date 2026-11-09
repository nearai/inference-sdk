# Live E2E tests

Run the SDKs against staging or production to check deployment attestation,
inference, and response signatures. These tests make billable requests and
require a funded test account.

## Local use

Set `NEARAI_API_KEY` through your local secret manager or shell and set
`NEARAI_BASE_URL` to the matching environment:

| Environment | `NEARAI_BASE_URL` |
| --- | --- |
| Staging | `https://cloud-stg-api.near.ai/v1` |
| Production | `https://cloud-api.near.ai/v1` |

Install Node.js 24.22.1 or later, then validate the fixed models once from the repository root.
Set `NEARAI_E2E_LANGUAGE` to `javascript`, `python`, `rust`, or `go` to select
one SDK's suites; the default selects all available suites.

```sh
export NEARAI_E2E_MODELS="$(node e2e/select-models.mjs)"
```

Run the selected SDK's command from the repository root:

```sh
# Node.js 24.22.1+
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
# Go 1.26.10+
export CGO_ENABLED=0
go -C go test -tags=e2e ./e2e -v -timeout 15m
go -C examples/example-go test -tags=e2e -run '^TestLive' -v -timeout 15m .
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

### Slack failure notifications

For optional failure alerts, create a [Slack incoming webhook](https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/)
for the destination channel and save its URL as the repository Actions secret
`TEST_ALERTS_SLACK_WEBHOOK_URL`.

A failed configuration or SDK job sends the failed job names and a workflow run link.

## Coverage

All SDKs and both environments use the fixed mainstream models in
[`models.json`](models.json). **To replace a model, edit its `id` in that file.**
Each model is listed once, with its `provider` (`near`, `chutes`, or `external`)
and `endpoints` (`chat`, `responses`, `messages`, or `systemone`). A model used
by multiple endpoints shares the same ID. The first NEAR Chat model is also the
default for shared encryption/client cases.

Keep the provider and endpoint coverage below when replacing models. Validate
the replacement against staging and production:

```sh
node --test e2e/select-models.test.mjs
NEARAI_BASE_URL=https://cloud-stg-api.near.ai/v1 node e2e/select-models.mjs
NEARAI_BASE_URL=https://cloud-api.near.ai/v1 node e2e/select-models.mjs
```

The selector checks each configured model ID and its capabilities against `/model/list`.

| Area | Live checks |
| --- | --- |
| Deployment | Gateway attestation and TLS identity, plus model and GPU evidence for NEAR TEE models. |
| Chat | JSON and streaming receipts, matching model reports, and rejection of altered responses. |
| Responses and Messages | JSON and streaming receipts through the native clients and supported official SDKs. |
| Encryption | Chat E2EE with Ed25519 and ECDSA, and OHTTP with Ed25519. |
| System One | Decision receipts for the configured deployment. |

## Official TypeSafe SDK integration

The JavaScript and Python suites send decisions to the configured hosted Jev model
through the official TypeSafe SDK and verify the response bytes using
`X-Generation-Id`. They run with the same commands and configuration as the
native System One tests.
