# Live E2E tests

These tests send real Chat requests and verify real attestation evidence and
response signatures. They run after pushes to `main` (including merged PRs)
and daily at 03:00 UTC, after the daily production deployment. GitHub may delay scheduled runs.
The **Live E2E** workflow can also be started manually from `main`.
Push, scheduled, and manual runs test both staging and production with all
four SDKs, as eight separate jobs. Releases run only the selected language
against both environments and block publication on failure. A failing test job
does not cancel the other environment.

## Configuration

Add these repository secrets in **Settings → Secrets and variables → Actions**:

| Environment | Fixed API URL | API key secret |
| --- | --- | --- |
| STG | `https://cloud-stg-api.near.ai/v1` | `NEARAI_STG_API_KEY` |
| PRD | `https://cloud-api.near.ai/v1` | `NEARAI_PRD_API_KEY` |

Use a dedicated test account with inference credits in each environment. URLs
are defined in the workflow; no URL secret is needed. Each test job receives only
its environment's API key, and both secrets are required before tests start.

Each environment discovers representative Chat models from its public
`/model/list` catalog: two NEAR TEE models, one Chutes model, and one external
model. All four SDKs receive the same selection for that environment. The
selector uses Chat capabilities, prefers non-reasoning models and lower token
prices, and fails if a category is missing. It does not silently fall back to a
hardcoded model.

The first NEAR model also runs the integrated E2EE/OHTTP cases for all four SDKs.
These capabilities are not listed separately in the catalog; missing support
fails the relevant case. The Gateway URL must expose its own TLS certificate,
not an aggregator's certificate.

Missing secrets fail the workflow. It does not run on pull requests and does
not expose credentials to build or dependency-install steps. Tests do not log
credentials, request bodies, or full attestation reports.

## Coverage

| SDK | Live checks |
| --- | --- |
| All four, all selected models | Gateway quote and peer TLS binding, JSON Chat responses and exact-byte receipt verification |
| All four, NEAR and external models | Complete SSE responses and exact-byte receipt verification |
| All four, NEAR models | Every returned model report and GPU evidence; model or Gateway receipt verification according to the returned signature kind |
| All four, external models | Gateway receipt verification; no NEAR model attestation or E2EE claims |
| All four, Chutes | Gateway receipt verification for JSON responses; no Chutes model attestation or E2EE claims |
| All four, signed responses | An altered response is rejected using the real receipt, without sending another request |
| All four | `InferenceClient` with unencrypted NEAR/Chutes/external Chat, Ed25519 E2EE, ECDSA E2EE, and OHTTP + E2EE |
| JavaScript | External OpenAI SDK using `InferenceClient.fetch`, generic package entry, and standalone verification functions |
| Go | External OpenAI Go client through the verified `http.RoundTripper`, JSON/SSE and E2EE |
| Python | External `AsyncOpenAI` using `InferenceClient.http_client`; explicit preflight and automatic preflight on the first Chat |
| Python, Rust, and Go | Standalone verification with both Ed25519 and ECDSA |
| All four | Standalone Chat uses the verified Gateway SPKI to pin its TLS connections |

Rust and Go also cover explicit and automatic preflight, cached evidence
timestamps, repeated receipt verification, and consuming streams through HTTP
EOF. The shared Gateway feature matrix is covered in all four SDKs;
JavaScript's generic entry and the JavaScript/Python/Go OpenAI transport adapters
are language-specific checks with no Rust adapter equivalent. None of the live
suites covers experimental direct endpoints or the example-specific Gateway
image-provenance allowlist.

The JavaScript tests import the built package entry points. Its generic entry
is exercised in Node; this is not a browser or CORS test. This suite targets
Gateway APIs, not experimental direct endpoints. Verification uses the SDK's
default TCB policy and real Intel/NVIDIA verifiers, not mocks or an application
deployment allowlist.

A complete four-language run without retries sends 105 small Chat requests per
environment (210 total), each capped at 1,024 completion tokens to leave room for
reasoning and a visible answer.
Responses must have non-empty answer content and finish with `stop`; empty or
token-truncated responses fail. The test does not require the model to return a
particular word. Chat requests that return HTTP 429 are retried up to three times
with 5, 10, and 20 second backoffs. A longer valid `Retry-After` is respected.
All four language suites disable additional OpenAI retries so this helper owns
the entire retry budget. Successful requests and failed streams are never replayed.
Receipt lookup retries transient API failures up to five attempts, with 0.5, 1,
2, and 4 second backoffs. All retries remain within each model case's 180 second
deadline. Successful Chat requests are not resent, and interrupted streams,
invalid responses, and cryptographic verification failures are not retried.
Test failures and timeouts fail CI; they are not converted into skipped or
successful tests.

Chutes' own evidence format and encrypted channel are outside these SDK
verification APIs. Its streaming support is separately gated by the provider,
so this suite tests Chutes with JSON only and verifies the Gateway signature over
the client-facing response. A missing signature fails every receipt test.

## Local use

Select one environment by setting `NEARAI_BASE_URL` to its URL above and
`NEARAI_API_KEY` to that environment's key through your local secret manager
or shell. Do not commit a key or paste it into a
command that saves shell history.
Discover models once from the repository root (Node.js 24; no API key used):

```sh
NEARAI_E2E_MODELS=$(node e2e/select-models.mjs)
export NEARAI_E2E_MODELS
NEARAI_E2E_SYSTEMONE_MODEL=$(node e2e/select-models.mjs systemone)
export NEARAI_E2E_SYSTEMONE_MODEL
```

Then run the relevant command from the repository root:

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
# Go 1.25.8+; the verifier is embedded
export CGO_ENABLED=0
go -C go test -tags=e2e ./e2e -v -timeout 15m
go -C examples/example-go test -tags=e2e -run '^TestLiveOpenAI$' -v -timeout 5m .
```

Go has six live SDK cases: standalone Ed25519/ECDSA across the selected catalog,
integrated plaintext across the catalog, and Ed25519 E2EE, ECDSA E2EE, and
OHTTP + E2EE on the first NEAR model. Each covers JSON/SSE (Chutes JSON only).
A seventh case covers the official OpenAI Go SDK's encrypted JSON and SSE calls.
Go live code uses the `e2e` build tag; ordinary test commands cannot select it.

Normal unit-test commands do not contact the live service. Jest selects only
`test/**/*.spec.ts`, pytest defaults to `test/`, and Rust's live tests are
explicitly ignored until the E2E command opts into them. PR CI still lints and
typechecks/compiles the live test code without using secrets.

Rust and Go also exercise System One via `NEARAI_E2E_SYSTEMONE_MODEL`, selected
from the public decision-model catalog. Both algorithms run with production
quote verification, Gateway TLS pinning, explicit receipt verification, and all
three answer variants. No System One inference request is retried; unavailable
receipts use bounded backoff. These tests require live credentials and remain
opt-in locally.
