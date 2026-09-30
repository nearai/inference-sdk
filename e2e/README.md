# Live E2E tests

These tests send real Chat requests and verify real attestation evidence and
response signatures. They run after pushes to `main` (including merged PRs)
and daily at 03:00 UTC, after the daily production deployment. GitHub may delay scheduled runs.
The **Live E2E** workflow can also be started manually from `main`.
Push, scheduled, and manual runs test both staging and production with all
three SDKs, as six separate jobs. Releases run only the selected language
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
model. All three SDKs receive the same selection for that environment. The
selector uses Chat capabilities, prefers non-reasoning models and lower token
prices, and fails if a category is missing. It does not silently fall back to a
hardcoded model.

The first NEAR model also runs JavaScript's E2EE and OHTTP feature cases. These
capabilities are not listed separately in the catalog; missing support fails
the relevant case. The Gateway URL must expose its own TLS certificate, not an
aggregator's certificate.

Missing secrets fail the workflow. It does not run on pull requests and does
not expose credentials to build or dependency-install steps. Tests do not log
credentials, request bodies, or full attestation reports.

## Coverage

| SDK | Live checks |
| --- | --- |
| All three, all selected models | Gateway quote and peer TLS binding, JSON Chat responses and signature lookup |
| All three, NEAR and external models | Complete SSE responses and exact-byte receipt verification |
| All three, NEAR models | Every returned model report and GPU evidence; model or Gateway receipt verification according to the returned signature kind |
| All three, external models | Gateway receipt verification; no NEAR model attestation or E2EE claims |
| All three, Chutes | Original JSON responses must report `SIGNATURE_UNSUPPORTED`; this is not successful response verification |
| All three, signed responses | An altered response is rejected using the real receipt, without sending another request |
| JavaScript | Node `InferenceClient` with unencrypted NEAR/Chutes/external Chat, Ed25519 E2EE, ECDSA E2EE, and OHTTP + E2EE |
| JavaScript | External OpenAI SDK using `InferenceClient.fetch`, generic package entry, and standalone verification functions |
| Python and Rust | Standalone verification with both Ed25519 and ECDSA |

The JavaScript tests import the built package entry points. Its generic entry
is exercised in Node; this is not a browser or CORS test. This suite targets
Gateway APIs, not experimental direct endpoints. Verification uses the SDK's
default TCB policy and real Intel/NVIDIA verifiers, not mocks or an application
deployment allowlist.

A complete three-language run sends 50 small Chat requests per environment (100 total), each
capped at 128 completion tokens. JavaScript disables OpenAI request retries.
Receipt lookup retries transient API failures up to five attempts, with 0.5, 1,
2, and 4 second backoffs, within each model case's 180 second deadline. It never
resends Chat or retries a cryptographic verification failure.
Test failures and timeouts fail CI; they are not converted into skipped or
successful tests.

Chutes' own evidence format and encrypted channel are outside these SDK
verification APIs. Its streaming support is separately gated by the provider,
so this suite tests Chutes with JSON only and checks the explicit unavailable
signature error. A missing signature still fails every NEAR/external receipt test.

## Local use

Select one environment by setting `NEARAI_BASE_URL` to its URL above and
`NEARAI_API_KEY` to that environment's key through your local secret manager
or shell. Do not commit a key or paste it into a
command that saves shell history.
Discover models once from the repository root (Node.js 24; no API key used):

```sh
NEARAI_E2E_MODELS=$(node e2e/select-models.mjs)
export NEARAI_E2E_MODELS
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

Normal unit-test commands do not contact the live service. Jest selects only
`test/**/*.spec.ts`, pytest defaults to `test/`, and Rust's live tests are
explicitly ignored until the E2E command opts into them. PR CI still lints and
typechecks/compiles the live test code without using secrets.
