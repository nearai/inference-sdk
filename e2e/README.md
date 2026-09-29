# Live E2E tests

These tests send real Chat requests and verify real attestation evidence and
response signatures. They run after pushes to `main` (including merged PRs)
and daily at 02:17 UTC / 10:17 Asia/Shanghai. GitHub may delay scheduled runs.
The **Live E2E** workflow can also be started manually from `main`.

## Configuration

Add these repository secrets in **Settings → Secrets and variables → Actions**:

| Secret | Value |
| --- | --- |
| `NEARAI_E2E_BASE_URL` | Gateway HTTPS API base URL including `/v1`, such as `https://cloud-api.near.ai/v1/` |
| `NEARAI_E2E_API_KEY` | API key for a dedicated test account with inference credits |

The optional repository variable `NEARAI_E2E_MODEL` selects the model. It
defaults to `z-ai/glm-5.3-flash`. Use a canonical NEAR-hosted GPU model that
supports both signing algorithms, E2EE, and OHTTP. The endpoint must expose the
Gateway's own TLS certificate, not an aggregator's certificate.

Missing secrets fail the workflow. It does not run on pull requests and does
not expose credentials to build or dependency-install steps. Tests do not log
credentials, request bodies, or full attestation reports.

## Coverage

| SDK | Live checks |
| --- | --- |
| All three | Gateway quote and peer TLS binding, every returned model report, GPU evidence, JSON and complete SSE responses, signature retrieval, and exact-byte receipt verification |
| All three | An altered response is rejected using the real receipt, without sending another request |
| JavaScript | Node `InferenceClient` with unencrypted Chat, Ed25519 E2EE, ECDSA E2EE, and OHTTP + E2EE |
| JavaScript | External OpenAI SDK using `InferenceClient.fetch`, generic package entry, and standalone verification functions |
| Python and Rust | Standalone verification with both Ed25519 and ECDSA |

The JavaScript tests import the built package entry points. Its generic entry
is exercised in Node; this is not a browser or CORS test. This suite targets
Gateway APIs, not experimental direct endpoints. Verification uses the SDK's
default TCB policy and real Intel/NVIDIA verifiers, not mocks or an application
deployment allowlist.

A complete run sends 22 small Chat requests, each capped at 128 completion
tokens. JavaScript disables OpenAI request retries. Test failures and timeouts
fail CI; they are not converted into skipped or successful tests.

## Local use

Provide the same environment variables through your local secret manager or
shell. Do not commit a key or paste it into a command that saves shell history.
Run the relevant command from the repository root:

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
