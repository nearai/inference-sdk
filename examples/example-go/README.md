# Go examples

Build the pinned native DCAP library as described in [the Go SDK README](../../go/README.md)
and keep `CGO_LDFLAGS` set. Set `NEARAI_API_KEY` through your secret manager or shell.
`NEAR_AI_API_KEY` is also accepted for Open Code Review integrations.

Run from this directory:

| Command | Demonstrates |
| --- | --- |
| `go run .` | Official OpenAI Go SDK, JSON and streaming, E2EE, verified transport and receipts |
| `go run ./gateway/client` | Integrated Gateway preflight, E2EE, JSON/SSE, image provenance and receipts |
| `go run ./gateway/bare` | Standalone Gateway/model verification, pinned TLS, E2EE, ciphertext capture/decryption and receipts |
| `go run ./direct/client` | Experimental integrated direct inference, JSON/SSE, E2EE and receipts |
| `go run ./direct/bare` | Standalone direct report verification, E2EE, ciphertext capture/decryption and all matching receipt signers |

`NEARAI_BASE_URL` and `NEARAI_MODEL` override the Gateway/direct defaults.
`NEARAI_SIGNING_ALGO` accepts `ed25519` (default) or `ecdsa` and selects the same
algorithm for evidence, encryption, and receipt lookup. Use a NEAR TEE model for E2EE.
Run direct examples separately with the matching direct URL and model; direct
endpoints remain experimental and do not authenticate TLS with attestation.

The four examples each consume both JSON and SSE through HTTP EOF and verify
receipts before displaying plaintext. Standalone examples capture ciphertext
below decryption; they never verify a signature over reserialized plaintext.
Direct verification returns every report sharing the response signer, rather
than claiming a particular serving instance.

Gateway examples use the same four image provenance policies as JavaScript and
Python: `cloud-api`, `cvm-ingress`, `dstack-vpc`, and `dstack-vpc-client`. These
policies cover Gateway build artifacts, not model runtime images or weights.
Add commit pins in `internal/demo.GatewayImages` for stricter admission policy.
An optional `GITHUB_TOKEN` increases GitHub API rate limits for provenance lookup.

`go vet ./...` and `go test -race ./...` compile every example and exercise the
OpenAI transport with local signed fixtures. Live OpenAI JSON/SSE coverage is
opt-in: `go test -tags=e2e -run '^TestLiveOpenAI$' -v .`, with the shared live
configuration from [the E2E guide](../../e2e/README.md).
