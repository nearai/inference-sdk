# Go examples

Use Go 1.26.10+; the SDK embeds the DCAP verifier.
Set `NEARAI_API_KEY` and run from this directory. The
[shared example guide](../README.md) describes configuration, verification order,
image policies, and the matching JavaScript, Python, and Rust examples.

| Command | Demonstrates |
| --- | --- |
| `go run ./gateway/client` | Native Chat JSON/SSE, E2EE, Gateway/model image provenance, and receipts |
| `go run ./gateway/bare` | Standalone Gateway/model verification, pinned TLS, E2EE, and exact ciphertext receipts |
| `go run ./gateway/openai` | Official OpenAI Chat JSON/SSE through the verified transport, with E2EE |
| `go run ./gateway/responses-client` | Native Responses JSON/SSE and Gateway receipts |
| `go run ./gateway/responses` | Official OpenAI Responses JSON/SSE and Gateway receipts |
| `go run ./gateway/systemone` | Billing, team, and urgency decisions with verified receipts |
| `go run ./direct/client` | Experimental native direct Chat with E2EE and receipts |
| `go run ./direct/bare` | Experimental standalone direct verification over plaintext HTTPS |
| `go run ./direct/openai` | Experimental official OpenAI direct Chat with E2EE and receipts |

`go run .` remains an alias for `gateway/openai`. `NEARAI_BASE_URL`,
`NEARAI_MODEL`, `NEARAI_SIGNING_ALGO`, and `NEARAI_OHTTP` select the endpoint,
model, signature algorithm, and optional OHTTP. Set `NEARAI_MODEL` for System One;
`NEARAI_EXPECT_SIGNATURE_KIND` defaults to `gateway`, with `provider_tee` available
for verified self-hosted decision models.

JSON answers are printed after receipt verification. SSE text is printed as it
arrives; the example consumes through EOF and verifies the receipt afterward.
Verification failures exit with an error. Official clients reuse
`inference.HTTPClient()` and disable automatic inference retries. Responses keep
field-level E2EE disabled; OHTTP requires Ed25519.

Native and standalone Gateway Chat apply both Gateway and Compose Manager model
image policies. Add commit pins in `internal/demo.GatewayImages` and
`internal/demo.ModelImages` for stricter admission. `GITHUB_TOKEN` may be used
for GitHub provenance requests. See the shared guide for
[direct endpoint verification](../README.md#direct-endpoints).

```sh
go vet ./...
go test -race ./...
go test -tags=e2e -run '^TestLive' -v .
```

The last command requires the shared [live configuration](../../e2e/README.md).
Offline tests exercise official SDK parsing against signed Chat and Responses
fixtures. The module uses a local SDK replacement; use a released module
version when copying it outside this repository.
