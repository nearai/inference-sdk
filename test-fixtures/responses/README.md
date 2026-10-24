# Responses transport fixtures

`response.json` and `response.sse` exercise text, function calls, opaque reasoning,
Unicode, mixed SSE line endings, and signed trailing bytes. SDK tests sign and
verify these exact bytes. The Rust and Go copies in `rs/test-fixtures/responses`
and `go/testdata/responses` keep their published packages self-contained; update
all copies together.
