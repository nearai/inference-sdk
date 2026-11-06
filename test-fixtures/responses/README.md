# Responses transport fixtures

`response.json` and `response.sse` exercise text, function calls, opaque reasoning,
Unicode, mixed SSE line endings, and signed trailing bytes. SDK tests sign and
verify these exact bytes. The Rust and Go copies in `rs/test-fixtures/responses`
and `go/testdata/responses` keep their published packages self-contained; update
all copies together.

The text `Original UTF-8: A é € 🌍` includes 1-, 2-, 3-, and 4-byte UTF-8
sequences. Function-call arguments include the same multibyte characters inside
an embedded JSON string. Tests split the wire bytes into small chunks to exercise
incremental decoding. Tampering replaces the equal-length marker `Original` with
`Tampered` to check signature verification without changing the response length.
