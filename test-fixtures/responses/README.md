# Responses transport fixtures

`response.json` and `response.sse` exercise text, function calls, opaque reasoning,
Unicode, mixed SSE line endings, and signed trailing bytes. All four SDK test
suites read these files directly and sign and verify these exact bytes.

`streams.json` is the canonical cross-language receipt contract. All four test
suites read it directly from this directory. It covers normal EOF, response IDs
versus output item IDs, conflicting/malformed IDs, explicit error records and
malformed JSON, including an undelimited tail. Invalid inputs must never produce
a verified receipt, fetch a signature or replay inference. The valid EOF case
does not require a successful completion event.
