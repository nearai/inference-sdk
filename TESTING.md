# Cross-language test contracts

Use this guide to locate tests and maintain equivalent behavior across
JavaScript, Python, Rust and Go. Compare scenarios and assertions rather than counts.

## Layout

Locate tests by API or verification domain: `inference-client` / `inference_client`
for Gateway Chat and shared session behavior, `responses`, `messages`, `systemone`,
and `direct-inference-client` / `direct_inference_client` for their own contracts.
Attestation, response-signature, E2EE, OHTTP, TLS and provenance tests stay separate.
Within a file, keep local fixtures first, then group tests by the operation and
failure boundary they exercise. Use descriptive scenario names in test output.

- JavaScript: `js/test/*.spec.ts`; reusable fixture modules contain no test cases.
- Python: `py/tests/test_*.py`; reusable fixtures live in `py/tests/support/`.
- Rust: `rs/tests/inference_client.rs` loads the API modules under
  `rs/tests/inference/` and its shared fixture from `rs/tests/support/inference.rs`
  once. Tests of private internals remain beside their implementation.
- Go: domain-specific `go/*_test.go` files share `attestation_fixtures_test.go` and
  `inference_fixtures_test.go` in the same package, retaining private test access.

Share setup and wire fixtures; keep each API's request, response and failure
assertions in its own tests.

## Shared fixtures

All four suites read the common [Responses](test-fixtures/responses/streams.json),
[Messages](test-fixtures/messages/streams.json),
[Compose Manager](test-fixtures/compose-manager/README.md), and
[provenance](test-fixtures/provenance/README.md) fixtures from `test-fixtures/`.
Extend existing scenarios where possible, with assertions on results, error codes,
and whether requests were sent.

## Validation

Run each SDK's maintained check command from its directory: JS `pnpm check`,
Python `make check`, Rust `make check`, Go `make check`. These commands also check
live-test code without sending inference: JS typechecks it and tests its helpers,
Python collects it, and Rust/Go compile it. Run affected examples as well.
Python's default suite includes its example tests.
See [live E2E instructions](e2e/README.md) for tests that send inference requests.
