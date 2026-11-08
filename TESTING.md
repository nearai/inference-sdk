# SDK tests

## Layout

| SDK | Test files | Shared setup |
| --- | --- | --- |
| JavaScript | `js/test/*.spec.ts` | Fixture modules in `js/test/` |
| Python | `py/tests/test_*.py` | `py/tests/support/` |
| Rust | `rs/tests/` and `rs/tests/inference/` | `rs/tests/support/` |
| Go | `go/*_test.go` | `go/attestation_fixtures_test.go` and `go/inference_fixtures_test.go` |

## Validation

From the language directory, run `pnpm check` for JavaScript or `make check`
for Python, Rust and Go. To test against a deployed Gateway, follow the
[live E2E guide](e2e/README.md).
