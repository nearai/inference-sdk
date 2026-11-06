# Cross-language test contracts

For SDK contributors changing behavior shared by JavaScript, Python, Rust and Go.
Compare observable scenarios and assertions, not test counts. A parameterized
case, a loop inside one test, and an SDK adapter may produce different counts.

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

Share setup and wire fixtures, while keeping each API's request, response and
failure assertions visible in its own tests. Do not import tests from other test
modules or introduce a generic harness merely to make the languages look alike.

## Coverage map

The links below are entry points to each contract's tests, not a claim that one
file contains every related assertion. Keep endpoint-specific, cryptographic and
transport tests where they observe different boundaries.

| Contract | Required assertions | JavaScript | Python | Rust | Go |
| --- | --- | --- | --- | --- | --- |
| Evidence API | Fresh nonce per request and every report; schema/algorithm/address validation; bootstrap strips credentials; authenticated metadata/model/signature requests retain caller configuration. | [tests](js/test/cloud-api.spec.ts) | [tests](py/tests/test_cloud_api.py) | [tests](rs/tests/cloud_api.rs) | [tests](go/cloud_api_test.go) |
| TDX and policy | Reject nonce, signer/report-data, debug, TCB, app-compose and RTMR mismatches; explicit allowlists override defaults; rejected evidence cannot reach deployment policy. | [tests](js/test/model-attestation.spec.ts) | [tests](py/tests/test_model_attestation.py) | [tests](rs/tests/model_attestation.rs) | [tests](go/model_attestation_test.go) |
| GPU evidence | Require evidence when configured; authenticate JWT signature/key, issuer, time, nonce and verdict; propagate transient service failures. | [tests](js/test/model-attestation.spec.ts) | [tests](py/tests/test_model_attestation.py) | [tests](rs/src/nvidia.rs) | [tests](go/gpu_test.go) |
| Compose Manager | Bind signed actions and their canonical hash to the quote; authenticate runtime deployment; use the serving envelope for Direct manager evidence. | [tests](js/test/compose-manager-provenance.spec.ts) | [tests](py/tests/test_compose_manager_provenance.py) | [tests](rs/tests/compose_manager_provenance.rs) | [tests](go/compose_manager_test.go) |
| Image provenance | Verify real signed bundles and source identity/digest/commit; reject unpinned or unapproved images before fetching; bound pagination and downloaded evidence. | [tests](js/test/provenance.spec.ts) | [tests](py/tests/test_provenance.py) | [tests](rs/tests/image_provenance.rs) | [tests](go/provenance_test.go) |
| Response signatures | Ed25519/ECDSA and model/Gateway receipts: verify exact bytes; independently reject request, response, signature, signer and kind changes. | [tests](js/test/response-signature.spec.ts) | [tests](py/tests/test_response_signature.py) | [tests](rs/tests/response_signature.rs) | [tests](go/response_signature_test.go) |
| Signer collections | Preserve order, duplicates and nonadjacent matches; distinguish algorithms; reject zero matches; singular helpers retain their unique-match contract. | [tests](js/test/cloud-api.spec.ts) | [tests](py/tests/test_cloud_api.py) | [tests](rs/tests/cloud_api.rs) | [tests](go/cloud_api_test.go) |
| Gateway admission and routing | Verify every report before Chat, including secondary policy/evidence failures; skip reports without encryption keys; require the request-selected signer and return its entire verified group. | [tests](js/test/inference-client.spec.ts) | [tests](py/tests/test_inference_client.py) | [tests](rs/tests/inference_client.rs) | [tests](go/inference_client_test.go) |
| Direct clients | Preserve all verified reports and the actual serving report; bind OHTTP to the serving signer; return independent Direct results; reject unsupported Gateway APIs. | [tests](js/test/direct-inference-client.spec.ts) | [tests](py/tests/test_direct_inference_client.py) | [tests](rs/tests/inference/direct_inference_client.rs) | [tests](go/direct_inference_client_test.go) |
| TLS binding | Capture the bootstrap peer from the evidence connection; pin subsequent evidence/Chat/signature transport; wrong pin fails before HTTP writes, with no fallback. Normal certificate and hostname validation remain active. | [tests](js/test/node-pinned-tls-fetch.spec.ts) | [tests](py/tests/test_pinned_tls.py) | [tests](rs/src/pinned_tls.rs) | [tests](go/pinned_tls_test.go) |
| E2EE field contract | Both algorithms: encrypt/decrypt all supported content, reasoning, tools, audio and logprob fields; preserve unrelated fields and framing; use a fresh response key per request and reject cross-request decryption. | [tests](js/test/e2ee-request.spec.ts) | [tests](py/tests/test_e2ee_request.py) | [tests](rs/src/e2ee.rs) | [tests](go/e2ee_request_test.go) |
| OHTTP | Authenticate the key configuration before authenticated traffic; exercise real HPKE/BHTTP, final authentication, truncation and cancellation; never fall back to plaintext or replay inference. | [tests](js/test/ohttp-fetch.spec.ts) | [tests](py/tests/test_ohttp.py) | [tests](rs/src/ohttp.rs) | [tests](go/ohttp_test.go) |
| Chat JSON and SSE | Preserve signed wire bytes while exposing plaintext; check both algorithms, encrypted/plaintext requests and response formats; invalid or incompletely consumed streams cannot produce a verified receipt. | [tests](js/test/inference-client.spec.ts) | [tests](py/tests/test_inference_client.py) | [tests](rs/tests/inference_client.rs) | [tests](go/inference_client_test.go) |
| Responses | Consume the shared Responses stream corpus through public transports: consistent response IDs, ignored item IDs, malformed/error record rejection, unchanged wire bytes, no signature lookup for invalid streams, and no inference replay. | [tests](js/test/responses.spec.ts) | [tests](py/tests/test_responses.py) | [tests](rs/tests/inference/responses.rs) | [tests](go/responses_test.go) |
| Messages | Consume shared message fixtures; enforce message_start/message_stop lifecycle and message IDs, reject error/truncated/conflicting streams, and finish OHTTP authentication before exposing the terminal event. | [tests](js/test/messages.spec.ts) | [tests](py/tests/test_messages.py) | [tests](rs/tests/inference/messages.rs) | [tests](go/messages_test.go) |
| System One | Preserve structured values and exact receipt bytes, validate JSON/image/box responses, enforce selected keys and reject unsupported privacy modes before I/O. | [tests](js/test/systemone.spec.ts) | [tests](py/tests/test_systemone.py) | [tests](rs/tests/inference/systemone.rs) | [tests](go/systemone_test.go) |
| Cache snapshots and TTL | Responses retain their request’s evidence across session refresh; cache reuse retains verification time; zero TTL and cache clearing prevent stale receipt reuse. | [tests](js/test/inference-client.spec.ts) | [tests](py/tests/test_inference_client.py) | [tests](rs/tests/inference_client.rs) | [tests](go/inference_client_test.go) |
| Cancellation and ownership | Share concurrent verification; cancelling one waiter does not cancel another; close owned resources; release captured bytes after terminal verification, retain them for retryable signature failures; retry signature lookup without replaying inference. | [tests](js/test/inference-client-abort.spec.ts) | [tests](py/tests/test_inference_client.py) | [tests](rs/src/inference_core.rs) | [tests](go/inference_client_test.go) |

## Shared input, independent assertions

- [Responses streams](test-fixtures/responses/streams.json): one canonical corpus
  read directly by all four suites. Valid streams retain their exact signed bytes;
  invalid streams must not produce a verified receipt or trigger signature lookup.
  Normal EOF does not require `response.completed`: authenticating bytes is distinct
  from asserting that generation succeeded. Item IDs never become receipt IDs.
- [Messages streams](test-fixtures/messages/streams.json): protocol-specific lifecycle
  cases. Do not substitute the Responses EOF rules for Messages terminal rules.
- [Compose Manager evidence](test-fixtures/compose-manager/README.md) and
  [signed provenance bundles](test-fixtures/provenance/README.md): common evidence
  with independent verification. Cryptographic success tests use actual signatures;
  changing the verifier to always succeed must break the corresponding rejection tests.
- [Examples](examples/README.md): retain copyable inference → SDK verification →
  display flows, consistent receipt/report output, and incremental Unicode/SSE
  handling. Official adapters have their own integration tests where available.

## Test quality

Prefer strengthening an existing end-to-end contract over another happy-path
setup. Merge duplicates only when their assertions survive in the replacement;
keep descriptive parameter names so a failing scenario remains identifiable.
A negative test should assert the relevant failure boundary and observable effects
(such as no Chat, no signature request, no partial verified result, or resource
release), rather than only asserting that some exception occurred. Use exact
error codes within each SDK when the operation owns that error classification.

Do not duplicate language-specific machinery in other SDKs: JavaScript has Node
and browser-compatible entry points; Python has HTTPX/HTTPX2 adapters; Go has
native/WASM quote verification; Rust owns streams through drop. Stream errors may
surface during consumption or receipt verification. The shared requirement is that
invalid evidence cannot produce a verified receipt, and inference is not replayed.
JS's Node TLS fixture exercises the real pin validator with mocked native HTTPS;
Python, Rust and Go also run real local TLS servers. Local suites do not establish
browser deployment compatibility or production fleet cardinality.

## Validation

Run each SDK's maintained check command from its directory: JS `pnpm check`,
Python `make lint`, Rust `make check`, Go `make check`. Run affected examples and
E2E source/type checks as well. Python's default suite includes its example tests.
Live suites are separate and billable; see [live E2E instructions](e2e/README.md).
When reporting results, separate local assertions, fixture coverage and actual
production requests, and identify the commit that was tested.
