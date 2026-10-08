# Go API and verification notes

## Clients and lifecycle

`NewInferenceClient(InferenceOptions)` creates a Gateway client.
`NewDirectInferenceClient(DirectInferenceOptions)` requires an explicit base URL
and defaults E2EE to true; set `DisableE2EE: true` to opt out. Direct clients are
experimental: they do not verify a Gateway, and direct TLS attestation binding
is disabled, matching JavaScript/Python's current direct-endpoint limitation.
Normal HTTPS verification still applies.

Always close the client and each HTTP response body. `Close` cancels shared
verification work and active requests, clears retained data, and closes owned
idle connections. Caller-supplied HTTP clients/transports are borrowed.

`Verify(ctx, model)` performs deployment admission without sending Chat and
returns `AttestationVerificationResult`: Gateway evidence (nil for direct), all
model reports, and the original `VerifiedAt` timestamp. Cache hits preserve the
timestamp. Mutating returned evidence does not modify the internal cache.

`AttestationTTL` and `ResponseTTL` are optional `*time.Duration` values, defaulting
to one hour. A pointer to zero disables reuse/retention. Expired records are
unavailable immediately and cleaned up periodically. Simultaneous callers share
preflight and response-verification work. Cancelling one waiter leaves other
waiters intact; shared verification is limited to two minutes. Failed preflight
is not cached. Retryable signature retrieval failures can be attempted again
without replaying the completion.

`MaxBodyBytes` defaults to 64 MiB for each buffered Chat request/response. Streaming
is incremental, but signature verification requires retaining the wire body.
Select shorter retention and smaller limits for memory-constrained services.
Successful verification does not automatically discard its retained record.

## Verification guarantees

All returned model reports must verify, including instances sharing a signer.
By default, only `UpToDate` and `OutOfDate` TCB states are accepted. An explicitly
empty `AcceptedTCBStatuses` rejects all states. Debug-enabled quotes are rejected.
Quote report data binds the client nonce and signer, plus the Gateway's SPKI
fingerprint when requested. The SDK replays RTMR3 events and checks the hash of
the exact app-compose text against MRCONFIGID.

GPU evidence, when supplied, must carry the same nonce and an NVIDIA-signed
ES384 overall verdict with the expected issuer and valid timestamps. Set
`RequireGPUEvidence` to reject missing evidence. `QuoteVerifier`, `GPUVerifier`,
and `DeploymentVerifier` hooks are trusted application code: custom verifiers
must authenticate their inputs, not merely parse them.

Gateway pinning checks the observed peer during the TLS handshake before sending
Chat, model-evidence, or signature requests. It supports the default transport
or a caller's `*http.Transport` with normal TLS verification and no custom
`DialTLS`/`DialTLSContext`. `DisableTLSBinding: true` is an explicit opt-out for
application proxies; it no longer establishes the attested Gateway's TLS identity.
Requests do not follow redirects. The configured credentials take precedence over
credentials supplied by an external OpenAI client.

Model metadata uses the canonical request model ID with aliasing disabled. Models
without supported NEAR model attestation use Gateway-only verification. E2EE and
model deployment policies reject that flow before transmitting Chat.

## Response verification

`VerifyResponse(ctx, completionID)` verifies retained, exact request/response
bytes against evidence saved before transmission, including ciphertext under
E2EE. It distinguishes:

- `provider_tee`: a verified model signer signed the exact bytes and canonical
  model ID. This does not authenticate the Gateway's handling of them.
- `gateway`: a verified Gateway signer signed the exact client-visible bytes.
  This does not prove execution in a model TEE.

`VerifiedCompletionResult.Attestation` contains Gateway/routed-model evidence.
For direct endpoints, it is nil and `Attestations` includes every matching model
report: a shared signing key cannot identify an individual serving instance.
`VerifyDirectModelResponse` provides the same behavior for manual workflows.

Signatures and independently verified deployments do not establish a complete
cryptographic chain from model execution through Gateway rewriting.

Manual workflow APIs:

- `NewAttestationClient` / `NewDirectAttestationClient` retrieve metadata,
  Gateway/model reports, and completion signatures with fresh random nonces.
- `VerifyGatewayAttestation`, `VerifyModelAttestation`,
  `VerifyDirectModelAttestation`, and `VerifyDirectModelAttestations` authenticate
  those reports. The plural direct helper checks serving-report membership and
  binds its optional fingerprint to the supplied observed peer.
- `VerifyGatewayResponse`, `VerifyModelResponse`, `VerifyDirectModelResponse`
  verify exact bytes using already authenticated evidence.
- `FindModelAttestationForSignature` requires exactly one matching model report;
  it rejects missing and ambiguous matches.

## Encryption

E2EE uses Ed25519-to-X25519 / HKDF-SHA256 / XChaCha20-Poly1305 or the legacy
secp256k1 / HKDF-SHA256 / AES-GCM protocol. Each request gets a fresh response key.
The model key is bound to its quote-authenticated signer before use.

Protected request fields include message content (including serialized multimodal
content), reasoning, name, refusal, audio data, tool/function names and arguments,
tool descriptions/parameters, and selected function names. Protected response
fields include message/delta content, reasoning, refusal, audio data, tool/function
names and arguments, logprobs, and streaming tool-result output. Other fields,
including model IDs, roles and tool-call IDs, remain visible. The standalone
`PrepareE2EEChatRequest` consumes the supplied body and returns a new request plus
`DecryptJSON`/`DecryptSSE` helpers; it does not attest the supplied model key or
verify response signatures.

OHTTP protects the whole Chat HTTP exchange to the Gateway (or experimental
direct endpoint). Authorization and explicitly forwarded application headers are
visible to that endpoint; content and E2EE headers are inside the encrypted
exchange. It is independent of field E2EE and works with Gateway-only models.
`NewOHTTPTransport` requires an already authenticated key configuration.
OHTTP/BHTTP responses authenticate the final encrypted frame, including trailing
padding after SSE `[DONE]`; missing, truncated or corrupt frames fail.

## Deployment and image policies

`DeploymentPolicy(ctx, model, deployment)` runs after the model's configured
`DeploymentVerifier`. Verification alone does not approve a publisher, image,
measurement or release version. Supply policies for those decisions.

`VerifyDeploymentImageProvenance` selects digest-pinned images from measured
app-compose JSON's `docker_compose_file`. Every configured image repository must
occur, and every matching service must pin a digest. Unresolved image variables
and malformed Compose are rejected before fetching evidence.

`FetchImageProvenance` retrieves inline GitHub bundles, including pagination.
Pagination contributes only a cursor; supplied origins/paths and bundle URLs are
never followed. `ProvenanceOptions.GitHubToken` is separate from the Gateway key.
`VerifyImageProvenance` checks Sigstore signatures, certificate transparency,
transparency logs, the artifact digest, GitHub build identity, source ref/commit,
and SLSA provenance. `SignerIdentity` supports explicitly trusted reusable
workflows. `Commit` optionally pins reviewed source. The default Sigstore root
uses authenticated production TUF updates; `TrustedRoot` supports offline trusted
material. Trust-root refresh uses the upstream synchronous API; cancellation is
checked before and after it, not during its network operation.

## Errors and development

Use `errors.As(err, &sdkError)` for `*nearai.Error`. Branch on `Code`, inspect
`Details`, and use `errors.Is` for wrapped context cancellation. `Retryable`
indicates a failed external operation may succeed on another attempt; it never
authorizes automatic replay of inference. The SDK does not retry completions.

From `go/`, after setting `CGO_LDFLAGS`:

```sh
gofmt -w *.go internal/dcap/*.go
go vet ./...
go test -race -cover ./...
```

The test suite includes cross-language E2EE vectors, signed provenance fixtures,
native DCAP verification, admission and exact signatures, shared cancellation,
stream failures, TLS rejection, and chunked OHTTP authentication. It does not
make paid inference calls.
