# Python API reference

Parameters, defaults, and return values for the public clients and verification
functions. For working examples, see the [guide](./verification-guide.md).

- [Inference client](#inferenceclient)
- [Attestation client](#attestationclient)
- [Attestation and response verification](#verification-functions)
- [Model attestation selection](#local-model-selection)
- [E2EE and TLS pinning](#standalone-e2ee-and-pinned-tls), and [OHTTP](#ohttp-helpers)
- [Image build provenance](#image-build-provenance)
- [Evidence types, policies, and results](#evidence-signatures-policies-and-results)
- [Verification service URLs](#built-in-verifier-factories)
- [Direct endpoints](#direct-clients-and-verification) (experimental)

Network operations and attestation verification are asynchronous.
Standalone response-signature verification is synchronous.

## InferenceClient

Use as an asynchronous context manager in an `asyncio` event loop, or call
`await client.aclose()` when finished. Chat Completions are supported. `chat.completions.create` does not
automatically verify the response signature; use `verify_response` afterwards.

### Constructor

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `api_key` | `str \| None` | `None` | Gateway bearer credential; custom authentication may use `headers`. |
| `base_url` | `str` | `https://cloud-api.near.ai/v1` | Gateway or compatible aggregator HTTP(S) base URL, without a query or fragment. |
| `headers` | `Mapping[str, str] \| None` | `None` | Configured headers for evidence, Chat, and signature requests. An explicit `api_key` determines their bearer authorization. Per-request or external OpenAI authorization does not override this configuration. |
| `signing_algo` | `SigningAlgo` | `'ed25519'` | Algorithm for attestation, E2EE, model routing, and response signatures. With OHTTP enabled, only `'ed25519'` is accepted. |
| `e2ee` | `bool` | `False` | Encrypt supported Chat fields to a verified model key. Requires model attestation. |
| `ohttp` | `bool` | `False` | Encapsulate Chat requests and responses through `/ohttp` using authenticated Gateway key configuration. Independent of field-level E2EE. |
| `attestation_cache_time_to_live_ms` | `float` | `3600000` | Reuse successful verification per model for this long; `0` verifies each request. |
| `response_cache_time_to_live_ms` | `float` | `3600000` | Retain wire bytes for this long after the response finishes. |
| `gateway_verification` | `GatewayVerificationOptions \| None` | `None` | Gateway evidence, TLS, policy, and verifier configuration. |
| `model_verification` | `ModelVerificationOptions \| None` | `None` | Model policy and verifier configuration. |
| `deployment_policy` | `DeploymentPolicy \| None` | `None` | Optional callback `(model, deployment)` that rejects unapproved model deployments by raising. May be asynchronous. |

For model support and response-signature guarantees, see
[what verification proves](./verification-guide.md#what-verification-proves).

### Methods

| Method | Returns when awaited | Description |
| --- | --- | --- |
| `chat.completions.create(...)` | OpenAI completion or async stream | Chat Completions parameters. Verifies deployments before sending, then decrypts if E2EE is enabled. |
| `send(request: httpx.Request)` | `httpx.Response` | The same verified Chat path with an application-owned HTTP request. |
| `verify(model: str)` | `None` | Verifies deployments without Chat. Shares Chat's cache and in-flight work. |
| `verify_response(id: str)` | `VerifiedCompletionResult` | Verifies the signature using retained bytes and evidence. Unknown or expired IDs raise `api.completion_not_found`. |
| `aclose()` | `None` | Closes owned HTTP connections and clears retained records. Called by the async context manager. |

Consume the full response or stream before calling `verify_response`.
Records remain until their TTL expires, including after verification.

### Verification options

| Type | Field | Default | Description |
| --- | --- | --- | --- |
| `GatewayVerificationOptions` | `include_spki_fingerprint: bool` | `True` | Pin to the observed TLS peer during evidence retrieval, then authenticate it against the Gateway quote before inference. |
| | `policy: AttestationPolicy \| None` | `None` | Gateway TCB policy. |
| | `verifiers: AttestationVerifiers \| None` | `None` | Gateway quote and deployment callbacks. |
| `ModelVerificationOptions` | `policy: ModelAttestationPolicy \| None` | `None` | Model TCB and GPU policy. |
| | `verifiers: ModelAttestationVerifiers \| None` | `None` | Model quote, GPU, and deployment callbacks. |

### HTTP integration and response results

`http_client` returns a new, non-owning `httpx.AsyncClient` adapter accepted by
`openai.AsyncOpenAI`. It shares the built-in Chat interface's verification,
encryption, cache, and response-byte capture. Closing an adapter does not close
the owning client or discard its response records. Keep the owner open until
response verification finishes.

| `VerifiedCompletionResult` field | Type | Description |
| --- | --- | --- |
| `id` | `str` | Completion ID supplied to `verify_response`. |
| `signature_kind` | `Literal['provider_tee', 'gateway']` | Trust boundary of the verified signature. |
| `signature` | `CompletionSignature` | Retrieved signature and signer identity. |
| `attestation` | `VerifiedModelAttestation \| VerifiedGatewayAttestation` | Verified evidence matching the signature kind. |

## AttestationClient

The client does not send completion requests or retain completion bytes. It
creates a fresh nonce for every attestation fetch.

`fetch_model_metadata(model)` requests the URL-encoded model ID and returns
`ModelMetadata(provider_type: str, attestation_supported: bool)`, mapped from the
Gateway's `metadata.providerType` and `metadata.attestationSupported` fields.

Use the same explicit
`signing_algo` for attestation and signature fetches in one flow.
The Gateway's report and signature endpoints have different defaults.

### Constructor

| Field | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `api_key` | `str \| None` | No | `None` | Bearer token for signature and evidence requests. |
| `base_url` | `str` | No | `https://cloud-api.near.ai/v1` | Absolute HTTP(S) Gateway base URL, without a query or fragment. |
| `headers` | `Mapping[str, str] \| None` | No | `None` | Additional request headers, including aggregator authentication. |

### Methods

Optional arguments after `*` are keyword-only. All methods are asynchronous.

| Method | Signature | Result |
| --- | --- | --- |
| `fetch_model_metadata` | `(model)` | `ModelMetadata` |
| `fetch_gateway_attestation` | `(*, signing_algo=None, include_spki_fingerprint=True)` | `FetchedGatewayAttestation` |
| `fetch_model_attestations` | `(model, *, signing_algo=None, signing_address=None)` | `FetchedModelAttestations` |
| `fetch_completion_signature` | `(completion_id, *, signing_algo=None)` | `CompletionSignature` |

### Completion-signature methods

| API | Parameter | Type | Required | Description |
| --- | --- | --- | --- | --- |
| `fetch_completion_signature` | `completion_id` | `str` | Yes | Completion ID returned by the API response. Fetch after the completion reaches a terminal state. |
|  | `signing_algo` | `SigningAlgo \| None` | No | Signing algorithm to request. Set it when the application requires a particular algorithm; omit it for the service default. |

Unavailable signatures raise `ApiError`. See [error handling](./verification-guide.md#handle-errors).

### Target-model deployment methods

| API | Parameter | Type | Required | Description |
| --- | --- | --- | --- | --- |
| `fetch_model_attestations` | `model` | `str` | Yes | Canonical target model ID. Use before sending its completion. |
|  | `signing_algo` | `SigningAlgo \| None` | No | Optional API request filter for the required signing algorithm. |
|  | `signing_address` | `str \| None` | No | Optional API request filter for the advertised signing address. It must be hexadecimal: 20 or 32 bytes without `signing_algo`, or the matching length when an algorithm is selected. Invalid input raises `ApiError` before a request. |

Model fetches request no TLS fingerprint and check the echoed nonce. The result
preserves every returned model report, including an empty collection.

### Local model selection

`find_model_attestation_for_signature(attestations, signature)` synchronously
returns the sole `VerifiedModelAttestation` matching a `provider_tee` signer.
Zero or multiple matches raise `ApiError`. It does not verify evidence.

| Function | Parameter | Type | Required | Description |
| --- | --- | --- | --- | --- |
| `find_model_attestation_for_signature` | `attestations` | `tuple[VerifiedModelAttestation, ...] \| list[VerifiedModelAttestation]` | Yes | Results returned by verifying every item from `client.fetch_model_attestations()`. Exactly one item must match the signer. |
|  | `signature` | `CompletionSignatureReference` | Yes | A `provider_tee` signature whose signer selects the result. |

| Result type | Field | Type | Description |
| --- | --- | --- | --- |
| `FetchedModelAttestations` | `attestations` | `tuple[ModelAttestation, ...]` | Every model attestation returned by the Gateway. It may be empty or contain multiple items. |
|  | `client_binding` | `ModelClientBinding` | Client nonce associated with this evidence request. |

### Gateway deployment method

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `signing_algo` | `SigningAlgo \| None` | No | Gateway signing algorithm required by the deployment check. In a deployment-first flow, set it before the completion. |
| `include_spki_fingerprint` | `bool` | No | `True` by default. Requests the Gateway TLS fingerprint and captures the peer fingerprint from this HTTPS request. |

`client.fetch_gateway_attestation()` checks its echoed nonce. With the default
`include_spki_fingerprint=True`, it requires the returned attestation to
contain a TLS fingerprint and captures the SHA-256 SPKI fingerprint from the
TLS connection for that exact HTTPS request. With `False`, it requires the
attestation to omit the fingerprint and does not capture a peer fingerprint.
TLS binding requires an HTTPS endpoint; use `False` for an HTTP custom endpoint.

| `FetchedGatewayAttestation` field | Type | Description |
| --- | --- | --- |
| `attestation` | `GatewayAttestation` | Returned Gateway evidence. |
| `client_binding` | `GatewayClientBinding` | Client values associated with this evidence request. |

| Client-binding field | Type | Description |
| --- | --- | --- |
| `ModelClientBinding.nonce` | `str` | Client nonce generated and sent by the matching model-evidence fetch. |
| `GatewayClientBinding.nonce` | `str` | Client nonce generated and sent by the matching Gateway-evidence fetch. |
| `GatewayClientBinding.spki_fingerprint` | `str \| None` | SHA-256 SPKI fingerprint observed for that exact Gateway-evidence HTTPS request when the fetch included it and the runtime exposes it. |

## Verification functions

| Function | Parameters | Returns |
| --- | --- | --- |
| `verify_gateway_attestation` | `(attestation, client_binding, *, policy=None, verifiers=None)` | Awaitable `VerifiedGatewayAttestation` |
| `verify_model_attestation` | `(attestation, client_binding, *, policy=None, verifiers=None)` | Awaitable `VerifiedModelAttestation` |
| `verify_gateway_response` | `(request_body, response_body, signature, attestation)` | `None` |
| `verify_model_response` | `(request_body, response_body, signature, attestation)` | `None` |

### Attestation verification

| Function | Parameter | Type | Required | Description |
| --- | --- | --- | --- | --- |
| `verify_model_attestation` | `attestation` | `ModelAttestation` | Yes | Raw model evidence. |
|  | `client_binding` | `ModelClientBinding` | Yes | Client binding returned by the matching model-evidence fetch. |
|  | `policy` | `ModelAttestationPolicy \| None` | No | TCB and GPU-evidence requirements. |
|  | `verifiers` | `ModelAttestationVerifiers \| None` | No | TDX quote, deployment, and GPU evidence verifier overrides. |
| `verify_gateway_attestation` | `attestation` | `GatewayAttestation` | Yes | Raw Gateway evidence. |
|  | `client_binding` | `GatewayClientBinding` | Yes | Client values returned with the matching Gateway-evidence fetch. |
|  | `policy` | `AttestationPolicy \| None` | No | Accepted Gateway TCB statuses. |
|  | `verifiers` | `AttestationVerifiers \| None` | No | TDX quote and deployment verifier overrides. |

`client_binding.nonce` must come from the matching fetch result. Model evidence
always verifies the signer-and-nonce report-data layout and has no TLS-binding
result. A Gateway attestation with an SPKI fingerprint verifies the
signer-and-fingerprint-and-nonce report-data layout and requires the TLS peer
from `client_binding` to match. Without an SPKI fingerprint, Gateway
verification checks signer-and-nonce report data and returns
`GatewayTlsBinding(kind='none')`.

### Completion-signature verification

| Function | Parameter | Type | Required | Description |
| --- | --- | --- | --- | --- |
| `verify_model_response` | `request_body` | `bytes` | Yes | Exact bytes sent to the completion endpoint. |
|  | `response_body` | `bytes` | Yes | Exact bytes received from the completion endpoint. |
|  | `signature` | `CompletionSignature` | Yes | Signature with `kind='provider_tee'`. |
|  | `attestation` | `VerifiedModelAttestation` | Yes | Verified model evidence whose signer must match the signature. |
| `verify_gateway_response` | `request_body` | `bytes` | Yes | Exact bytes sent to the completion endpoint. |
|  | `response_body` | `bytes` | Yes | Exact bytes received from the completion endpoint. |
|  | `signature` | `CompletionSignature` | Yes | Signature with `kind='gateway'`. |
|  | `attestation` | `VerifiedGatewayAttestation` | Yes | Verified Gateway evidence whose signer must match the signature. |

Response verification compares exact bytes and requires the signature's signer
to match the supplied verified result. See [signature guarantees](./verification-guide.md#what-verification-proves).

## Standalone E2EE and pinned TLS

`await prepare_e2ee_chat_request(request, model_key)` returns a
`PreparedE2eeChatRequest` without sending it.

| `prepare_e2ee_chat_request` parameter | Type | Description |
| --- | --- | --- |
| `request` | `httpx.Request` | JSON Chat Completions request; the helper does not send it. |
| `model_key` | `E2eeModelKey` | Public key extracted from verified model evidence. |

| Type | Field | Type | Description |
| --- | --- | --- | --- |
| `E2eeModelKey` | `signing_algo` | `SigningAlgo` | Selects Ed25519-v2 or legacy ECDSA encryption. |
| | `public_key` | `str` | Hexadecimal model encryption public key, not an ECDSA address. |
| `PreparedE2eeChatRequest` | `request` | `httpx.Request` | Encrypted request with model-routing and encryption headers. |
| | `decrypt_response` | asynchronous `(httpx.Response) -> httpx.Response` | Decrypts JSON or streaming SSE using this request's response key. |

The E2EE helper does not verify attestations or response signatures. Retain the
encrypted request and response bytes for standalone response verification.

`create_pinned_tls_client(spki_fingerprint: str | Sequence[str])` accepts a SHA-256
SPKI fingerprint or a nonempty set of allowed fingerprints obtained from verified
evidence. Close the returned
HTTP client after use. Normal certificate-chain and hostname validation remain
enabled; a different SPKI is rejected before sending request headers or body.

## OHTTP helpers

| Function | Returns | Async |
| --- | --- | --- |
| `verify_ohttp_key_config(ohttp_attestation, signer)` | `bytes` | No |
| `create_ohttp_client(key_config, *, base_url, http_client=None, forwarded_headers=())` | `httpx.AsyncClient` | No |

`InferenceClient` performs these steps automatically when `ohttp=True`.
For a manual flow, verify Gateway evidence first, pass its signer and the
advertised configuration to `verify_ohttp_key_config`, then pass the returned
bytes to `create_ohttp_client`.

| Function | Parameter | Type | Description |
| --- | --- | --- | --- |
| `verify_ohttp_key_config` | `ohttp_attestation` | `OhttpAttestation` | Configuration advertised by the Gateway report. |
|  | `signer` | `SigningIdentity` | Previously verified Ed25519 Gateway identity. Must match the configuration's signing key. |
| `create_ohttp_client` | `key_config` | `bytes` | Authenticated raw configuration returned by `verify_ohttp_key_config`. |
|  | `base_url` | `str` | Endpoint whose origin serves `/ohttp`. Inner requests must use the same origin. |
|  | `http_client` | `httpx.AsyncClient \| None` | Outer transport. Pass a pinned client to preserve TLS binding. If omitted, creates and owns a normal HTTP client. |
|  | `forwarded_headers` | `Sequence[str]` | Additional inner header names to expose on the outer request. Authorization is forwarded automatically; content and encryption-protocol headers stay inner-only. |

| `OhttpAttestation` field | Type | Description |
| --- | --- | --- |
| `signing_algo` | `Literal['ed25519']` | Configuration signature algorithm. |
| `signing_key` | `str` | Hexadecimal Ed25519 signing public key. |
| `key_config` | `str` | Hexadecimal encoded OHTTP key configuration. |
| `signature` | `str` | Hexadecimal signature over the raw configuration bytes. |

Use the returned HTTP client as an asynchronous context manager or close it
with `aclose()`. A caller-supplied outer client remains open. This helper does
not fetch attestations, encrypt Chat fields, or retain response bytes for
signature verification.

## Image build provenance

### `verify_deployment_image_provenance`

Asynchronously returns `None` when every configured image repository is present
and every matching service image passes provenance verification. It parses
`app_compose` as JSON containing a `docker_compose_file` YAML string with a
`services` map. Missing or null service images are ignored.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `app_compose` | `str` | Yes | Measured app-compose JSON. |
| `image_policies` | `Mapping[str, ImageProvenancePolicy]` | Yes | Nonempty mapping from image repository to trusted GitHub build policy. |
| `github_token` | `str \| None` | No | Optional GitHub authentication token. |

Images must use `repository@sha256:<64 hex>` or
`repository:tag@sha256:<64 hex>`. A leading `docker.io/` is normalized in policy
keys and service images. All matching references must be pinned, even when a
different service uses a valid pin. Unrelated literal images are ignored;
references containing `$` are rejected without environment expansion. Selection
is validated before any fetch.

Raises `VerificationError` when image selection, retrieval, or verification
fails. Retrieval failures retain their original cause and retryability.

### `fetch_image_provenance`

Asynchronously returns `list[str]` of inline Sigstore bundle JSON from GitHub.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `repository` | `str` | Yes | GitHub repository in `owner/repo` form. |
| `digest` | `str` | Yes | Image digest in `sha256:<64 hex characters>` form. |
| `github_token` | `str \| None` | No | GitHub authentication token; defaults to no token. |

### `verify_image_provenance`

Asynchronously returns `VerifiedImageProvenance`. One bundle must satisfy every
signature, artifact, source and policy check. The helper supports GitHub SLSA v1
and v0.2 provenance and refreshes Sigstore's production trust root through TUF.
The statement's source commit must match the signing certificate's source digest
(or legacy GitHub workflow SHA when the source digest is absent), before applying
the optional commit pin.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `bundles` | `Sequence[str]` | Yes | Candidate Sigstore bundle JSON strings. |
| `digest` | `str` | Yes | Expected image digest, not a hash chosen from the bundle. |
| `policy` | `ImageProvenancePolicy` | Yes | Caller-owned build identity and optional source pin. |

| Policy field | Type | Default | Description |
| --- | --- | --- | --- |
| `repository` | `str` | required | Expected source GitHub `owner/repo`; also the repository used to fetch attestations. |
| `workflow` | `str` | required | Expected source workflow path, such as `.github/workflows/build.yml`. |
| `ref` | `str \| None` | `None` | Optional exact source ref, such as `refs/heads/main`. |
| `commit` | `str \| None` | `None` | Optional approved source commit SHA. |
| `issuer` | `str` | `https://token.actions.githubusercontent.com` | Expected certificate OIDC issuer. |
| `signer_identity` | `str \| None` | `None` | Exact signing-certificate URI for a reusable workflow, including its ref, tag, or commit suffix. Defaults to the source repository/workflow at the verified source ref. |

The certificate's source repository, ref, and commit must match the signed SLSA
source. Setting `signer_identity` changes only the accepted signer, not these
source checks.

| Result field | Type | Description |
| --- | --- | --- |
| `digest` | `str` | Verified image digest. |
| `repository` | `str` | Verified source GitHub repository. |
| `workflow` | `str` | Verified source workflow path. |
| `ref` | `str` | Verified source ref. |
| `commit` | `str` | Verified source commit SHA. |
| `certificate_identity` | `str` | Verified signing-certificate identity. |
| `issuer` | `str` | Accepted certificate OIDC issuer. |
| `predicate_type` | `str` | Verified SLSA predicate type. |

## Evidence, signatures, policies, and results

### Signatures and raw evidence

| Type | Field | Type | Description |
| --- | --- | --- | --- |
| `SigningIdentity` | `signing_algo` | `SigningAlgo` | `ecdsa` or `ed25519`. |
|  | `signing_address` | `str` | Hexadecimal signing identity: 20 bytes for ECDSA or 32 bytes for Ed25519. |
| `CompletionSignatureReference` | `kind` | `CompletionSignatureKind` | `provider_tee` or `gateway`. It selects the response verifier. Model-evidence selection accepts only `provider_tee`. |
|  | `signer` | `SigningIdentity` | Identity used to select evidence. |
| `CompletionSignature` | `kind`, `signer` | inherited | The `CompletionSignatureReference` fields that select its response verifier and signer. |
|  | `signed_text` | `str` | Text covered by the signature. |
|  | `signature` | `str` | Hexadecimal signature: 65 bytes for ECDSA or 64 bytes for Ed25519. |
| `AttestationEvidence` | `nonce` | `str` | Nonce echoed by the Gateway. The fetch helper compares it with its generated nonce. |
|  | `signer` | `SigningIdentity` | Advertised signing identity. |
|  | `intel_quote` | `str` | Intel TDX quote. |
|  | `event_log` | `AttestationEventLog` | Input used to replay RTMR3 measurements. |
|  | `app_compose` | `str` | Measured compose configuration text. |
| `ModelAttestation` | `reported_quote_data` | `str \| None` | Optional report-data copy cross-checked against the authenticated quote. |
|  | `nvidia_payload` | `str \| None` | Optional GPU evidence payload. |
|  | `signing_public_key` | `str \| None` | Reported hexadecimal public key, checked against the quote-bound signer during verification. |
| `GatewayAttestation` | `spki_fingerprint` | `str \| None` | TLS fingerprint returned when the fetch requested it. Its presence selects TLS-bound Gateway verification. |
|  | `reported_quote_data` | `str` | Gateway report-data copy required by Gateway verification. |
|  | `ohttp_attestation` | `OhttpAttestation \| None` | Signed OHTTP configuration from the report envelope. Authenticate it with `verify_ohttp_key_config` and the verified Gateway signer before use. |

`CompletionSignatureKind` is `Literal['provider_tee', 'gateway']` and
`SigningAlgo` is `Literal['ecdsa', 'ed25519']`. `AttestationEventLog` is
`str | list[object]`. `TcbStatus` is one of `UpToDate`, `SWHardeningNeeded`,
`ConfigurationNeeded`, `ConfigurationAndSWHardeningNeeded`, `OutOfDate`,
`OutOfDateConfigurationNeeded`, `Revoked`, or `Unknown`.

### Policies and verifier callbacks

| Type | Field or signature | Default | Description |
| --- | --- | --- | --- |
| `AttestationPolicy` | `accepted_tcb_statuses` | default accepted statuses | Optional accepted TCB statuses. The default accepts `UpToDate` and `OutOfDate`. |
| `ModelAttestationPolicy` | `accepted_tcb_statuses` | default accepted statuses | Inherited TCB policy. |
|  | `gpu_evidence` | `'if-present'` | Requires GPU evidence only when set to `'required'`. |
| `AttestationVerifiers` | `tdx_quote` | built in | Optional replacement for the Intel DCAP quote verifier. |
|  | `deployment` | absent | Optional deployment-acceptance verifier. |
| `ModelAttestationVerifiers` | `tdx_quote`, `deployment`, `gpu_evidence` | built in / absent / built in | Optional TDX quote, deployment, and GPU evidence verifier overrides. |
| `TdxQuoteVerifier` | `(quote: str) -> TdxQuoteVerificationResult \| Awaitable[TdxQuoteVerificationResult]` | — | Authenticates a quote and returns verified fields. |
| `DeploymentVerifier` | `(deployment: MeasuredDeployment) -> None \| Awaitable[None]` | — | Returns only for an accepted deployment. |
| `GpuEvidenceVerifier` | `(payload: str) -> None \| Awaitable[None]` | — | Returns only for accepted GPU evidence. |

The default NVIDIA verifier verifies NRAS's overall JWT signature, issuer,
timestamps, signed nonce, and boolean verdict.

### Built-in verifier factories

Both factories are synchronous and return asynchronous verifier callbacks for
the `verifiers.tdx_quote` and `verifiers.gpu_evidence` fields. Their optional
arguments are independent of `AttestationClient.base_url`.

| Factory | Argument | Default |
| --- | --- | --- |
| `create_tdx_quote_verifier` | `pccs_url: str` | `https://api.trustedservices.intel.com` |
| `create_gpu_evidence_verifier` | `nras_url: str` | `https://nras.attestation.nvidia.com/v3/attest/gpu` |
| | `jwks_url: str` | `https://nras.attestation.nvidia.com/.well-known/jwks.json` |

`pccs_url` is a base URL passed to `dcap-qvl`, which constructs the SGX and TDX collateral
paths. A proxy must preserve PCCS bodies and issuer-chain headers, and serve
`/sgx/certification/v4/rootcacrl` to avoid a direct root-CRL fallback. See the
[proxy configuration example](./verification-guide.md#configure-attestation-service-urls).

`nras_url` receives the evidence POST; `jwks_url` supplies the trusted signing
keys. Use only a trusted JWKS source: checking the fixed NVIDIA issuer does not
authenticate an arbitrary JWKS endpoint. The full signature, issuer, time,
nonce, and verdict checks remain enabled.

Model verification checks the payload nonce against the client nonce before
calling a NVIDIA verifier. The factory additionally requires a 32-byte
hexadecimal payload nonce and verifies that the signed JWT nonce matches it.
Direct callback users must bind the payload nonce to their own fresh request
nonce. Nonces accept an optional `0x`/`0X` prefix and compare as bytes.

### Verified quote and deployment measurements

| Type | Field | Type | Description |
| --- | --- | --- | --- |
| `TdxQuoteVerificationResult` | `tcb_status` | `TcbStatus` | Authenticated quote TCB status. |
|  | `advisory_ids` | `tuple[str, ...]` | Authenticated quote advisory IDs. |
|  | `debug_enabled` | `bool` | Whether the quote enables debug mode. |
|  | `report_data` | `bytes` | Authenticated quote report data. |
|  | `mr_config_id` | `bytes` | Authenticated quote MRCONFIGID. |
|  | `rt_mr3` | `bytes` | Authenticated quote RTMR3. |
| `MeasuredDeployment` | `app_compose` | `str` | Configuration text bound to MRCONFIGID. |
|  | `runtime_measurements` | `RuntimeMeasurements` | Measurements derived from the verified event log. |
| `RuntimeMeasurements` | `os_image_hash` | `str \| None` | Optional measured OS image hash. |
|  | `compose_hash` | `str \| None` | Optional measured compose hash. |

### Verified results

| Type | Field | Type | Description |
| --- | --- | --- | --- |
| `VerifiedAttestationEvidence` | `signer` | `SigningIdentity` | Verified signing identity. |
|  | `tcb_status` | `TcbStatus` | Accepted quote TCB status. |
|  | `advisory_ids` | `tuple[str, ...]` | Quote advisory IDs. |
|  | `deployment` | `MeasuredDeployment` | Verified deployment measurements. |
|  | `deployment_provenance` | `'not_checked' \| 'verified'` | Whether a supplied deployment verifier accepted the deployment. |
| `VerifiedModelAttestation` | `gpu_evidence` | `'not_provided' \| 'verified'` | GPU-evidence verification outcome. It has no TLS-binding field. |
|  | `signing_public_key` | `str \| None` | Model public key authenticated against the verified signer; usable with `E2eeModelKey`. |
| `VerifiedGatewayAttestation` | `tls_binding` | `GatewayTlsBinding` | `attested` when the attestation fingerprint matches the observed peer; `none` when the attestation has no fingerprint. |

`GatewayTlsBinding` is either `GatewayTlsBinding(kind='none')` or
`GatewayTlsBinding(kind='attested', spki_fingerprint=...)`.

## Direct clients and verification

Both direct clients are [experimental](./verification-guide.md#direct-model-endpoints)
and not recommended for production. `DirectInferenceClient` accepts the
same common options as `InferenceClient`, with the following differences:

| Parameter or member | Direct behavior |
| --- | --- |
| `base_url` | Required first argument: the model endpoint's API URL. |
| `api_key` | Optional keyword argument: a credential accepted by the endpoint. |
| `e2ee` | Defaults to `True`. |
| `gateway_verification` | Not available; there is no Gateway workflow. |
| `model_verification`, `deployment_policy` | Applied to every supplied direct model report. |
| `verify(model)` | Verifies every supplied direct report without sending Chat; shares Chat's cache. |
| `verify_response(id)` | Returns `VerifiedDirectCompletionResult`. |

`DirectAttestationClient(base_url, *, api_key=None, headers=None)` exposes:

| Method | Parameters | Result |
| --- | --- | --- |
| `fetch_model_attestations` | `signing_algo=None`, `signing_address=None` (keyword-only) | `FetchedDirectModelAttestations` |
| `fetch_completion_signature` | `completion_id`, keyword-only `signing_algo=None` | `CompletionSignature` with kind `provider_tee` |

Direct fetch requests no TLS fingerprint at present. Normal HTTPS certificate
validation remains enabled. The raw report's top-level serving evidence must
also occur in `all_attestations`, compared by content.

| Type | Field | Description |
| --- | --- | --- |
| `DirectModelAttestation` | Inherited `ModelAttestation` fields | Model quote, signer, nonce, deployment, GPU evidence, and optional public key. |
| | `model_name: str`, `instance_id: str \| None` | Endpoint metadata, not additional quote-authenticated claims. |
| | `spki_fingerprint: str \| None` | Reported TLS SPKI fingerprint. |
| `DirectClientBinding` | `nonce: str`, `spki_fingerprint: str \| None` | Fresh client nonce and optional observed TLS fingerprint. |
| `FetchedDirectModelAttestations` | `serving_attestation`, `attestations` | Top-level serving report and the full tuple of supplied direct reports. |
| | `client_binding`, `ohttp_attestation` | Client binding and optional signed OHTTP configuration. |
| `VerifiedDirectModelAttestation` | Inherited `VerifiedModelAttestation` fields | Independently verified deployment and signing key. |
| | `model_name`, `instance_id`, `spki_fingerprint` | Endpoint metadata and optional quote-authenticated fingerprint. |
| `VerifiedDirectModelAttestations` | `serving_attestation`, `attestations` | Verified serving entry and every verified supplied report. |
| | `tls_binding: DirectTlsBinding` | `none` or `attested`; only the serving report is compared with the observed peer. |
| | `spki_fingerprints: tuple[str, ...]` | Distinct fingerprints authenticated by the verified reports, in response order. |
| `VerifiedDirectCompletionResult` | `id`, `signature_kind`, `signature` | Completion ID and verified `provider_tee` signature. |
| | `attestations` | Tuple of verified reports sharing its signer; this does not identify one CVM. |

### Direct verification functions

| Function | Parameters | Returns |
| --- | --- | --- |
| `verify_direct_model_attestation` | `(attestation, client_binding, *, policy=None, verifiers=None)` | Awaitable `VerifiedDirectModelAttestation` |
| `verify_direct_model_attestations` | `(fetched_attestations, *, policy=None, verifiers=None)` | Awaitable `VerifiedDirectModelAttestations` |
| `verify_direct_model_response` | `(request_body, response_body, signature, attestations)` | `tuple[VerifiedDirectModelAttestation, ...]` |

The single-report verifier accepts a `ModelClientBinding`. The collection
verifier accepts `FetchedDirectModelAttestations` and checks every entry.
Both accept the same policy and verifier types as `verify_model_attestation`.
A TLS-bound serving report requires an observed peer fingerprint.

The response verifier accepts exact request and response bytes, a
`CompletionSignature`, and a sequence of verified direct model reports.
