# Python SDK API reference

This page describes the public APIs exported by `nearai_inference_sdk`. For
workflows and complete examples, see the [verification guide](./verification-guide.md).

## Recommended lifecycle

Most applications use the public APIs in three stages:

1. Before a completion, fetch and verify both Gateway and target-model
   deployment evidence.
2. Send the completion outside this SDK, retaining its completion ID and exact
   request and response bytes.
3. Fetch the completion signature and dispatch on `signature.kind` to verify
   the exact bytes with the preverified model or Gateway evidence.

The signature kind selects a response verifier; it does not select or replace
the deployment checks. See the guide for the evidence boundary of this current
one-signature design.

## Public API

Gateway retrieval and attestation verification are asynchronous. Response
verification is synchronous.

| API | Signature | Returns | Purpose |
| --- | --- | --- | --- |
| `AttestationClient` | `(api_key, *, base_url=...)` | client | Owns NEAR AI Cloud credentials and retrieves deployment evidence and completion signatures. |
| `client.fetch_completion_signature` | `(completion_id, *, signing_algo=None)` | `CompletionSignature` | Fetches one completion signature after a completion. |
| `client.fetch_model_attestations` | `(model, *, signing_algo=None, signing_address=None)` | `FetchedModelAttestations` | Fetches target-model deployment evidence; optional signer fields narrow the API response. |
| `client.fetch_gateway_attestation` | `(*, signing_algo=None, include_spki_fingerprint=True)` | `FetchedGatewayAttestation` | Fetches Gateway deployment evidence, optionally including its TLS fingerprint. |
| `find_model_attestation_for_signature` | `(attestations, signature)` | `VerifiedModelAttestation` | Locally selects the sole preverified model deployment for a `provider_tee` signer. |
| `verify_model_attestation` | `(attestation, client_binding, *, policy=None, verifiers=None)` | `VerifiedModelAttestation` | Verifies target-model deployment evidence. |
| `verify_gateway_attestation` | `(attestation, client_binding, *, policy=None, verifiers=None)` | `VerifiedGatewayAttestation` | Verifies Gateway deployment evidence using the layout in the attestation. |
| `verify_model_response` | `(request_body, response_body, signature, attestation)` | `None` | Verifies a `provider_tee` signature using preverified model evidence. |
| `verify_gateway_response` | `(request_body, response_body, signature, attestation)` | `None` | Verifies a `gateway` signature using preverified Gateway evidence. |
| `fetch_image_provenance` | `(repository, digest, github_token=None)` | `list[str]` | Retrieves all inline GitHub Sigstore bundles for an image digest. |
| `verify_image_provenance` | `(bundles, digest, policy)` | `VerifiedImageProvenance` | Verifies an image digest against a caller-selected GitHub build identity. |
| `verify_deployment_image_provenance` | `(app_compose, image_policies, github_token=None)` | `None` | Verifies configured, digest-pinned service images from measured app-compose JSON. |

## AttestationClient

The client does not send completion requests or retain completion bytes. It
creates a fresh nonce for every attestation fetch.

For one three-stage verification operation, pass the same explicit
`signing_algo` to both attestation fetches and `fetch_completion_signature`.
The Gateway's report and signature endpoints have different defaults.

### Constructor

| Field | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `api_key` | `str` | Yes | — | Bearer token for signature and evidence requests. |
| `base_url` | `str` | No | `https://cloud-api.near.ai/v1` | Absolute HTTP(S) NEAR AI Cloud Gateway base URL. |

`AttestationClient` construction and methods, plus
`find_model_attestation_for_signature`, raise `ApiError` for invalid helper
input as well as Gateway and selection failures. The `verify_*` functions
raise `VerificationError` instead. Handle each operation at its own boundary;
the client and selection helpers never require an `ApiError` versus
`VerificationError` dispatch after catching an error.

### Completion-signature methods

| API | Parameter | Type | Required | Description |
| --- | --- | --- | --- | --- |
| `fetch_completion_signature` | `completion_id` | `str` | Yes | Completion ID returned by the API response. Fetch after the completion reaches a terminal state. |
|  | `signing_algo` | `SigningAlgo \| None` | No | Signing algorithm to request. Set it when the application requires a particular algorithm; omit it for the service default. |

`client.fetch_completion_signature()` raises `ApiError` when the Gateway returns
an unavailable 2xx response. The error code is
`api.completion_signature_unavailable`; its details contain
`providerErrorCode` and `providerMessage` from the service response.

### Target-model deployment methods

| API | Parameter | Type | Required | Description |
| --- | --- | --- | --- | --- |
| `fetch_model_attestations` | `model` | `str` | Yes | Canonical target model ID. Use before sending its completion. |
|  | `signing_algo` | `SigningAlgo \| None` | No | Optional API request filter for the required signing algorithm. |
|  | `signing_address` | `str \| None` | No | Optional API request filter for the advertised signing address. It must be hexadecimal: 20 or 32 bytes without `signing_algo`, or the matching length when an algorithm is selected. Invalid input raises `ApiError` before a request. |

Every model-attestation fetch generates a fresh 32-byte client nonce, requests
`include_tls_fingerprint=false`, checks the Gateway's echoed nonce, and returns a
`ModelClientBinding` with the raw evidence. `signing_algo` and
`signing_address` only narrow the remote response. The result preserves every
model attestation the Gateway returns, including an empty collection. Verify each
returned item before inference. Use `find_model_attestation_for_signature`
after a `provider_tee` signature is available to select exactly one matching
verified result for response verification.

### Local model selection

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

### Attestation verification

| Function | Parameter | Type | Required | Description |
| --- | --- | --- | --- | --- |
| `verify_model_attestation` | `attestation` | `ModelAttestation` | Yes | Raw model evidence. |
|  | `client_binding` | `ModelClientBinding` | Yes | Client binding returned by the matching model-evidence fetch. |
|  | `policy` | `ModelAttestationPolicy \| None` | No | TCB and GPU-evidence requirements. |
|  | `verifiers` | `ModelAttestationVerifiers \| None` | No | Quote, deployment, and NVIDIA verifier overrides. |
| `verify_gateway_attestation` | `attestation` | `GatewayAttestation` | Yes | Raw Gateway evidence. |
|  | `client_binding` | `GatewayClientBinding` | Yes | Client values returned with the matching Gateway-evidence fetch. |
|  | `policy` | `AttestationPolicy \| None` | No | Accepted Gateway TCB statuses. |
|  | `verifiers` | `AttestationVerifiers \| None` | No | Quote and deployment verifier overrides. |

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

Dispatch only after fetching the completion signature: pass a `provider_tee` signature to
`verify_model_response` with the model deployment result, and a `gateway`
signature to `verify_gateway_response` with the Gateway deployment result.
Each function verifies exact bytes and requires its signature signer to match
the supplied verified result.

The two deployment results and a single completion signature do not currently
prove a complete model-to-Gateway-to-final-bytes chain. A `provider_tee`
signature does not identify the Gateway that returned the bytes; a `gateway`
signature does not prove that an attested model generated them. [cloud-api#986](https://github.com/nearai/cloud-api/issues/986) tracks the missing
provider-signature and Gateway-receipt chain.

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

Selection errors raise `VerificationError` with code
`provenance.deployment_images_invalid` and a `reason` of `empty_policy`,
`invalid_app_compose`, `invalid_docker_compose`, `unresolved_image`, `image_missing`,
or `image_not_pinned`; `imageRepository` and `service` identify the selection when
applicable. GitHub request errors are wrapped as `provenance.image_request_failed`
with `imageRepository`, `digest`, the original cause, and unchanged retryability.
Image verification errors pass through unchanged.

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
| `repository` | `str` | required | Expected GitHub `owner/repo`. |
| `workflow` | `str` | required | Expected workflow path, such as `.github/workflows/build.yml`. |
| `ref` | `str \| None` | `None` | Optional exact source ref, such as `refs/heads/main`. |
| `commit` | `str \| None` | `None` | Optional approved source commit SHA. |
| `issuer` | `str` | `https://token.actions.githubusercontent.com` | Expected certificate OIDC issuer. |

| Result field | Type | Description |
| --- | --- | --- |
| `digest` | `str` | Verified image digest. |
| `repository` | `str` | Verified GitHub repository. |
| `workflow` | `str` | Verified build workflow path. |
| `ref` | `str` | Verified build ref. |
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
| `GatewayAttestation` | `spki_fingerprint` | `str \| None` | TLS fingerprint returned when the fetch requested it. Its presence selects TLS-bound Gateway verification. |
|  | `reported_quote_data` | `str` | Gateway report-data copy required by Gateway verification. |

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
| `AttestationVerifiers` | `quote` | built in | Optional replacement for the Intel DCAP quote verifier. |
|  | `deployment` | absent | Optional deployment-acceptance verifier. |
| `ModelAttestationVerifiers` | `quote`, `deployment`, `nvidia` | built in / absent / built in | Optional quote, deployment, and NVIDIA verifier overrides. |
| `QuoteVerifier` | `(quote: str) -> QuoteVerificationResult \| Awaitable[QuoteVerificationResult]` | — | Authenticates a quote and returns verified fields. |
| `DeploymentVerifier` | `(deployment: MeasuredDeployment) -> None \| Awaitable[None]` | — | Returns only for an accepted deployment. |
| `NvidiaEvidenceVerifier` | `(payload: str) -> None \| Awaitable[None]` | — | Returns only for accepted GPU evidence. |

The default NVIDIA verifier verifies NRAS's overall JWT signature, issuer,
timestamps, signed nonce, and boolean verdict.

| Type | Field | Type | Description |
| --- | --- | --- | --- |
| `QuoteVerificationResult` | `tcb_status` | `TcbStatus` | Authenticated quote TCB status. |
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
| `VerifiedGatewayAttestation` | `tls_binding` | `GatewayTlsBinding` | `attested` when the attestation fingerprint matches the observed peer; `none` when the attestation has no fingerprint. |

`GatewayTlsBinding` is either `GatewayTlsBinding(kind='none')` or
`GatewayTlsBinding(kind='attested', spki_fingerprint=...)`.
