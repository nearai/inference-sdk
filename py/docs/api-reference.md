# Python SDK API reference

This page describes the public APIs exported by `verifiable_ai_sdk`. For
workflows and complete examples, see the [verification guide](./verification-guide.md).

## Public functions

The Cloud request and attestation-verification functions are asynchronous.
Response verification functions are synchronous.

| Function | Signature | Returns | Purpose |
| --- | --- | --- | --- |
| `fetch_completion_signature` | `(api_key, completion_id, *, signing_algo=None, base_url=...)` | `CompletionSignature` | Fetches one completion signature. Raises if Cloud API reports that no signature is available. |
| `lookup_completion_signature` | `(api_key, completion_id, *, signing_algo=None, base_url=...)` | `CompletionSignatureLookup` | Fetches one signature or a service-provided unavailable result. |
| `fetch_model_attestations` | `(api_key, model, *, signing_algo=None, signing_address=None, base_url=...)` | `FetchedModelAttestations` | Fetches model evidence for a canonical model, optionally filtered by signer. |
| `fetch_model_attestation_for_signature` | `(api_key, model, signature, *, base_url=...)` | `FetchedModelAttestation` | Fetches and selects model evidence for a `provider_tee` signer. |
| `find_model_attestation_for_signature` | `(attestations, signature)` | `ModelAttestation` | Selects the single model attestation for a `provider_tee` signer. It does not verify evidence. |
| `fetch_gateway_attestation` | `(api_key, *, signing_algo=None, base_url=...)` | `FetchedGatewayAttestation` | Fetches Gateway evidence, requests its TLS fingerprint, and captures the TLS peer for that HTTPS request. |
| `verify_model_attestation` | `(attestation, nonce, *, policy=None, verifiers=None)` | `VerifiedModelAttestation` | Verifies model attestation evidence. |
| `verify_gateway_attestation` | `(attestation, client_binding, *, policy=None, verifiers=None)` | `VerifiedGatewayAttestation` | Verifies Gateway evidence and its quote-bound TLS identity. By default, it requires the observed TLS peer binding. |
| `verify_model_response` | `(request_body, response_body, signature, attestation)` | `None` | Verifies exact bytes signed by a `provider_tee` signer. |
| `verify_gateway_response` | `(request_body, response_body, signature, attestation)` | `None` | Verifies exact bytes signed by a `gateway` signer. |

## Cloud request helpers

The request helpers do not send completion requests or retain completion bytes.
Python uses ordinary function parameters: `api_key` comes first, required
request fields follow, and optional fields are keyword-only.

### Shared Cloud parameters

| Field | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `api_key` | `str` | Yes | — | Bearer token for signature and evidence requests. |
| `base_url` | `str` | No | `https://cloud-api.near.ai/v1` | Cloud API base URL. |

The SDK owns the HTTP request for every helper. The native Gateway helper
captures the TLS peer SPKI fingerprint for its exact evidence request.

### Signature helpers

| Function | Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `lookup_completion_signature` and `fetch_completion_signature` | `api_key` | `str` | Yes | Bearer token for the Cloud API request. |
|  | `completion_id` | `str` | Yes | Non-empty completion ID. |
|  | `signing_algo` | `SigningAlgo \| None` | No | Signing algorithm to request. Omit it to use the service default. |

`lookup_completion_signature` returns `CompletionSignatureLookup`, whose
`status` is either `'found'` with `signature`, or `'unavailable'` with the
service's `unavailable` error. `fetch_completion_signature` is the strict
form: an unavailable 2xx response raises `ApiError` with
`api.completion_signature_unavailable`.

| `CompletionSignatureLookup` state | Available field | Type | Description |
| --- | --- | --- | --- |
| `status == 'found'` | `signature` | `CompletionSignature` | Signature returned by Cloud API. |
| `status == 'unavailable'` | `unavailable` | `SignatureUnavailable` | Service-provided `error_code` and `message` from a 2xx response. |

### Model-attestation helpers

| Function | Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `fetch_model_attestations` | `api_key` | `str` | Yes | Bearer token for the Cloud API request. |
|  | `model` | `str` | Yes | Non-empty canonical model ID. |
|  | `signing_algo` | `SigningAlgo \| None` | No | Optional signer filter. |
|  | `signing_address` | `str \| None` | No | Optional signer filter. Supply it when requesting evidence for a `provider_tee` response signature. |
| `fetch_model_attestation_for_signature` | `api_key` | `str` | Yes | Bearer token for the Cloud API request. |
|  | `model` | `str` | Yes | Non-empty canonical model ID. |
|  | `signature` | `CompletionSignatureReference` | Yes | A `provider_tee` signature. Its signer selects the evidence. A full `CompletionSignature` also works. |
| `find_model_attestation_for_signature` | `attestations` | `tuple[ModelAttestation, ...] \| list[ModelAttestation]` | Yes | Evidence returned by `fetch_model_attestations`. Exactly one item must match the signer. |
|  | `signature` | `CompletionSignatureReference` | Yes | A `provider_tee` signature whose signer selects the result. |

Every model-attestation fetch generates a fresh 32-byte client nonce, checks
Cloud API's echoed nonce, and returns the nonce with raw evidence. Pass it to
`verify_model_attestation`.

| Result type | Field | Type | Description |
| --- | --- | --- | --- |
| `FetchedModelAttestations` | `nonce` | `str` | Client nonce generated and sent by the SDK. |
|  | `attestations` | `tuple[ModelAttestation, ...]` | Cloud API model attestations. The SDK currently requires exactly one item. |
| `FetchedModelAttestation` | `nonce` | `str` | Client nonce generated and sent by the SDK. |
|  | `attestation` | `ModelAttestation` | Evidence selected for the `provider_tee` signer. |

### Gateway-attestation helper

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `api_key` | `str` | Yes | Bearer token for the Cloud API request. |
| `signing_algo` | `SigningAlgo \| None` | No | Gateway signing algorithm. Omit it to use the Cloud API default; for a Gateway response, pass `signature.signer.signing_algo`. |

`fetch_gateway_attestation` generates a fresh nonce, checks its echoed value,
requests TLS-fingerprint evidence, and captures the SHA-256 SPKI fingerprint
from the TLS connection for that HTTPS request. If the HTTP runtime cannot
expose that connection, `client_binding.peer_spki_fingerprint` is `None` and
the default Gateway policy rejects the result at verification time.

| `FetchedGatewayAttestation` field | Type | Description |
| --- | --- | --- |
| `attestation` | `GatewayAttestation` | Returned Gateway evidence. |
| `client_binding` | `GatewayClientBinding` | Client values associated with this evidence request. |

| `GatewayClientBinding` field | Type | Description |
| --- | --- | --- |
| `nonce` | `str` | Client nonce generated and sent by the SDK. |
| `peer_spki_fingerprint` | `str \| None` | SHA-256 SPKI fingerprint observed for this exact HTTPS request. The default Gateway policy requires it; set `verify_peer_tls_binding=False` only if it is unavailable. |

## Verification functions

### Attestation verification

| Function | Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `verify_model_attestation` | `attestation` | `ModelAttestation` | Yes | Raw model evidence. |
|  | `nonce` | `str` | Yes | Client nonce returned by the matching model-evidence fetch. |
|  | `policy` | `ModelAttestationPolicy \| None` | No | TCB and GPU-evidence requirements. |
|  | `verifiers` | `ModelAttestationVerifiers \| None` | No | Quote, deployment, and NVIDIA verifier overrides. |
| `verify_gateway_attestation` | `attestation` | `GatewayAttestation` | Yes | Raw Gateway evidence. |
|  | `client_binding` | `GatewayClientBinding` | Yes | Client values returned with the matching Gateway-evidence fetch. |
|  | `policy` | `GatewayAttestationPolicy \| None` | No | TCB and peer TLS binding requirements. |
|  | `verifiers` | `AttestationVerifiers \| None` | No | Quote and deployment verifier overrides. |

`client_binding.nonce` must come from the matching fetch result.
`GatewayAttestationPolicy.verify_peer_tls_binding` defaults to `True`: a
missing peer fingerprint fails verification, and a supplied fingerprint must
match the fingerprint authenticated by the quote. Set it to `False` only when
no peer certificate is available. The SDK then ignores any supplied peer
fingerprint, still verifies the nonce and quote-bound TLS identity, and returns
`GatewayTlsBinding(kind='attested', ...)`.

### Response verification

| Function | Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `verify_model_response` | `request_body` | `bytes` | Yes | Exact bytes sent to the completion endpoint. |
|  | `response_body` | `bytes` | Yes | Exact bytes received from the completion endpoint. |
|  | `signature` | `CompletionSignature` | Yes | Signature with `kind='provider_tee'`. |
|  | `attestation` | `VerifiedModelAttestation` | Yes | Verified model evidence whose signer must match the signature. |
| `verify_gateway_response` | `request_body` | `bytes` | Yes | Exact bytes sent to the completion endpoint. |
|  | `response_body` | `bytes` | Yes | Exact bytes received from the completion endpoint. |
|  | `signature` | `CompletionSignature` | Yes | Signature with `kind='gateway'`. |
|  | `attestation` | `VerifiedGatewayAttestation` | Yes | Verified Gateway evidence whose signer must match the signature. |

Call the matching attestation verifier before response verification. Verified
results are ordinary data, so callers decide when raw evidence must be verified
again after storage, transfer, or reconstruction in another process.

## Evidence, signatures, policies, and results

### Signatures and raw evidence

| Type | Field | Type | Description |
| --- | --- | --- | --- |
| `SigningIdentity` | `signing_algo` | `SigningAlgo` | `ecdsa` or `ed25519`. |
|  | `signing_address` | `str` | Hexadecimal signing identity: 20 bytes for ECDSA or 32 bytes for Ed25519. |
| `CompletionSignatureReference` | `kind` | `CompletionSignatureKind` | `provider_tee` or `gateway`. Model-evidence selection accepts only `provider_tee`. |
|  | `signer` | `SigningIdentity` | Identity used to select evidence. |
| `CompletionSignature` | `signed_text` | `str` | Text covered by the signature. |
|  | `signature` | `str` | Hexadecimal signature: 65 bytes for ECDSA or 64 bytes for Ed25519. |
| `AttestationEvidence` | `nonce` | `str` | Nonce echoed by Cloud API. The fetch helper compares it with its generated nonce. |
|  | `signer` | `SigningIdentity` | Advertised signing identity. |
|  | `intel_quote` | `str` | Intel TDX quote. |
|  | `event_log` | `AttestationEventLog` | Input used to replay RTMR3 measurements. |
|  | `app_compose` | `str` | Measured compose configuration text. |
|  | `declared_spki_fingerprint` | `str \| None` | Optional service-declared fingerprint for model evidence; not a caller-observed TLS peer. |
| `ModelAttestation` | `reported_quote_data` | `str \| None` | Optional report-data copy cross-checked against the authenticated quote. |
|  | `nvidia_payload` | `str \| None` | Optional GPU evidence payload. |
| `GatewayAttestation` | `declared_spki_fingerprint` | `str` | Gateway TLS fingerprint authenticated by the quote. |
|  | `reported_quote_data` | `str` | Gateway report-data copy required by Gateway verification. |

`CompletionSignatureKind` is `Literal['provider_tee', 'gateway']` and
`SigningAlgo` is `Literal['ecdsa', 'ed25519']`.

### Policies and verifier callbacks

| Type | Field or signature | Default | Description |
| --- | --- | --- | --- |
| `AttestationPolicy` | `accepted_tcb_statuses` | default accepted statuses | Optional accepted TCB statuses. The default accepts `UpToDate` and `OutOfDate`. |
| `ModelAttestationPolicy` | `accepted_tcb_statuses` | default accepted statuses | Inherited TCB policy. The default accepts `UpToDate` and `OutOfDate`. |
|  | `gpu_evidence` | `'if-present'` | Requires GPU evidence only when set to `'required'`. |
| `GatewayAttestationPolicy` | `accepted_tcb_statuses` | default accepted statuses | Inherited TCB policy. The default accepts `UpToDate` and `OutOfDate`. |
|  | `verify_peer_tls_binding` | `True` | Require and compare the TLS peer observed for the evidence request. Set to `False` only when no peer certificate is available; any supplied peer fingerprint is then ignored. |
| `AttestationVerifiers` | `quote` | built in | Optional replacement for the Intel DCAP quote verifier. |
|  | `deployment` | absent | Optional deployment-acceptance verifier. |
| `ModelAttestationVerifiers` | `quote` | built in | Optional replacement for the Intel DCAP quote verifier. |
|  | `deployment` | absent | Optional deployment-acceptance verifier. |
|  | `nvidia` | built in | Optional replacement for the NVIDIA NRAS verifier. |
| `QuoteVerifier` | `(quote: str) -> QuoteVerificationResult \| Awaitable[QuoteVerificationResult]` | — | Authenticates a quote and returns verified fields. |
| `DeploymentVerifier` | `(deployment: MeasuredDeployment) -> None \| Awaitable[None]` | — | Returns only for an accepted deployment. |
| `NvidiaEvidenceVerifier` | `(payload: str) -> None \| Awaitable[None]` | — | Returns only for accepted GPU evidence. |

The default NVIDIA verifier delegates to NVIDIA NRAS over HTTPS and accepts its
documented boolean overall result. It does not locally validate the returned
JWT/EAT signature.

`TcbStatus` is one of `UpToDate`, `SWHardeningNeeded`,
`ConfigurationNeeded`, `ConfigurationAndSWHardeningNeeded`, `OutOfDate`,
`OutOfDateConfigurationNeeded`, `Revoked`, or `Unknown`.

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
| `VerifiedModelAttestation` | `tls_binding` | `ModelTlsBinding` | `none` or a service-declared fingerprint binding; not client-to-model TLS proof. |
|  | `gpu_evidence` | `'not_provided' \| 'verified'` | GPU-evidence verification outcome. |
| `VerifiedGatewayAttestation` | `tls_binding` | `GatewayTlsBinding` | `peer` when the observed peer matched; `attested` when peer binding was explicitly disabled. |

`ModelTlsBinding` is either `ModelTlsBinding(kind='none')` or
`ModelTlsBinding(kind='declared', spki_fingerprint=...)`.
`GatewayTlsBinding` is either `GatewayTlsBinding(kind='peer',
spki_fingerprint=...)` or, only when peer binding was explicitly disabled,
`GatewayTlsBinding(kind='attested', spki_fingerprint=...)`.
