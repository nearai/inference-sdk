# Python SDK API reference

This page describes the public APIs exported by `verifiable_ai_sdk`. For
workflows and complete examples, see the [verification guide](./verification-guide.md).

## Public functions

The Cloud request and attestation-verification functions are asynchronous.
Response verification functions are synchronous.

| Function | Signature | Returns | Purpose |
| --- | --- | --- | --- |
| `fetch_completion_signature` | `(api_key, completion_id, *, signing_algo=None, base_url=...)` | `CompletionSignature` | Fetches one completion signature or raises when none is available. |
| `lookup_completion_signature` | `(api_key, completion_id, *, signing_algo=None, base_url=...)` | `CompletionSignatureLookup` | Fetches one signature or a service-provided unavailable result. |
| `fetch_model_attestations` | `(api_key, model, *, signing_algo=None, signing_address=None, base_url=...)` | `FetchedModelAttestations` | Fetches model evidence; optional signer fields narrow the API response. |
| `fetch_model_attestation_for_signature` | `(api_key, model, signature, *, base_url=...)` | `FetchedModelAttestation` | Fetches and locally selects model evidence for a `provider_tee` signer. |
| `find_model_attestation_for_signature` | `(attestations, signature)` | `ModelAttestation` | Locally selects the sole evidence item for a `provider_tee` signer. |
| `fetch_gateway_attestation` | `(api_key, *, signing_algo=None, policy=None, base_url=...)` | `FetchedGatewayAttestation` | Fetches Gateway evidence using the selected TLS-binding policy. |
| `verify_model_attestation` | `(attestation, client_binding, *, policy=None, verifiers=None)` | `VerifiedModelAttestation` | Verifies model attestation evidence. |
| `verify_gateway_attestation` | `(attestation, client_binding, *, policy=None, verifiers=None)` | `VerifiedGatewayAttestation` | Verifies Gateway evidence using the selected quote binding layout. |
| `verify_model_response` | `(request_body, response_body, signature, attestation)` | `None` | Verifies exact bytes signed by a `provider_tee` signer. |
| `verify_gateway_response` | `(request_body, response_body, signature, attestation)` | `None` | Verifies exact bytes signed by a `gateway` signer. |

## Cloud request helpers

The request helpers do not send completion requests or retain completion bytes.
Python uses ordinary function parameters: `api_key` comes first, required
request fields follow, and optional fields are keyword-only.

### Shared parameters

| Field | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `api_key` | `str` | Yes | — | Bearer token for signature and evidence requests. |
| `base_url` | `str` | No | `https://cloud-api.near.ai/v1` | Cloud API base URL. |

### Signature helpers

| Function | Parameter | Type | Required | Description |
| --- | --- | --- | --- | --- |
| `lookup_completion_signature` and `fetch_completion_signature` | `completion_id` | `str` | Yes | Completion ID returned by the API response. |
|  | `signing_algo` | `SigningAlgo \| None` | No | Signing algorithm to request. Omit it for the service default. |

`lookup_completion_signature` returns `CompletionSignatureLookup`, whose
`status` is either `'found'` with `signature`, or `'unavailable'` with the
service's `unavailable` error. `fetch_completion_signature` is the strict
form: an unavailable 2xx response raises `ApiError` with
`api.completion_signature_unavailable`.

### Model-attestation helpers

| Function | Parameter | Type | Required | Description |
| --- | --- | --- | --- | --- |
| `fetch_model_attestations` | `model` | `str` | Yes | Canonical model ID. |
|  | `signing_algo` | `SigningAlgo \| None` | No | Optional API request filter for the advertised signing algorithm. |
|  | `signing_address` | `str \| None` | No | Optional API request filter for the advertised signing address. |
| `fetch_model_attestation_for_signature` | `model` | `str` | Yes | Canonical model ID. |
|  | `signature` | `CompletionSignatureReference` | Yes | A `provider_tee` signature. The helper uses its signer as request filters and then performs local selection. |
| `find_model_attestation_for_signature` | `attestations` | `tuple[ModelAttestation, ...] \| list[ModelAttestation]` | Yes | Evidence returned by `fetch_model_attestations`. Exactly one item must match the signer. |
|  | `signature` | `CompletionSignatureReference` | Yes | A `provider_tee` signature whose signer selects the result. |

Every model-attestation fetch generates a fresh 32-byte client nonce, requests
`include_tls_fingerprint=false`, checks Cloud API's echoed nonce, and returns a
`ModelClientBinding` with the raw evidence. `signing_algo` and
`signing_address` only narrow the remote response: use
`find_model_attestation_for_signature` to match a completion signature locally
before verifying it.

| Result type | Field | Type | Description |
| --- | --- | --- | --- |
| `FetchedModelAttestations` | `attestations` | `tuple[ModelAttestation, ...]` | Cloud API model attestations. The SDK currently requires exactly one item. |
|  | `client_binding` | `ModelClientBinding` | Client nonce associated with this evidence request. |
| `FetchedModelAttestation` | `attestation` | `ModelAttestation` | Evidence selected for the `provider_tee` signer. |
|  | `client_binding` | `ModelClientBinding` | Client nonce associated with this evidence request. |

### Gateway-attestation helper

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `signing_algo` | `SigningAlgo \| None` | No | Gateway signing algorithm. For a Gateway response, pass `signature.signer.signing_algo`. |
| `policy` | `GatewayAttestationPolicy \| None` | No | Controls both `include_tls_fingerprint` in the request and the later quote binding layout. Defaults to `GatewayAttestationPolicy()`. |

`fetch_gateway_attestation` generates a fresh nonce, checks its echoed value,
and returns the resolved policy with the evidence. With the default
`verify_tls_binding=True`, it requests TLS-fingerprint evidence and the native
helper captures the SHA-256 SPKI fingerprint from the TLS connection for that
exact HTTPS request. With `verify_tls_binding=False`, it sends
`include_tls_fingerprint=false` and does not capture a peer fingerprint.

| `FetchedGatewayAttestation` field | Type | Description |
| --- | --- | --- |
| `attestation` | `GatewayAttestation` | Returned Gateway evidence. |
| `client_binding` | `GatewayClientBinding` | Client values associated with this evidence request. |
| `policy` | `GatewayAttestationPolicy` | Resolved fetch policy; pass it to `verify_gateway_attestation`. |

| Client-binding field | Type | Description |
| --- | --- | --- |
| `ModelClientBinding.nonce` | `str` | Client nonce generated and sent by the matching model-evidence fetch. |
| `GatewayClientBinding.nonce` | `str` | Client nonce generated and sent by the matching Gateway-evidence fetch. |
| `GatewayClientBinding.peer_spki_fingerprint` | `str \| None` | SHA-256 SPKI fingerprint observed for that exact Gateway-evidence HTTPS request when TLS binding was enabled and the runtime exposes it. |

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
|  | `policy` | `GatewayAttestationPolicy \| None` | No | TCB and TLS-binding requirements. Use the paired fetch result's `policy`. |
|  | `verifiers` | `AttestationVerifiers \| None` | No | Quote and deployment verifier overrides. |

`client_binding.nonce` must come from the matching fetch result. Model evidence
always verifies the signer-and-nonce report-data layout and has no TLS-binding
result. `GatewayAttestationPolicy.verify_tls_binding` defaults to `True`: the
Gateway fetch requests a TLS fingerprint, and verification requires the quote
fingerprint to match the TLS peer observed for that request. Set it to `False`
before fetching only when no peer certificate is available. The resulting
Gateway verification instead checks signer-and-nonce report data and returns
`GatewayTlsBinding(kind='none')`.

### Response verification

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
| `ModelAttestation` | `reported_quote_data` | `str \| None` | Optional report-data copy cross-checked against the authenticated quote. |
|  | `nvidia_payload` | `str \| None` | Optional GPU evidence payload. |
| `GatewayAttestation` | `tls_spki_fingerprint` | `str \| None` | TLS fingerprint returned only for a TLS-binding evidence request. It is required by the enabled verification path. |
|  | `reported_quote_data` | `str` | Gateway report-data copy required by Gateway verification. |

`CompletionSignatureKind` is `Literal['provider_tee', 'gateway']` and
`SigningAlgo` is `Literal['ecdsa', 'ed25519']`.

### Policies and verifier callbacks

| Type | Field or signature | Default | Description |
| --- | --- | --- | --- |
| `AttestationPolicy` | `accepted_tcb_statuses` | default accepted statuses | Optional accepted TCB statuses. The default accepts `UpToDate` and `OutOfDate`. |
| `ModelAttestationPolicy` | `accepted_tcb_statuses` | default accepted statuses | Inherited TCB policy. |
|  | `gpu_evidence` | `'if-present'` | Requires GPU evidence only when set to `'required'`. |
| `GatewayAttestationPolicy` | `accepted_tcb_statuses` | default accepted statuses | Inherited TCB policy. |
|  | `verify_tls_binding` | `True` | Controls both evidence retrieval and verification. `True` selects signer + TLS fingerprint + nonce and requires the observed peer; `False` selects signer + nonce and returns no TLS binding. |
| `AttestationVerifiers` | `quote` | built in | Optional replacement for the Intel DCAP quote verifier. |
|  | `deployment` | absent | Optional deployment-acceptance verifier. |
| `ModelAttestationVerifiers` | `nvidia` | built in | Optional replacement for the NVIDIA NRAS verifier. |
| `QuoteVerifier` | `(quote: str) -> QuoteVerificationResult \| Awaitable[QuoteVerificationResult]` | — | Authenticates a quote and returns verified fields. |
| `DeploymentVerifier` | `(deployment: MeasuredDeployment) -> None \| Awaitable[None]` | — | Returns only for an accepted deployment. |
| `NvidiaEvidenceVerifier` | `(payload: str) -> None \| Awaitable[None]` | — | Returns only for accepted GPU evidence. |

The default NVIDIA verifier delegates to NVIDIA NRAS over HTTPS and accepts its
documented boolean overall result. It does not locally validate the returned
JWT/EAT signature.

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
| `VerifiedGatewayAttestation` | `tls_binding` | `GatewayTlsBinding` | `attested` when TLS binding was enabled and matched the observed peer; `none` when the no-TLS policy selected signer-and-nonce evidence. |

`GatewayTlsBinding` is either `GatewayTlsBinding(kind='none')` or
`GatewayTlsBinding(kind='attested', spki_fingerprint=...)`.
