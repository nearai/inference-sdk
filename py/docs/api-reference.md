# Python SDK API reference

This page describes the public APIs exported by `verifiable_ai_sdk`. For
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

Cloud retrieval and attestation verification are asynchronous. Response
verification is synchronous.

| API | Signature | Returns | Purpose |
| --- | --- | --- | --- |
| `AttestationClient` | `(api_key, *, base_url=...)` | client | Owns Cloud API credentials and retrieves deployment evidence and completion signatures. |
| `client.fetch_completion_signature` | `(completion_id, *, signing_algo=None)` | `CompletionSignature` | Fetches one completion signature after a completion. |
| `client.fetch_model_attestations` | `(model, *, signing_algo=None, signing_address=None)` | `FetchedModelAttestations` | Fetches target-model deployment evidence; optional signer fields narrow the API response. |
| `client.fetch_model_attestation_for_signature` | `(model, signature)` | `FetchedModelAttestation` | Fetches and locally selects model evidence for a `provider_tee` signer. |
| `client.fetch_gateway_attestation` | `(*, signing_algo=None, include_spki_fingerprint=True)` | `FetchedGatewayAttestation` | Fetches Gateway deployment evidence, optionally including its TLS fingerprint. |
| `find_model_attestation_for_signature` | `(attestations, signature)` | `ModelAttestation` | Locally selects the sole evidence item for a `provider_tee` signer. |
| `verify_model_attestation` | `(attestation, client_binding, *, policy=None, verifiers=None)` | `VerifiedModelAttestation` | Verifies target-model deployment evidence. |
| `verify_gateway_attestation` | `(attestation, client_binding, *, policy=None, verifiers=None)` | `VerifiedGatewayAttestation` | Verifies Gateway deployment evidence using the layout in the attestation. |
| `verify_model_response` | `(request_body, response_body, signature, attestation)` | `None` | Verifies a `provider_tee` signature using preverified model evidence. |
| `verify_gateway_response` | `(request_body, response_body, signature, attestation)` | `None` | Verifies a `gateway` signature using preverified Gateway evidence. |

## AttestationClient

The client does not send completion requests or retain completion bytes. It
creates a fresh nonce for every attestation fetch.

### Constructor

| Field | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `api_key` | `str` | Yes | — | Bearer token for signature and evidence requests. |
| `base_url` | `str` | No | `https://cloud-api.near.ai/v1` | Absolute HTTP(S) Cloud API base URL. |

### Completion-signature methods

| API | Parameter | Type | Required | Description |
| --- | --- | --- | --- | --- |
| `fetch_completion_signature` | `completion_id` | `str` | Yes | Completion ID returned by the API response. Fetch after the completion reaches a terminal state. |
|  | `signing_algo` | `SigningAlgo \| None` | No | Signing algorithm to request. Set it when the application requires a particular algorithm; omit it for the service default. |

`client.fetch_completion_signature()` raises `ApiError` when Cloud API returns
an unavailable 2xx response. The error code is
`api.completion_signature_unavailable`; its details contain
`providerErrorCode` and `providerMessage` from the service response.

### Target-model deployment methods

| API | Parameter | Type | Required | Description |
| --- | --- | --- | --- | --- |
| `fetch_model_attestations` | `model` | `str` | Yes | Canonical target model ID. Use before sending its completion. |
|  | `signing_algo` | `SigningAlgo \| None` | No | Optional API request filter for the required signing algorithm. |
|  | `signing_address` | `str \| None` | No | Optional API request filter for the advertised signing address. |
| `fetch_model_attestation_for_signature` | `model` | `str` | Yes | Canonical model ID. |
|  | `signature` | `CompletionSignatureReference` | Yes | A `provider_tee` signature. The method uses its signer as request filters and then performs local selection. This is a signature-driven convenience, not the deployment-first workflow. |

Every model-attestation fetch generates a fresh 32-byte client nonce, requests
`include_tls_fingerprint=false`, checks Cloud API's echoed nonce, and returns a
`ModelClientBinding` with the raw evidence. `signing_algo` and
`signing_address` only narrow the remote response. The SDK currently requires
Cloud API to return exactly one model attestation, so deployment-first callers
can verify `fetched.attestations[0]` before the completion. Use
`find_model_attestation_for_signature` only when doing signature-driven local
selection after a `provider_tee` signature is available.

### Local model selection

| Function | Parameter | Type | Required | Description |
| --- | --- | --- | --- | --- |
| `find_model_attestation_for_signature` | `attestations` | `tuple[ModelAttestation, ...] \| list[ModelAttestation]` | Yes | Evidence returned by `client.fetch_model_attestations()`. Exactly one item must match the signer. |
|  | `signature` | `CompletionSignatureReference` | Yes | A `provider_tee` signature whose signer selects the result. |

| Result type | Field | Type | Description |
| --- | --- | --- | --- |
| `FetchedModelAttestations` | `attestations` | `tuple[ModelAttestation, ...]` | Cloud API model attestations. The SDK currently requires exactly one item. |
|  | `client_binding` | `ModelClientBinding` | Client nonce associated with this evidence request. |
| `FetchedModelAttestation` | `attestation` | `ModelAttestation` | Evidence selected for the `provider_tee` signer. |
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
signature does not prove that an attested model generated them. [Cloud API issue
#986](https://github.com/nearai/cloud-api/issues/986) tracks the missing
provider-signature and Gateway-receipt chain.

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
| `AttestationEvidence` | `nonce` | `str` | Nonce echoed by Cloud API. The fetch helper compares it with its generated nonce. |
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
| `VerifiedGatewayAttestation` | `tls_binding` | `GatewayTlsBinding` | `attested` when the attestation fingerprint matches the observed peer; `none` when the attestation has no fingerprint. |

`GatewayTlsBinding` is either `GatewayTlsBinding(kind='none')` or
`GatewayTlsBinding(kind='attested', spki_fingerprint=...)`.
