# Rust SDK API reference

This page lists the public Rust request and verification APIs exported by
`verifiable_ai_sdk`. For workflows and complete examples, see the
[verification guide](./verification-guide.md).

## Cloud API requests

Each Cloud API helper takes its `api_key` directly. It uses
`DEFAULT_NEAR_AI_CLOUD_BASE_URL` and the built-in reqwest client. There is
no shared Cloud client or configuration object to retain.

For a custom base URL or request filter, construct the matching request
builder. Builders own configuration for one request and finish with `send()`.

| Builder | Required constructor arguments | Optional methods | Terminal operation |
| --- | --- | --- | --- |
| `ModelAttestationsRequest` | `new(api_key, model)` | `base_url`, `signing_algo`, `signing_address` | `send()` → `FetchedModelAttestations` |
| `ModelAttestationForSignatureRequest` | `new(api_key, model, signature)` | `base_url` | `send()` → `FetchedModelAttestation` |
| `GatewayAttestationRequest` | `new(api_key)` | `base_url`, `signing_algo` | `send()` → `FetchedGatewayAttestation` |
| `CompletionSignatureRequest` | `new(api_key, completion_id)` | `base_url`, `signing_algo` | `send()` → `CompletionSignatureLookup` |

`base_url` parses an absolute Cloud API base URL and returns
`Result<Self, VerificationError>`. The `signing_algo` and `signing_address`
methods add the corresponding Cloud API query filters.

`CompletionSignatureRequest::send()` preserves Cloud API's unavailable result.
Use `fetch_completion_signature()` when an unavailable signature should instead
be returned as `ApiError::CompletionSignatureUnavailable`.

## Cloud API functions

These convenience functions take only required normal arguments and return
`Result<_, SdkError>`. They fetch evidence or signatures only; they do not send
an inference request or retain completion bytes.

| Function | Parameters | Returns | Description |
| --- | --- | --- | --- |
| `lookup_completion_signature` | `api_key: &str`, `completion_id: &str` | `CompletionSignatureLookup` | Returns a completion signature or a service-provided unavailable state. |
| `fetch_completion_signature` | `api_key`, `completion_id` | `CompletionSignature` | Strict form: returns a signature or `ApiError::CompletionSignatureUnavailable` for a 2xx unavailable envelope. |
| `fetch_model_attestations` | `api_key`, `model: &str` | `FetchedModelAttestations` | Fetches evidence for a canonical model ID. It currently requires exactly one candidate. |
| `find_model_attestation_for_signature` | `attestations: &[ModelAttestation]`, `signature: &CompletionSignatureReference` | `&ModelAttestation` | Selects the single attestation matching a `ProviderTee` signer. It does not verify evidence. |
| `fetch_model_attestation_for_signature` | `api_key`, `model`, `signature: &CompletionSignatureReference` | `FetchedModelAttestation` | Fetches model evidence for a `ProviderTee` signer and selects the sole matching candidate. |
| `fetch_gateway_attestation` | `api_key` | `FetchedGatewayAttestation` | Fetches Gateway evidence with a fresh nonce, requests TLS-fingerprint evidence using Ed25519, and captures the SHA-256 SPKI fingerprint from that HTTPS request's peer certificate. Use `GatewayAttestationRequest` for another signing algorithm. |

### Cloud fetch results

Every attestation fetch generates a fresh 32-byte client nonce, sends it, and
checks the service's echoed nonce. Model results return that nonce directly.
Gateway results return a `GatewayClientBinding`, so callers can pass it with the
matching evidence to `verify_gateway_attestation`.

| Type | Field | Description |
| --- | --- | --- |
| `FetchedModelAttestations` | `attestations` | Returned `Vec<ModelAttestation>`. The current helper requires exactly one item. |
|  | `nonce` | SDK-generated client nonce for these attestations. |
| `FetchedModelAttestation` | `attestation` | Candidate selected for the supplied `ProviderTee` signer. |
|  | `nonce` | SDK-generated client nonce. |
| `FetchedGatewayAttestation` | `attestation` | Returned Gateway attestation. |
|  | `client_binding` | `GatewayClientBinding` returned with the evidence request. |
| `GatewayClientBinding` | `nonce` | SDK-generated client nonce. |
|  | `peer_spki_fingerprint` | Optional SHA-256 SPKI fingerprint observed for the exact HTTPS evidence request. The default Gateway policy requires it; set `verify_peer_tls_binding` to `false` only when it is unavailable. |

## Attestation verification

| Function | Parameters | Returns | Description |
| --- | --- | --- | --- |
| `verify_model_attestation` | `attestation: &ModelAttestation`, `nonce: &str`, `policy: Option<&ModelAttestationPolicy>`, `verifiers: ModelAttestationVerifiers` | `VerifiedModelAttestation` | Verifies model evidence, policy, measured deployment, and GPU evidence when supplied. |
| `verify_gateway_attestation` | `attestation: &GatewayAttestation`, `client_binding: &GatewayClientBinding`, `policy: Option<&GatewayAttestationPolicy>`, `verifiers: AttestationVerifiers` | `VerifiedGatewayAttestation` | Verifies Gateway evidence and its quote-bound TLS identity. By default, it also requires and verifies the client-observed TLS peer. |

Both functions are asynchronous and return `Result<_, VerificationError>`.

Pass the matching fetch result's `nonce` or `client_binding`. `policy: None`
uses defaults; pass `Default::default()` as `verifiers` to use built-in quote,
deployment, and GPU verification.

`GatewayAttestationPolicy::verify_peer_tls_binding` defaults to `true`. In
that mode, `client_binding.peer_spki_fingerprint` must be a 32-byte hexadecimal
SHA-256 SPKI fingerprint independently observed for the TLS peer serving the
Gateway attestation request. Do not use the attestation's declared fingerprint
as the observed peer value. A runtime without peer-certificate access must set
`verify_peer_tls_binding` to `false`; verification then ignores a supplied peer
fingerprint and returns `GatewayTlsBinding::Attested`.

## Response verification

| Function | Parameters | Returns | Description |
| --- | --- | --- | --- |
| `verify_model_response` | `request_body: &[u8]`, `response_body: &[u8]`, `signature: &CompletionSignature`, `attestation: &VerifiedModelAttestation` | `()` | Verifies a `ProviderTee` completion signature for exact bytes and matches its signer to verified model evidence. |
| `verify_gateway_response` | `request_body: &[u8]`, `response_body: &[u8]`, `signature: &CompletionSignature`, `attestation: &VerifiedGatewayAttestation` | `()` | Verifies a `Gateway` completion signature for exact bytes and matches its signer to verified Gateway evidence. |

Both functions return `Result<(), VerificationError>`. Call the matching
attestation verifier first.

For both response functions, supply the exact request and response bytes. The
model request body must contain a non-empty JSON `model` string. The signature
kind must match the verifier (`ProviderTee` or `Gateway`), and the verified
attestation must bind the signature signer.

## Signatures and evidence

### Signature types

| Type | Field | Description |
| --- | --- | --- |
| `SigningIdentity` | `signing_algo` | `SigningAlgo::Ecdsa` or `SigningAlgo::Ed25519`. |
|  | `signing_address` | Hexadecimal public signing identity: 20 bytes for ECDSA or 32 bytes for Ed25519. |
| `CompletionSignature` | `kind` | `CompletionSignatureKind::ProviderTee` or `CompletionSignatureKind::Gateway`; selects the verification path. |
|  | `signed_text` | Text covered by the signature. |
|  | `signature` | Hexadecimal signature: 65 bytes for ECDSA or 64 bytes for Ed25519. |
|  | `signer` | Signing identity that must match verified evidence. |
| `CompletionSignatureReference` | `kind` | Signature kind used for evidence selection. `find_model_attestation_for_signature` accepts only `ProviderTee`. |
|  | `signer` | Signing identity used to select matching model evidence. |
| `CompletionSignatureLookup` | `Found(CompletionSignature)` | A signature was returned. |
|  | `Unavailable(SignatureUnavailable)` | A 2xx service response reported no signature. `SignatureUnavailable` carries `error_code` and `message`. |

### Attestation evidence

`ModelAttestation` wraps `AttestationEvidence` with optional
`reported_quote_data` and `nvidia_payload`. `GatewayAttestation` wraps
`AttestationEvidence` with a required `reported_quote_data` copy.

Optional model fields are represented as `Option<String>`: an absent value is
`None`; a supplied `nvidia_payload` is validated by the matching verifier.
Gateway `reported_quote_data` is required.

| `AttestationEvidence` field | Description |
| --- | --- |
| `nonce` | Nonce echoed by Cloud API. The fetch helper validates it against its generated nonce. |
| `signer` | Advertised signing identity. |
| `intel_quote` | Intel TDX quote. |
| `event_log` | `AttestationEventLog::Json(String)` or `AttestationEventLog::Entries(Vec<serde_json::Value>)`, used to replay RTMR3. |
| `app_compose` | Measured compose configuration text. |

| Attestation type | Field | Description |
| --- | --- | --- |
| `ModelAttestation` | `declared_spki_fingerprint` | Optional declared SPKI fingerprint; not a caller-observed TLS peer fingerprint. |
|  | `reported_quote_data` | Optional report-data copy cross-checked against the authenticated quote. |
|  | `nvidia_payload` | Optional NVIDIA evidence payload. |
| `GatewayAttestation` | `reported_quote_data` | Required report-data copy cross-checked against the authenticated quote. |
|  | `declared_spki_fingerprint` | Required Gateway TLS SPKI fingerprint authenticated by the quote. |

## Policies and verifier callbacks

| Type | Field | Default | Description |
| --- | --- | --- | --- |
| `ModelAttestationPolicy` | `accepted_tcb_statuses: Option<Vec<TcbStatus>>` | `UpToDate`, `OutOfDate` | Model TCB statuses accepted by verification. |
|  | `gpu_evidence: GpuEvidenceRequirement` | `IfPresent` | `IfPresent` verifies supplied GPU evidence and accepts an absent payload; `Required` rejects absent evidence. |
| `GatewayAttestationPolicy` | `accepted_tcb_statuses: Option<Vec<TcbStatus>>` | `UpToDate`, `OutOfDate` | Gateway TCB statuses accepted by verification. |
|  | `verify_peer_tls_binding: bool` | `true` | Require and compare the TLS peer observed for the evidence request. Set to `false` only when no peer certificate is available; any supplied peer fingerprint is then ignored. |
| `AttestationVerifiers<'a>` | `quote`, `deployment` | `None` | Optional `QuoteVerifier` and `DeploymentVerifier` overrides. |
| `ModelAttestationVerifiers<'a>` | `quote`, `deployment`, `nvidia` | `None` | Optional `QuoteVerifier`, `DeploymentVerifier`, and `NvidiaEvidenceVerifier` overrides. |

| Trait | Method | Contract |
| --- | --- | --- |
| `QuoteVerifier` | `async fn verify(&self, intel_quote: &str) -> Result<QuoteVerificationResult, VerificationError>` | Authenticates a quote and returns verified quote fields. |
| `DeploymentVerifier` | `async fn verify(&self, deployment: &MeasuredDeployment) -> Result<(), VerificationError>` | Returns `Ok(())` only for a deployment the application accepts. |
| `NvidiaEvidenceVerifier` | `async fn verify(&self, nvidia_payload: &str) -> Result<(), VerificationError>` | Returns `Ok(())` only for GPU evidence the application accepts. |

The default NVIDIA implementation is `NrasNvidiaEvidenceVerifier`; the default
Intel implementation is `DcapQuoteVerifier`. See the guide for their trust-root
and JWT/EAT-validation behavior.

## Verified results

| Type | Field | Description |
| --- | --- | --- |
| `VerifiedAttestationEvidence` | `signer` | Verified signing identity. |
|  | `tcb_status`, `advisory_ids` | Accepted quote TCB status and authenticated advisory IDs. |
|  | `deployment` | `MeasuredDeployment` with `app_compose` and derived `RuntimeMeasurements`. |
|  | `deployment_provenance` | `NotChecked` when no custom deployment verifier was supplied; `Verified` when it accepted the deployment. |
| `VerifiedModelAttestation` | `evidence` | Shared verified evidence above. |
|  | `tls_binding` | `ModelTlsBinding::None` or `ModelTlsBinding::Declared { spki_fingerprint }`. A declaration is not a direct model TLS binding. |
|  | `gpu_evidence` | `GpuEvidenceStatus::NotProvided` or `GpuEvidenceStatus::Verified`. |
| `VerifiedGatewayAttestation` | `evidence` | Shared verified evidence above. |
|  | `tls_binding` | `GatewayTlsBinding::Peer { spki_fingerprint }` when the observed peer matched, or `GatewayTlsBinding::Attested { spki_fingerprint }` when peer binding was explicitly disabled. |

## Errors

See [Handle errors](./verification-guide.md#handle-errors). The public error
surface is `ApiError`, `VerificationError`, and `SdkError`; this reference
intentionally focuses on request and verification APIs rather than enumerating
each error variant.
