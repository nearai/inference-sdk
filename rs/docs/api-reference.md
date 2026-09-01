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
| `ModelAttestationForSignatureRequest` | `new(api_key, model, signature: &CompletionSignature)` | `base_url` | `send()` → `FetchedModelAttestation` |
| `GatewayAttestationRequest` | `new(api_key)` | `base_url`, `signing_algo`, `policy` | `send()` → `FetchedGatewayAttestation` |
| `CompletionSignatureRequest` | `new(api_key, completion_id)` | `base_url`, `signing_algo` | `send()` → `CompletionSignatureLookup` |

`base_url` parses an absolute Cloud API base URL and returns
`Result<Self, VerificationError>`. The `signing_algo` and `signing_address`
methods add the corresponding Cloud API query filters. For Gateway evidence,
`policy` controls both `include_tls_fingerprint` on the request and the
report-data layout later verified.

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
| `find_model_attestation_for_signature` | `attestations: &[ModelAttestation]`, `signature: &CompletionSignature` | `&ModelAttestation` | Selects the single attestation matching a `ProviderTee` signer. It does not verify evidence. |
| `fetch_model_attestation_for_signature` | `api_key`, `model`, `signature: &CompletionSignature` | `FetchedModelAttestation` | Fetches model evidence for a `ProviderTee` signer and selects the sole matching candidate. |
| `fetch_gateway_attestation` | `api_key` | `FetchedGatewayAttestation` | Standalone Gateway-evidence helper. It uses the default TLS-binding policy, requests TLS-fingerprint evidence with a fresh nonce, and captures the SHA-256 SPKI fingerprint from that HTTPS request's peer certificate. |

`ModelAttestationsRequest::signing_algo` and `signing_address` only narrow the
Cloud API response. They do not replace
`find_model_attestation_for_signature`, which performs the local, exact signer
match for a `ProviderTee` signature. `ModelAttestationForSignatureRequest` is
the convenience form: it applies those request filters and then delegates to
that same local selector.

Model fetches always send `include_tls_fingerprint=false`; model verification
checks the signer-and-nonce quote layout and makes no client-to-model TLS
claim.

### Cloud fetch results

Every attestation fetch generates a fresh 32-byte client nonce, sends it, and
checks the service's echoed nonce. Results return the client values associated
with that evidence request; pass the matching `client_binding` to the
attestation verifier.

| Type | Field | Description |
| --- | --- | --- |
| `FetchedModelAttestations` | `attestations` | Returned `Vec<ModelAttestation>`. The current helper requires exactly one item. |
|  | `client_binding` | `ModelClientBinding` returned with these attestations. |
| `FetchedModelAttestation` | `attestation` | Candidate selected for the supplied `ProviderTee` signer. |
|  | `client_binding` | `ModelClientBinding` returned with the selected attestation. |
| `FetchedGatewayAttestation` | `attestation` | Returned Gateway attestation. |
|  | `client_binding` | `GatewayClientBinding` returned with the evidence request. |
|  | `policy` | Resolved `GatewayAttestationPolicy` for this request. Pass it to `verify_gateway_attestation`. |
| `ModelClientBinding` | `nonce` | SDK-generated client nonce. |
| `GatewayClientBinding` | `nonce` | SDK-generated client nonce. |
|  | `peer_spki_fingerprint` | Optional SHA-256 SPKI fingerprint observed for the exact HTTPS evidence request. The default Gateway policy requires it; set `verify_tls_binding` to `false` before fetching when it is unavailable. |

## Attestation verification

| Function | Parameters | Returns | Description |
| --- | --- | --- | --- |
| `verify_model_attestation` | `attestation: &ModelAttestation`, `client_binding: &ModelClientBinding`, `policy: Option<&ModelAttestationPolicy>`, `verifiers: ModelAttestationVerifiers` | `VerifiedModelAttestation` | Verifies model evidence, policy, measured deployment, and GPU evidence when supplied. |
| `verify_gateway_attestation` | `attestation: &GatewayAttestation`, `client_binding: &GatewayClientBinding`, `policy: Option<&GatewayAttestationPolicy>`, `verifiers: AttestationVerifiers` | `VerifiedGatewayAttestation` | Verifies Gateway evidence and its quote-bound TLS identity. By default, it also requires and verifies the client-observed TLS peer. |

Both functions are asynchronous and return `Result<_, VerificationError>`.

Pass the matching fetch result's `client_binding`. `policy: None` uses defaults;
pass `Default::default()` as `verifiers` to use built-in quote, deployment, and
GPU verification.

`GatewayAttestationPolicy::verify_tls_binding` defaults to `true`. In that
mode, `client_binding.peer_spki_fingerprint` must be a 32-byte hexadecimal
SHA-256 SPKI fingerprint independently observed for the TLS peer serving the
Gateway attestation request. Do not use the attestation's fingerprint as the
observed peer value. A runtime without peer-certificate access must set
`verify_tls_binding` to `false` before fetching; the request then omits the
fingerprint and verification checks signer-and-nonce report data, returning
`GatewayTlsBinding::None`.

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

For a `Gateway` response, fetch evidence through
`GatewayAttestationRequest::new(api_key).signing_algo(signature.signer.signing_algo).send()`.
The convenience `fetch_gateway_attestation(api_key)` follows the Cloud API
default, so do not use it when the response requires a specific signer.

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
| `ModelAttestation` | `reported_quote_data` | Optional report-data copy cross-checked against the authenticated quote. |
|  | `nvidia_payload` | Optional NVIDIA evidence payload. |
| `GatewayAttestation` | `reported_quote_data` | Required report-data copy cross-checked against the authenticated quote. |
|  | `tls_spki_fingerprint` | Optional Gateway TLS SPKI fingerprint. It is present when TLS binding was requested and must match the client-observed peer before verification returns an attested TLS binding. |

## Policies and verifier callbacks

| Type | Field | Default | Description |
| --- | --- | --- | --- |
| `ModelAttestationPolicy` | `accepted_tcb_statuses: Option<Vec<TcbStatus>>` | `UpToDate`, `OutOfDate` | Model TCB statuses accepted by verification. |
|  | `gpu_evidence: GpuEvidenceRequirement` | `IfPresent` | `IfPresent` verifies supplied GPU evidence and accepts an absent payload; `Required` rejects absent evidence. |
| `GatewayAttestationPolicy` | `accepted_tcb_statuses: Option<Vec<TcbStatus>>` | `UpToDate`, `OutOfDate` | Gateway TCB statuses accepted by verification. |
|  | `verify_tls_binding: bool` | `true` | When `true`, request the TLS fingerprint and require it to match the observed peer. When `false`, request no fingerprint and verify signer-and-nonce report data instead. |
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
|  | `gpu_evidence` | `GpuEvidenceStatus::NotProvided` or `GpuEvidenceStatus::Verified`. |
| `VerifiedGatewayAttestation` | `evidence` | Shared verified evidence above. |
|  | `tls_binding` | `GatewayTlsBinding::Attested { spki_fingerprint }` when the quote-bound fingerprint matched the observed peer, or `GatewayTlsBinding::None` when TLS binding was disabled. |

## Errors

See [Handle errors](./verification-guide.md#handle-errors). The public error
surface is `ApiError`, `VerificationError`, and `SdkError`; this reference
intentionally focuses on request and verification APIs rather than enumerating
each error variant.
