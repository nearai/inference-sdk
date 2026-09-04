# Rust SDK API reference

This page lists the public Rust request and verification APIs exported by
`verifiable_ai_sdk`. For workflows and complete examples, see the
[verification guide](./verification-guide.md).

## Cloud API client

`AttestationClient` owns the API key, Cloud API base URL, and its internal
reqwest clients. Create it once and reuse it for all signature and evidence
requests in a flow. The client only fetches evidence; it does not send
inference requests or retain completion bytes.

| Constructor | Parameters | Result | Description |
| --- | --- | --- | --- |
| `AttestationClient::new` | `api_key: String` | `AttestationClient` | Uses `DEFAULT_NEAR_AI_CLOUD_BASE_URL`. |
| `AttestationClient::with_base_url` | `api_key: String`, `base_url: &str` | `Result<AttestationClient, VerificationError>` | Uses an absolute HTTP(S) base URL, such as staging. The URL may include a path prefix such as `/v1`. |

All client methods below are asynchronous and return `Result<_, SdkError>`.

| Method | Parameters after `&self` | Returns | Description |
| --- | --- | --- | --- |
| `fetch_completion_signature` | `completion_id: &str`, `signing_algo: Option<SigningAlgo>` | `CompletionSignature` | Fetches a completion signature. A valid 2xx unavailable envelope returns `SdkError::Api(ApiError::CompletionSignatureUnavailable { .. })`, preserving the service's code and message. |
| `fetch_model_attestations` | `model: &str`, `signing_algo: Option<SigningAlgo>`, `signing_address: Option<&str>` | `FetchedModelAttestations` | Fetches evidence for a canonical model ID. The filters only narrow the API response; it currently requires exactly one candidate. |
| `fetch_model_attestation_for_signature` | `model: &str`, `signature: &CompletionSignature` | `FetchedModelAttestation` | Requires a `ProviderTee` signature, applies its signer as API filters, and selects the exact matching candidate locally. It does not verify the evidence. |
| `fetch_gateway_attestation` | `options: GatewayAttestationFetchOptions` | `FetchedGatewayAttestation` | Fetches Gateway evidence. The options select the signing-algorithm filter and whether to request and capture SPKI fingerprint evidence. |

`signing_algo` and `signing_address` only narrow the Cloud API response. They
do not replace `find_model_attestation_for_signature`, which performs the local,
exact signer match for a `ProviderTee` signature. The
`fetch_model_attestation_for_signature` method is the convenience form that
applies those filters and then delegates to that same selector.

### Gateway fetch options

`GatewayAttestationFetchOptions::default()` uses the Cloud API's selected
signing algorithm and requests SPKI fingerprint evidence.

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `signing_algo` | `Option<SigningAlgo>` | `None` | Optional Gateway signing-algorithm filter. Use a Gateway completion signature's algorithm when verifying that response. |
| `include_spki_fingerprint` | `bool` | `true` | When true, request Gateway SPKI fingerprint evidence and capture the peer certificate for that HTTPS request. When false, request no fingerprint and do not capture the peer. |

TLS binding requires an HTTPS endpoint. Set `include_spki_fingerprint` to
`false` for an HTTP custom endpoint.

### Evidence selection

| Function | Parameters | Returns | Description |
| --- | --- | --- | --- |
| `find_model_attestation_for_signature` | `attestations: &[ModelAttestation]`, `signature: &CompletionSignature` | `Result<&ModelAttestation, SdkError>` | Free pure function that selects the single attestation matching a `ProviderTee` signer. It does not verify evidence. |

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
| `FetchedModelAttestations` | `attestations` | Returned `Vec<ModelAttestation>`. The current client method requires exactly one item. |
|  | `client_binding` | `ModelClientBinding` returned with these attestations. |
| `FetchedModelAttestation` | `attestation` | Candidate selected for the supplied `ProviderTee` signer. |
|  | `client_binding` | `ModelClientBinding` returned with the selected attestation. |
| `FetchedGatewayAttestation` | `attestation` | Returned Gateway attestation. |
|  | `client_binding` | `GatewayClientBinding` returned with the evidence request. |
| `ModelClientBinding` | `nonce` | SDK-generated client nonce. |
| `GatewayClientBinding` | `nonce` | SDK-generated client nonce. |
|  | `spki_fingerprint` | Optional SHA-256 SPKI fingerprint observed for the exact HTTPS evidence request. It is present when `GatewayAttestationFetchOptions::include_spki_fingerprint` is true and the runtime exposes the peer certificate. |

## Attestation verification

| Function | Parameters | Returns | Description |
| --- | --- | --- | --- |
| `verify_model_attestation` | `attestation: &ModelAttestation`, `client_binding: &ModelClientBinding`, `policy: Option<&ModelAttestationPolicy>`, `verifiers: ModelAttestationVerifiers` | `VerifiedModelAttestation` | Verifies model evidence, policy, measured deployment, and GPU evidence when supplied. |
| `verify_gateway_attestation` | `attestation: &GatewayAttestation`, `client_binding: &GatewayClientBinding`, `policy: Option<&AttestationPolicy>`, `verifiers: AttestationVerifiers` | `VerifiedGatewayAttestation` | Verifies Gateway evidence. A returned Gateway SPKI fingerprint selects TLS-bound verification and requires the client-observed peer; no returned fingerprint selects signer-and-nonce verification. |

Both functions are asynchronous and return `Result<_, VerificationError>`.

Pass the matching fetch result's `client_binding`. `policy: None` uses default
TCB statuses; pass `Default::default()` as `verifiers` to use built-in quote,
deployment, and GPU verification.

When `GatewayAttestation.spki_fingerprint` is present,
`client_binding.spki_fingerprint` must be the independently observed SHA-256
SPKI fingerprint for the TLS peer that served the evidence request. Do not use
the attestation's fingerprint as the observed peer value. When the attestation
does not report an SPKI fingerprint, verification checks signer-and-nonce
report data and returns `GatewayTlsBinding::None`.

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

For a `Gateway` response, pass `GatewayAttestationFetchOptions` with
`signing_algo: Some(signature.signer.signing_algo)` to
`client.fetch_gateway_attestation`. Do not use the Cloud API default algorithm
when the response requires a specific signer.

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

### Attestation evidence

`ModelAttestation` wraps `AttestationEvidence` with optional
`reported_quote_data` and `nvidia_payload`. `GatewayAttestation` wraps
`AttestationEvidence` with a required `reported_quote_data` copy.

Optional model fields are represented as `Option<String>`: an absent value is
`None`; a supplied `nvidia_payload` is validated by the matching verifier.
Gateway `reported_quote_data` is required.

| `AttestationEvidence` field | Description |
| --- | --- |
| `nonce` | Nonce echoed by Cloud API. The client method validates it against its generated nonce. |
| `signer` | Advertised signing identity. |
| `intel_quote` | Intel TDX quote. |
| `event_log` | `AttestationEventLog::Json(String)` or `AttestationEventLog::Entries(Vec<serde_json::Value>)`, used to replay RTMR3. |
| `app_compose` | Measured compose configuration text. |

| Attestation type | Field | Description |
| --- | --- | --- |
| `ModelAttestation` | `reported_quote_data` | Optional report-data copy cross-checked against the authenticated quote. |
|  | `nvidia_payload` | Optional NVIDIA evidence payload. |
| `GatewayAttestation` | `reported_quote_data` | Required report-data copy cross-checked against the authenticated quote. |
|  | `spki_fingerprint` | Optional Gateway TLS SPKI fingerprint. Its presence selects the TLS-bound quote layout and requires a matching client-observed peer before verification returns an attested TLS binding. |

## Policies and verifier callbacks

| Type | Field | Default | Description |
| --- | --- | --- | --- |
| `ModelAttestationPolicy` | `accepted_tcb_statuses: Option<Vec<TcbStatus>>` | `UpToDate`, `OutOfDate` | Model TCB statuses accepted by verification. |
|  | `gpu_evidence: GpuEvidenceRequirement` | `IfPresent` | `IfPresent` verifies supplied GPU evidence and accepts an absent payload; `Required` rejects absent evidence. |
| `AttestationPolicy` | `accepted_tcb_statuses: Option<Vec<TcbStatus>>` | `UpToDate`, `OutOfDate` | TCB statuses accepted by verification. |
| `AttestationVerifiers<'a>` | `quote`, `deployment` | `None` | Optional `QuoteVerifier` and `DeploymentVerifier` overrides. |
| `ModelAttestationVerifiers<'a>` | `quote`, `deployment`, `nvidia` | `None` | Optional `QuoteVerifier`, `DeploymentVerifier`, and `NvidiaEvidenceVerifier` overrides. |

| Trait | Method | Contract |
| --- | --- | --- |
| `QuoteVerifier` | `async fn verify(&self, intel_quote: &str) -> Result<QuoteVerificationResult, VerificationError>` | Authenticates a quote and returns verified quote fields. |
| `DeploymentVerifier` | `async fn verify(&self, deployment: &MeasuredDeployment) -> Result<(), VerificationError>` | Returns `Ok(())` only for a deployment the application accepts. |
| `NvidiaEvidenceVerifier` | `async fn verify(&self, nvidia_payload: &str) -> Result<(), VerificationError>` | Returns `Ok(())` only for GPU evidence the application accepts. |

`TcbStatus` is one of `UpToDate`, `SwHardeningNeeded`, `ConfigurationNeeded`,
`ConfigurationAndSwHardeningNeeded`, `OutOfDate`,
`OutOfDateConfigurationNeeded`, `Revoked`, or `Unknown`.

### Built-in verifier helpers

| Export | Construction or signature | Description |
| --- | --- | --- |
| `DcapQuoteVerifier` | `DcapQuoteVerifier::default()` or `DcapQuoteVerifier::new(pccs_url)` | Built-in Intel DCAP verifier. Pass a custom PCCS base URL when needed. |
| `verify_dcap_quote` | `async fn verify_dcap_quote(pccs_url: &str, intel_quote: &str) -> Result<QuoteVerificationResult, VerificationError>` | One-off Intel DCAP verification using the supplied PCCS URL. |
| `NrasNvidiaEvidenceVerifier` | `NrasNvidiaEvidenceVerifier::default()`, `NrasNvidiaEvidenceVerifier::new(url)`, or `NrasNvidiaEvidenceVerifier::with_client(client, url)` | Built-in NVIDIA NRAS verifier. `with_client` accepts a `reqwest::Client` for caller-owned HTTP configuration. |

The default NVIDIA verifier accepts NRAS's documented boolean overall result; it
does not locally validate the returned JWT/EAT signature. See the guide for the
trust-root implications.

### Quote and deployment values

| Type | Field | Type | Description |
| --- | --- | --- | --- |
| `QuoteVerificationResult` | `tcb_status` | `TcbStatus` | Authenticated TCB status. |
|  | `advisory_ids` | `Vec<String>` | Authenticated advisory IDs. |
|  | `debug_enabled` | `bool` | Whether the authenticated quote enables debug mode. |
|  | `report_data` | `Vec<u8>` | Authenticated quote report data. |
|  | `mr_config_id` | `Vec<u8>` | Authenticated quote MRCONFIGID. |
|  | `rt_mr3` | `Vec<u8>` | Authenticated quote RTMR3. |
| `MeasuredDeployment` | `app_compose` | `String` | Configuration text bound to MRCONFIGID. |
|  | `runtime_measurements` | `RuntimeMeasurements` | Runtime measurements derived from verified event-log entries. |
| `RuntimeMeasurements` | `os_image_hash` | `Option<String>` | Optional measured OS image hash. |
|  | `compose_hash` | `Option<String>` | Optional measured compose hash. |

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
|  | `tls_binding` | `GatewayTlsBinding::Attested { spki_fingerprint }` when the quote-bound fingerprint matched the observed peer, or `GatewayTlsBinding::None` when the attestation had no SPKI fingerprint. |

## Errors

See [Handle errors](./verification-guide.md#handle-errors). The public error
surface is `ApiError`, `VerificationError`, and `SdkError`; this reference
intentionally focuses on request and verification APIs rather than enumerating
each error variant. `fetch_completion_signature` maps a valid 2xx unavailable
response to `SdkError::Api(ApiError::CompletionSignatureUnavailable {
provider_error_code, provider_message })`.
