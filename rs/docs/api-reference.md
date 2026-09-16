# Rust SDK API reference

This page lists the public Rust request and verification APIs exported by
`nearai_inference_sdk`. For workflows and complete examples, see the
[verification guide](./verification-guide.md).

## Verification lifecycle

The public APIs support three stages:

1. Fetch and verify both Gateway and model deployment evidence.
2. Send chat using the canonical model ID and retain its exact request and
   response bytes.
3. Fetch a completion signature and verify that receipt against one of the
   previously verified deployments.

Complete stage 1 before chat. `CompletionSignatureKind` matters only in stage
3: `ProviderTee` selects `verify_model_response`; `Gateway` selects
`verify_gateway_response`. It does not replace either preflight check.

For one three-stage verification operation, pass the same explicit
`SigningAlgo` to both attestation fetches and `fetch_completion_signature`.
The Gateway's report and signature endpoints have different defaults.

The current Gateway interface does not cryptographically bind both preflight
attestations to one completion or link a model signature through a Gateway
transformation. [cloud-api#986](https://github.com/nearai/cloud-api/issues/986)
tracks a complete provider-signature and Gateway-receipt chain.

## Gateway client

`AttestationClient` owns the API key, Gateway base URL, and its internal
reqwest clients. Create it once and reuse it for all signature and evidence
requests in a flow. The client only fetches evidence; it does not send
inference requests or retain completion bytes.

| Constructor | Parameters | Result | Description |
| --- | --- | --- | --- |
| `AttestationClient::new` | `api_key: String` | `AttestationClient` | Uses `DEFAULT_NEAR_AI_CLOUD_BASE_URL`. |
| `AttestationClient::with_base_url` | `api_key: String`, `base_url: &str` | `Result<AttestationClient, ApiError>` | Uses an absolute HTTP(S) base URL, such as staging. The URL may include a path prefix such as `/v1`. |

All client methods below are asynchronous and return `Result<_, ApiError>`.

| Method | Parameters after `&self` | Returns | Description |
| --- | --- | --- | --- |
| `fetch_completion_signature` | `completion_id: &str`, `signing_algo: Option<SigningAlgo>` | `CompletionSignature` | Fetches the receipt for a completed inference. A valid 2xx unavailable envelope returns `ApiError::CompletionSignatureUnavailable { .. }`, preserving the service's code and message. |
| `fetch_model_attestations` | `model: &str`, `signing_algo: Option<SigningAlgo>`, `signing_address: Option<&str>` | `FetchedModelAttestations` | Fetches every model deployment candidate returned for a canonical model ID, including an empty list. The filters only narrow the API response. |
| `fetch_gateway_attestation` | `options: GatewayAttestationFetchOptions` | `FetchedGatewayAttestation` | Fetches Gateway deployment evidence. The options select the signing-algorithm filter and whether to request and capture SPKI fingerprint evidence. |

`signing_algo` and `signing_address` only narrow the Gateway response. They
do not replace local selection from verified model results. Use
`find_model_attestation_for_signature` after verifying every fetched candidate.

When supplied, `signing_address` must be hexadecimal: 20 or 32 bytes without
`signing_algo`, or the exact length for the selected algorithm. Invalid filters
return `ApiError::InvalidInput` before a request is sent.

### Gateway fetch options

`GatewayAttestationFetchOptions::default()` uses the Gateway's selected
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
| `find_model_attestation_for_signature` | `attestations: &[VerifiedModelAttestation]`, `signature: &CompletionSignature` | `Result<&VerifiedModelAttestation, ApiError>` | Free pure function that selects the single verified result matching a `ProviderTee` signer. It does not verify the response signature. |

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
| `FetchedModelAttestations` | `attestations` | Every returned `ModelAttestation` candidate, possibly empty. Verify each item during a deployment preflight. |
|  | `client_binding` | `ModelClientBinding` returned with these attestations. |
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

## Completion receipt verification

| Function | Parameters | Returns | Description |
| --- | --- | --- | --- |
| `verify_model_response` | `request_body: &[u8]`, `response_body: &[u8]`, `signature: &CompletionSignature`, `attestation: &VerifiedModelAttestation` | `()` | Verifies a `ProviderTee` completion signature for exact bytes and matches its signer to verified model evidence. |
| `verify_gateway_response` | `request_body: &[u8]`, `response_body: &[u8]`, `signature: &CompletionSignature`, `attestation: &VerifiedGatewayAttestation` | `()` | Verifies a `Gateway` completion signature for exact bytes and matches its signer to verified Gateway evidence. |

Both functions return `Result<(), VerificationError>`. Verify both Gateway and
model deployments before sending chat, then call the function matching the
returned receipt kind. The kind selects the response signer; it does not make
the other preflight result unnecessary.

For both response functions, supply the exact request and response bytes. The
model request body must contain a non-empty JSON `model` string. The signature
kind must match the verifier (`ProviderTee` or `Gateway`), and the verified
attestation must bind the signature signer.

For a `Gateway` response, `verify_gateway_response` requires a
`VerifiedGatewayAttestation` with the same signer. For a `ProviderTee`
response, `verify_model_response` requires a `VerifiedModelAttestation` with
the same signer. Select it from the verified preflight results with
`find_model_attestation_for_signature`.

## Image build provenance

These functions are asynchronous. The low-level functions separate retrieval
from verification; the deployment helper combines them for required images.

| Function | Parameters | Returns | Description |
| --- | --- | --- | --- |
| `fetch_image_provenance` | `repository: &str`, `digest: &str`, `github_token: Option<&str>` | `Result<Vec<String>, ApiError>` | Fetches all inline GitHub attestation bundles, following pagination. `repository` is `owner/repo`; `digest` is `sha256:` plus 64 hexadecimal digits. |
| `verify_image_provenance` | `bundles: &[String]`, `digest: &str`, `policy: &ImageProvenancePolicy` | `Result<VerifiedImageProvenance, VerificationError>` | Verifies Sigstore and SLSA v1 or v0.2 provenance. At least one complete bundle must satisfy the policy. |
| `verify_deployment_image_provenance` | `app_compose: &str`, `image_policies: &BTreeMap<String, ImageProvenancePolicy>`, `github_token: Option<&str>` | `Result<(), VerificationError>` | Parses measured Compose, requires every configured image repository and verifies all matching digest-pinned references. |

The deployment helper expects outer JSON with a `docker_compose_file` YAML
string and a `services` map. YAML aliases and merge keys are supported. Policy
keys are container image repositories, not GitHub source repositories. An
optional `docker.io/` prefix is normalized on both keys and references. Every
matching reference must be `repository@sha256:<64 hex digits>` or
`repository:tag@sha256:<64 hex digits>`. The policy map must not be empty;
unlisted literal images are ignored. Any image containing `$` is rejected:
environment variables and their defaults are not resolved. Missing or null
service images are ignored. All Compose/reference checks finish before fetching.

Malformed Compose or unsupported references return
`provenance.deployment_images_invalid`, with a `DeploymentImagesFailureReason`
(`empty_policy`, `invalid_app_compose`, `invalid_docker_compose`,
`unresolved_image`, `image_missing`, or `image_not_pinned`) and optional image
repository/service details. Fetch failures become
`provenance.image_request_failed`, preserving the `ApiError` source and its
retryability. Cryptographic verification errors are returned unchanged.

`ImageProvenancePolicy::new(repository: String, workflow: String)` sets the
GitHub Actions issuer and leaves the optional ref, commit and signer identity
unset. The source repository, ref and commit are bound to the certificate's
authenticated source claims and signed SLSA statement. The optional commit pin
applies to this source commit, not a reusable workflow's commit.

| Policy field | Type | Description |
| --- | --- | --- |
| `repository` | `String` | Required GitHub source repository, such as `nearai/compose-manager`. |
| `workflow` | `String` | Required caller/source workflow path, such as `.github/workflows/build.yml`. |
| `git_ref` | `Option<String>` | Optional exact source Git ref, such as `refs/heads/master`. Serialized as `ref`. |
| `commit` | `Option<String>` | Optional full, 40-digit source commit SHA. |
| `signer_identity` | `Option<String>` | Optional exact certificate SAN URI for a reusable signing workflow, including its ref, tag or SHA. No patterns are accepted. |
| `issuer` | `String` | Expected OIDC issuer; defaults to `https://token.actions.githubusercontent.com`. |

Without `signer_identity`, the certificate signer must be the configured source
repository/workflow at the authenticated source ref. With it, only the signer
identity changes: source policy and attestation retrieval still use
`repository`, `workflow`, `git_ref` and `commit`. Source claims use the modern
Fulcio extensions, falling back to each corresponding legacy GitHub claim only
when that modern extension is absent. Malformed modern claims are rejected.

| Verified result field | Type | Description |
| --- | --- | --- |
| `digest` | `String` | Verified SHA-256 artifact digest, including its `sha256:` prefix. |
| `repository`, `workflow`, `git_ref`, `commit` | `String` | Caller/source repository, workflow, ref and commit checked against the signed statement and authenticated certificate source claims. |
| `certificate_identity`, `issuer` | `String` | Authenticated signing workflow SAN URI and OIDC issuer. The signing workflow may differ from the caller/source workflow. |
| `predicate_type` | `String` | SLSA provenance predicate URI (`v1` or `v0.2`). |

These helpers use an embedded public-good Sigstore trust root. They do not
authenticate `app_compose` themselves or run automatically during attestation
verification. Call the deployment helper from a `DeploymentVerifier` so the SDK
has already checked quote and measurement binding. No default image trust policy
is supplied, and unlisted images are not approved by the helper.

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
| `nonce` | Nonce echoed by the Gateway. The client method validates it against its generated nonce. |
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

The default NVIDIA verifier verifies NRAS's overall JWT signature, issuer,
timestamps, signed nonce, and boolean verdict. A custom NRAS URL changes where
evidence is submitted, not the trusted NVIDIA issuer or JWKS endpoint.

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

See [Handle errors](./verification-guide.md#handle-errors). Cloud retrieval
and evidence selection use `ApiError`; explicit verification uses
`VerificationError`. Handle each operation at its own boundary, so a client or
selection handler never needs to distinguish the two. This reference
intentionally focuses on request and verification APIs rather than enumerating
each error variant.
`fetch_completion_signature` maps a valid 2xx unavailable response to
`ApiError::CompletionSignatureUnavailable { .. }`. The error preserves the
service's code and message.
