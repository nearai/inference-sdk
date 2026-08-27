# TypeScript SDK API reference

This page describes the public API exported by `verification-sdk`. For
workflows and complete code examples, see the [verification guide](./verification-guide.md).

## Runtime exports

| Export | Signature or value | Purpose |
| --- | --- | --- |
| `NearAiCloudClient` | `new NearAiCloudClient(options)` | Fetches completion signatures and attestation evidence. It does not send completion requests. |
| `generateNonce` | `() => string` | Generates a cryptographically random 32-byte hexadecimal nonce. |
| `verifyModelAttestation` | `(input: VerifyModelAttestationInput) => Promise<VerifiedModelAttestation>` | Verifies model evidence. |
| `verifyModelResponse` | `(input: VerifyModelResponseInput) => void` | Verifies a `provider_tee` completion signature and its verified model evidence. |
| `verifyGatewayAttestation` | `(input: VerifyGatewayAttestationInput) => Promise<VerifiedGatewayAttestation>` | Verifies gateway evidence and a caller-observed TLS peer binding. |
| `verifyGatewayResponse` | `(input: VerifyGatewayResponseInput) => void` | Verifies a `gateway` completion signature and its verified gateway evidence. |
| `VerificationError` | `class VerificationError extends Error` | Structured base class for SDK failures. |
| `ApiError` | `class ApiError extends VerificationError` | Structured Cloud API transport or response failure. |
| `isVerificationError` | `(value: unknown) => value is VerificationError` | Type guard for SDK failures. |
| `NO_ALIASING_HEADER` | `'x-no-aliasing'` | Header name used to reject model aliases. |
| `DEFAULT_NEAR_AI_CLOUD_BASE_URL` | `'https://cloud-api.near.ai/v1'` | Default Cloud API base URL used by `NearAiCloudClient`. |

## Client

### `NearAiCloudClient`

| Constructor parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `options` | `NearAiCloudClientOptions` | Yes | Client configuration. |

#### `NearAiCloudClientOptions`

| Field | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `apiKey` | `string` | Yes | — | Bearer token for signature and evidence requests. |
| `baseUrl?` | `string` | No | `https://cloud-api.near.ai/v1` | Absolute HTTPS Cloud API base URL. Credentials, query parameters, and fragments are rejected. |
| `fetch?` | `NearAiCloudFetch` | No | Global `fetch` | Fetch-compatible transport used for the client's requests. |

`NearAiCloudFetch` accepts `(input: string | URL | Request, init?: RequestInit)`
and returns `Awaitable<Response>`. `Awaitable<T>` is `T | PromiseLike<T>`.

#### Methods

| Method | Input | Resolves to | Notable failure or behavior |
| --- | --- | --- | --- |
| `lookupCompletionSignature(input)` | `FetchCompletionSignatureInput` | `CompletionSignatureLookup` | Returns the `unavailable` variant instead of throwing when no signature is available. |
| `fetchCompletionSignature(input)` | `FetchCompletionSignatureInput` | `CompletionSignature` | Throws `signature.unavailable` when the lookup result is unavailable. |
| `fetchModelAttestation(input)` | `FetchModelAttestationInput` | `ModelAttestation` | Requires a `provider_tee` signature, exactly one NEAR model report, and a matching signer. |
| `fetchGatewayAttestation(input)` | `FetchGatewayAttestationInput` | `GatewayAttestation` | Fetches standalone gateway evidence and always requests its TLS fingerprint. |

#### Client input types

| Type | Field | Type | Required | Description |
| --- | --- | --- | --- | --- |
| `FetchCompletionSignatureInput` | `completionId` | `string` | Yes | Non-empty completion ID. |
|  | `algorithm?` | `SigningAlgorithm` | No | Algorithm to request. Omitting it requests the service default, `ecdsa`. |
| `FetchModelAttestationInput` | `model` | `string` | Yes | Non-empty canonical model ID. |
|  | `nonce` | `string` | Yes | Fresh 32-byte hexadecimal nonce. |
|  | `signature` | `CompletionSignature` | Yes | Completion signature with `kind: 'provider_tee'`. |
| `FetchGatewayAttestationInput` | `nonce` | `string` | Yes | Fresh 32-byte hexadecimal nonce. |
|  | `algorithm?` | `SigningAlgorithm` | No | Gateway signing algorithm. Omitting it requests `ed25519`; when verifying a gateway response, use its signature algorithm. This does not select a gateway instance. |

## Verification functions

| Function | Input | Returns | Description |
| --- | --- | --- | --- |
| `generateNonce()` | — | `string` | Returns a fresh 64-character hexadecimal nonce. Throws `runtime.crypto_unavailable` if secure random bytes are unavailable. |
| `verifyModelAttestation(input)` | `VerifyModelAttestationInput` | `Promise<VerifiedModelAttestation>` | Verifies model attestation evidence and optional GPU evidence. |
| `verifyModelResponse(input)` | `VerifyModelResponseInput` | `void` | Verifies the exact completion bytes, a `provider_tee` signature, and its model attestation. |
| `verifyGatewayAttestation(input)` | `VerifyGatewayAttestationInput` | `Promise<VerifiedGatewayAttestation>` | Verifies standalone gateway evidence and binds it to the caller's TLS peer fingerprint. |
| `verifyGatewayResponse(input)` | `VerifyGatewayResponseInput` | `void` | Verifies the exact completion bytes, a `gateway` signature, and its verified gateway-service signer. |

### Attestation verification inputs

| Type | Field | Type | Required | Description |
| --- | --- | --- | --- | --- |
| `VerifyModelAttestationInput` | `attestation` | `ModelAttestation` | Yes | Raw model evidence. |
|  | `nonce` | `string` | Yes | Nonce sent in the attestation request and required to match the evidence. |
|  | `policy?` | `ModelAttestationPolicy` | No | TCB and GPU evidence requirements. |
|  | `verifiers?` | `ModelAttestationVerifiers` | No | Quote, deployment, and NVIDIA verifier overrides. |
| `VerifyGatewayAttestationInput` | `attestation` | `GatewayAttestation` | Yes | Raw standalone gateway evidence. |
|  | `nonce` | `string` | Yes | Nonce sent in the attestation request and required to match the evidence. |
|  | `peerSpkiFingerprint` | `string` | Yes | 32-byte hexadecimal SHA-256 SPKI fingerprint independently observed for the TLS peer bound to this evidence. For standalone verification, use the attestation request's peer. |
|  | `policy?` | `AttestationPolicy` | No | TCB requirements. |
|  | `verifiers?` | `AttestationVerifiers` | No | Quote and deployment verifier overrides. |

`peerSpkiFingerprint` must be independently observed by the caller. Do not use
`declaredSpkiFingerprint` from the attestation as this field. The SDK compares
the peer fingerprint with quote-bound evidence; it does not prove TLS
connection reuse.

`verifyGatewayResponse` verifies gateway-service provenance and integrity for
the exact completion bytes. It matches the signature to the signer bound to
verified gateway deployment evidence; it does not establish model execution.

### Response verification inputs

| Type | Field | Type | Required | Description |
| --- | --- | --- | --- | --- |
| `VerifyModelResponseInput` | `requestBody` | `Uint8Array` | Yes | Exact bytes sent to the completion endpoint. |
|  | `responseBody` | `Uint8Array` | Yes | Exact bytes received from the completion endpoint. |
|  | `signature` | `CompletionSignature` | Yes | Signature with `kind: 'provider_tee'`. |
|  | `attestation` | `VerifiedModelAttestation` | Yes | Exact object returned by `verifyModelAttestation` in the current process. |
| `VerifyGatewayResponseInput` | `requestBody` | `Uint8Array` | Yes | Exact bytes sent to the completion endpoint. |
|  | `responseBody` | `Uint8Array` | Yes | Exact bytes received from the completion endpoint. |
|  | `signature` | `CompletionSignature` | Yes | Signature with `kind: 'gateway'`. |
|  | `attestation` | `VerifiedGatewayAttestation` | Yes | Exact object returned by `verifyGatewayAttestation` in the current process. |

## Signatures and raw evidence

### Completion signatures

| Type | Field | Type | Description |
| --- | --- | --- | --- |
| `SigningIdentity` | `algorithm` | `'ecdsa' \| 'ed25519'` | Signing algorithm. |
|  | `address` | `string` | Hexadecimal signing identity: 20 bytes for ECDSA or 32 bytes for Ed25519. |
| `CompletionSignature` | `kind` | `'provider_tee' \| 'gateway'` | Explicit Cloud API signature kind. The SDK never infers it from `signedText`. |
|  | `signedText` | `string` | Text covered by the signature. |
|  | `signature` | `string` | Hexadecimal signature: 65 bytes for ECDSA or 64 bytes for Ed25519. |
|  | `signer` | `SigningIdentity` | Signing identity that must match verified evidence. |
| `CompletionBytes` | `requestBody` | `Uint8Array` | Exact completion request bytes. |
|  | `responseBody` | `Uint8Array` | Exact completion response bytes. |

`CompletionSignatureKind` is the union `'provider_tee' | 'gateway'`.
`SigningAlgorithm` is the union `'ecdsa' | 'ed25519'`.

### Completion signature lookup

| Type or variant | Field | Type | Description |
| --- | --- | --- | --- |
| `CompletionSignatureLookup` | `status` | `'found' \| 'unavailable'` | Discriminant. |
| `CompletionSignatureLookup` when `status === 'found'` | `signature` | `CompletionSignature` | Returned completion signature. |
| `CompletionSignatureLookup` when `status === 'unavailable'` | `unavailable` | `SignatureUnavailable` | Service-provided unavailable state. |
| `SignatureUnavailable` | `errorCode` | `string` | Service error code. |
|  | `message` | `string` | Service message. |

### Attestation evidence

`AttestationEventLog` is `string | readonly unknown[]`.

| Field | Type | Description |
| --- | --- | --- |
| `nonce` | `string` | Nonce echoed by the service. |
| `signer` | `SigningIdentity` | Advertised signing identity. |
| `intelQuote` | `string` | Intel TDX quote. |
| `eventLog` | `AttestationEventLog` | Input used to replay RTMR3 measurements. |
| `appCompose` | `string` | Measured compose configuration text. |
| `declaredSpkiFingerprint?` | `string \| null` | Optional service-declared SPKI fingerprint; it is not a caller-observed TLS peer. |
| `reportedQuoteData?` | `string` | Optional report-data copy cross-checked against the authenticated quote. |

`AttestationEvidence` contains the fields above. `ModelAttestation` and
`GatewayAttestation` extend it as follows:

| Type | Additional field | Type | Required | Description |
| --- | --- | --- | --- | --- |
| `ModelAttestation` | `nvidiaPayload?` | `string \| null` | No | GPU attestation payload. |
| `GatewayAttestation` | `reportedQuoteData` | `string` | Yes | Gateway report-data copy. |

## Policies and verifier callbacks

### Policies

| Type | Field | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `AttestationPolicy` | `acceptedTcbStatuses?` | `readonly TcbStatus[]` | `['UpToDate', 'OutOfDate']` | TCB statuses accepted by verification. |
| `ModelAttestationPolicy` | `acceptedTcbStatuses?` | `readonly TcbStatus[]` | `['UpToDate', 'OutOfDate']` | TCB statuses accepted by verification. |
|  | `gpuEvidence?` | `'if-present' \| 'required'` | `'if-present'` | Whether a model report without GPU evidence is accepted. |

`TcbStatus` is one of `UpToDate`, `SWHardeningNeeded`,
`ConfigurationNeeded`, `ConfigurationAndSWHardeningNeeded`, `OutOfDate`,
`OutOfDateConfigurationNeeded`, `Revoked`, or `Unknown`.

### Verifier bags and callbacks

| Type | Field or signature | Description |
| --- | --- | --- |
| `AttestationVerifiers` | `quote?: QuoteVerifier` | Replaces the built-in Intel DCAP quote verifier. |
|  | `deployment?: DeploymentVerifier` | Applies caller-defined deployment acceptance. |
| `ModelAttestationVerifiers` | `quote?: QuoteVerifier` | Replaces the built-in Intel DCAP quote verifier. |
|  | `deployment?: DeploymentVerifier` | Applies caller-defined deployment acceptance. |
|  | `nvidia?: NvidiaEvidenceVerifier` | Replaces the built-in NVIDIA verifier. |
| `QuoteVerifier` | `(quote: string) => Awaitable<QuoteVerificationResult>` | Authenticates a quote and returns the verified quote fields. |
| `DeploymentVerifier` | `(deployment: MeasuredDeployment) => Awaitable<void>` | Resolves only for an accepted deployment. |
| `NvidiaEvidenceVerifier` | `(payload: string) => Awaitable<void>` | Resolves only for accepted GPU evidence. |

### Quote and deployment values

| Type | Field | Type | Description |
| --- | --- | --- | --- |
| `QuoteVerificationResult` | `tcbStatus` | `TcbStatus` | Authenticated TCB status. |
|  | `advisoryIds` | `readonly string[]` | Authenticated advisory IDs. |
|  | `debugEnabled` | `boolean` | Whether the authenticated quote enables debug mode. |
|  | `reportData` | `Uint8Array` | Authenticated quote report data. |
|  | `mrConfigId` | `Uint8Array` | Authenticated quote MRCONFIGID. |
|  | `rtMr3` | `Uint8Array` | Authenticated quote RTMR3. |
| `MeasuredDeployment` | `readonly appCompose` | `string` | Configuration text bound to MRCONFIGID. |
|  | `readonly runtimeMeasurements` | `RuntimeMeasurements` | Runtime measurements derived from verified event-log entries. |
| `RuntimeMeasurements` | `readonly osImageHash?` | `string` | Optional measured OS image hash. |
|  | `readonly composeHash?` | `string` | Optional measured compose hash. |

## Verified results

`VerifiedAttestationEvidence` is shared by both verified attestation results.
All fields in verified results are readonly.

| Field | Type | Description |
| --- | --- | --- |
| `signer` | `Readonly<SigningIdentity>` | Verified signing identity. |
| `tcbStatus` | `TcbStatus` | Accepted TCB status. |
| `advisoryIds` | `readonly string[]` | Quote advisory IDs. |
| `deployment` | `MeasuredDeployment` | Verified deployment measurements. |
| `deploymentProvenance` | `DeploymentProvenanceStatus` | Whether a supplied `DeploymentVerifier` accepted the deployment. |

| Type | Additional field | Type | Description |
| --- | --- | --- | --- |
| `VerifiedModelAttestation` | `tlsBinding` | `ModelTlsBinding` | Verified model TLS binding. |
|  | `gpuEvidence` | `GpuEvidenceStatus` | GPU evidence result. |
| `VerifiedGatewayAttestation` | `tlsBinding` | `GatewayTlsBinding` | Verified gateway TLS binding. |

| Alias | Definition |
| --- | --- |
| `ModelTlsBinding` | `{ kind: 'none' } \| { kind: 'declared'; spkiFingerprint: string }` |
| `GatewayTlsBinding` | `{ kind: 'peer'; spkiFingerprint: string }` |
| `GpuEvidenceStatus` | `'not_provided' \| 'verified'` |
| `DeploymentProvenanceStatus` | `'not_checked' \| 'verified'` |

`VerifiedModelAttestation` and `VerifiedGatewayAttestation` are branded,
in-memory SDK results. They cannot be reconstructed from serialized data.

## Errors

The stable error contract is `failure.code` and its typed `failure.details`.
`message` is for people and should not be parsed.

| API | Property or signature | Description |
| --- | --- | --- |
| `VerificationError` | `new (failure: VerificationFailure, options?: VerificationErrorOptions)` | Creates a structured SDK failure. |
| `VerificationError` | `failure: VerificationFailure` | Discriminated failure payload. |
|  | `code: VerificationErrorCode` | Convenience alias for `failure.code`. |
|  | `phase: VerificationPhase` | Convenience alias for `failure.phase`. |
|  | `retryable: boolean` | Whether this failure is safe for the SDK to classify as transient. |
|  | `toJSON()` | Returns `name`, `message`, `failure`, and `retryable`. |
| `ApiError` | `new (failure: ApiFailure, options?: VerificationErrorOptions)` | Creates a structured API failure. |
|  | `status: number \| undefined` | HTTP status for `api.http_status`; otherwise `undefined`. |
| `isVerificationError` | `(value: unknown) => value is VerificationError` | Narrows an unknown thrown value to the SDK error type. |
| `VerificationFailure` | Discriminated union | Every failure variant in the tables below. |
| `ApiFailure` | Extracted union | `VerificationFailure` variants whose phase is `api`. |
| `VerificationErrorCode` | Union | All `VerificationFailure['code']` values. |
| `VerificationPhase` | Union | All `VerificationFailure['phase']` values. |
| `VerificationErrorOptions` | `{ cause?: unknown }` | Optional constructor options. |

### Input and API failures

| Code | `failure.details` | Retryable |
| --- | --- | --- |
| `input.invalid` | `field`, `reason` (`missing`, `invalid_hex`, `wrong_length`, `invalid_json`, `invalid_jwt`, `invalid_url`, `invalid_header`, `unverified_attestation`, or `unsupported_value`); may include `expected`, `expectedBytes`, `actualBytes` | No |
| `api.transport_failed` | `resource` (`model_attestation`, `gateway_attestation`, or `completion_signature`), `reason` (`request` or `response_body`) | Yes |
| `api.http_status` | `resource`, `status` | Depends on status |
| `api.invalid_json` | `resource` | No |
| `api.invalid_response` | `path`, `expected`, `actual` | No |
| `api.unexpected_model_attestation_count` | `expectedCount`, `actualCount` | No |
| `api.attestation_signer_mismatch` | `resource` (`model_attestation` or `gateway_attestation`) | No |

`api.http_status` is retryable for 408, 425, 429, status `>= 500`, and a
`completion_signature` 404.

### Quote, policy, and binding failures

| Code | `failure.details` | Retryable |
| --- | --- | --- |
| `quote.collateral_unavailable` | — | Yes |
| `quote.verification_failed` | `reason` (`invalid_encoding` or `verifier_error`) | No |
| `quote.invalid_result` | `path`, `expected`, `actual` | No |
| `quote.unsupported_report_type` | `expected: 'TD10'` | No |
| `policy.debug_enabled` | — | No |
| `policy.tcb_status_not_allowed` | `actual`, `accepted`, `advisoryIds` | No |
| `policy.gpu_evidence_required` | — | No |
| `binding.nonce_mismatch` | `source` (`attestationNonce`, `quoteReportData`, or `nvidiaPayload`) | No |
| `binding.report_data_invalid` | `source` (`quoteReportData` or `reportedQuoteData`), `reason` (`invalid_hex` or `wrong_length`), `expectedBytes`, optional `actualBytes` | No |
| `binding.report_data_mismatch` | `source` (`reportedQuoteData`, `signerBinding`, or `signerTlsBinding`) | No |
| `binding.spki_fingerprint_missing` | — | No |
| `binding.spki_fingerprint_mismatch` | `source: 'peer_tls_connection'` | No |

### Measurement, GPU, signature, and runtime failures

| Code | `failure.details` | Retryable |
| --- | --- | --- |
| `measurement.event_log_invalid` | `path`, `reason` (`invalid_json`, `invalid_type`, `invalid_hex`, `wrong_length`, or `digest_mismatch`); may include `expected`, `expectedBytes`, `actualBytes` | No |
| `measurement.rtmr3_mismatch` | `reason` (`wrong_length`, `no_events`, or `replay_mismatch`); may include `expectedBytes`, `actualBytes` | No |
| `measurement.app_compose_invalid` | `reason` (`invalid_json` or `missing`) | No |
| `measurement.mrconfigid_invalid` | `reason` (`wrong_length` or `unsupported_version`); may include `minimumBytes`, `actualBytes`, `version` | No |
| `measurement.app_compose_mrconfigid_mismatch` | — | No |
| `gpu.payload_invalid` | `reason` (`invalid_json` or `nonce_missing`) | No |
| `gpu.nras_request_failed` | `reason` (`timeout`, `transport`, or `http_status`), optional `status` | Depends on NRAS response |
| `gpu.nras_response_invalid` | `reason` (`invalid_json`, `invalid_jwt`, `invalid_schema`, or `invalid_verdict_type`) | No |
| `gpu.attestation_rejected` | `source` (`nras` or `custom_verifier`) | No |
| `provenance.verification_failed` | — | No |
| `signature.unavailable` | `providerErrorCode` | No |
| `signature.kind_mismatch` | `expected`, `actual` (`provider_tee` or `gateway`) | No |
| `signature.payload_mismatch` | `source` (`request_model` or `signed_payload`), `reason` (`invalid_json`, `missing_model`, or `text_mismatch`) | No |
| `signature.format_invalid` | `field` (`signature`, `signer.address`, or `signer.algorithm`), `reason` (`invalid_hex`, `wrong_length`, or `unsupported_algorithm`); may include `expectedBytes`, `actualBytes` | No |
| `signature.invalid` | `algorithm` (`ecdsa` or `ed25519`) | No |
| `signature.signer_mismatch` | — | No |
| `runtime.crypto_unavailable` | `capability` (`subtle_digest` or `secure_random`) | No |
