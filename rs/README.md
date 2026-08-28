# verification-sdk (Rust)

`verification-sdk` verifies NEAR AI Cloud attestation evidence and completion
signatures. It keeps Cloud API retrieval separate from local verification:

- fetch raw evidence and completion signatures with the Cloud API helpers;
- verify model or Gateway deployment evidence; and
- verify exact completion request and response bytes against verified evidence.

## Choose the verification path

Cloud API returns a `signature_kind` with each completion signature. Do not
infer it from the signed text.

| Signature kind | Verify with | A successful response check establishes |
| --- | --- | --- |
| `provider_tee` | `verify_model_attestation` and `verify_model_response` | The verified model TEE signer signed the exact request and response bytes. |
| `gateway` | `verify_gateway_attestation` and `verify_gateway_response` | The verified Gateway signer signed the exact client-visible request and response bytes. |

Model and Gateway attestations are also useful on their own when the goal is
to audit a deployment rather than bind a particular completion to its signer.

## Using the evidence

Keep the bytes sent to and returned by the completion endpoint unchanged. The
SDK hashes those exact bytes, including JSON formatting and stream framing.

1. To audit a model deployment, call `fetch_model_attestations`, select a
   candidate if needed, and pass its returned nonce to
   `verify_model_attestation`.
2. To verify a model-generated completion, fetch its signature, require
   `ProviderTee`, select matching model evidence, verify it, then call
   `verify_model_response` with the original request and response bytes.
3. To audit a Gateway endpoint, fetch its evidence and pass it with an
   independently observed TLS peer SPKI fingerprint to
   `verify_gateway_attestation`.
4. To verify a Gateway-signed completion, require `Gateway`, verify Gateway
   evidence, then call `verify_gateway_response` with the original bytes.

Each evidence fetch creates a fresh nonce and checks the service's echoed
nonce. Model verification checks the Intel quote, accepted TCB status,
quote report-data binding, RTMR3 event-log replay, MRCONFIGID/app-compose
binding, and GPU evidence when supplied. The default policy accepts
`UpToDate` and `OutOfDate` TCB statuses and treats missing or `null` GPU
evidence as not provided. Use `ModelAttestationPolicy` with
`GpuEvidenceRequirement::Required` when GPU evidence is mandatory.

## Gateway flow

Use `fetch_gateway_attestation` and `verify_gateway_attestation` for a
Gateway deployment. `verify_gateway_attestation` requires the SHA-256 SPKI
fingerprint independently observed from the TLS peer for the attestation
request. Do not use the fingerprint declared inside the attestation as that
observed value. The built-in reqwest transport preserves its normal behavior
and returns `None` for `FetchedGatewayAttestation.peer_spki_fingerprint`.
To make the TLS binding claim, configure `NearAiCloudOptions::with_transport`
with a TLS-aware transport. It must attach the fingerprint observed for that
exact request in `NearAiCloudResponse.peer_spki_fingerprint`; the fetch result
then carries the normalized value for `verify_gateway_attestation`.

For a `gateway` completion signature, verify that Gateway evidence first and
then call `verify_gateway_response` with the same exact completion bytes.
This establishes Gateway-service provenance for the bytes; it does not prove
that a model TEE generated them.

## Public API

| Area | Main exports |
| --- | --- |
| Cloud API | `NearAiCloudOptions`, `NearAiCloudTransport`, `lookup_completion_signature`, `fetch_completion_signature`, `fetch_model_attestations`, `find_model_attestation_for_signature`, `fetch_model_attestation_for_signature`, `fetch_gateway_attestation` |
| Deployment verification | `verify_model_attestation`, `verify_gateway_attestation`, `DcapQuoteVerifier`, `NrasNvidiaEvidenceVerifier` |
| Response verification | `verify_model_response`, `verify_gateway_response` |
| Policies and custom trust | `AttestationPolicy`, `ModelAttestationPolicy`, `QuoteVerifier`, `DeploymentVerifier`, `NvidiaEvidenceVerifier` |
| Structured errors | `ApiError`, `VerificationError`, `SdkError` |

Configuration and local input errors return `VerificationError`; Cloud fetch
helpers return `SdkError` because a request can fail locally or at the API.
Verification functions return `VerificationError`. Match error variants or use
`code()` and `retryable()` instead of parsing display strings.

The default Intel quote verifier retrieves collateral from PCCS, and the
default NVIDIA verifier submits supplied GPU evidence to NRAS. Supply custom
`QuoteVerifier`, `DeploymentVerifier`, or `NvidiaEvidenceVerifier`
implementations when your application owns those trust roots or needs fully
deterministic verification.
