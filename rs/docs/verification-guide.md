# Rust verification guide

Use this SDK to verify NEAR AI Cloud deployment attestations and completion
signatures. It does not send inference requests: the application retains the
exact request and response bytes, then supplies them to the response verifier.

## Completion signature kinds

`fetch_completion_signature` exposes Cloud API's `signature_kind` as
`CompletionSignature.kind`. It selects the verification path and the resulting
trust guarantee, not merely the key that signed.

| `signature.kind` | Trust boundary | A successful response verification establishes | It does not establish |
| --- | --- | --- | --- | --- |
| `ProviderTee` | The model-serving TEE | A verified model TEE signer signed the exact request and response bytes. | The Cloud API Gateway deployment or TLS identity. |
| `Gateway` | The NEAR AI Cloud Gateway TEE | A verified Gateway signer signed the exact client-visible request and response bytes. | That an attested model executed or generated the response. |

Cloud API can return a `Gateway` signature when it rewrites the response before
returning it, such as when it normalizes a stream for OpenAI compatibility. A
byte-exact provider signature would not verify the rewritten bytes. Always use
the kind returned for that completion; a `Gateway` signature is not evidence of
model execution.

## Choose what to verify

Both attestation kinds can be verified independently. A completion signature is
needed only when the claim concerns one particular response.

| Goal | Use it when | SDK calls | A successful result establishes | It does not establish |
| --- | --- | --- | --- |
| Audit a model deployment | You want to inspect a model-serving CVM's TCB status, measurements, GPU evidence, or deployment configuration. | `fetch_model_attestations` → `verify_model_attestation` | The model quote, nonce, signer, measurements, and configured policy checks passed. | That a particular response came from this deployment or that the client connected directly to its CVM. |
| Audit a Gateway endpoint | You want to inspect a Cloud API Gateway deployment and, by default, its TLS service identity. | `fetch_gateway_attestation` → `verify_gateway_attestation` | The Gateway quote and deployment evidence are verified. With the default TLS policy, the observed TLS peer also matches the fingerprint bound into the quote. | That a particular completion was served by that Gateway or that a model executed it. |
| Verify a model-issued response | The completion signature has `ProviderTee` kind. | `fetch_completion_signature` → `fetch_model_attestations` → `find_model_attestation_for_signature` → `verify_model_attestation` → `verify_model_response` | A verified model TEE signer signed the exact request and response bytes. | The Gateway deployment or TLS endpoint. |
| Verify a Gateway-issued response | The completion signature has `Gateway` kind. | `fetch_completion_signature` → `GatewayAttestationRequest::new(api_key).signing_algo(signature.signer.signing_algo).send()` → `verify_gateway_attestation` → `verify_gateway_response` | A verified Gateway signer signed the exact client-visible request and response bytes. | That an attested model executed or generated the response. |

`fetch_model_attestations` returns `FetchedModelAttestations`, preserving the
Cloud API `model_attestations` field. The SDK currently requires exactly one
candidate. For a deployment audit, verify its sole item with the returned
`client_binding`. Use `find_model_attestation_for_signature` only when a `ProviderTee`
signature must select matching evidence.

For all constructors, functions, policies, and result types, see the
[API reference](./api-reference.md).

## Verify a model response

Use this path only for `CompletionSignatureKind::ProviderTee`.

The SDK does not send inference requests. Before this flow, your application
must have sent a completion with `x-no-aliasing: true` using a canonical model
ID, then retained that model ID, the completion ID, and the exact request and
response bytes. Do not parse and serialize those bytes again: changing JSON
whitespace, key ordering, framing, or encoding changes the signed bytes.

```rust,no_run
use verifiable_ai_sdk::{
    fetch_completion_signature, fetch_model_attestations,
    find_model_attestation_for_signature, verify_model_attestation,
    verify_model_response, CompletionSignatureKind, CompletionSignatureReference,
};

async fn verify_model_completion(
    api_key: &str,
    model: &str,
    completion_id: &str,
    request_body: &[u8],
    response_body: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let signature = fetch_completion_signature(api_key, completion_id).await?;
    if signature.kind != CompletionSignatureKind::ProviderTee {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "this completion requires the Gateway flow",
        )
        .into());
    }

    let signature_reference = CompletionSignatureReference {
        kind: signature.kind,
        signer: signature.signer.clone(),
    };
    let model_evidence = fetch_model_attestations(api_key, model).await?;
    let attestation = find_model_attestation_for_signature(
        &model_evidence.attestations,
        &signature_reference,
    )?;
    let verified_attestation = verify_model_attestation(
        attestation,
        &model_evidence.client_binding,
        None,
        Default::default(),
    )
    .await?;

    verify_model_response(
        request_body,
        response_body,
        &signature,
        &verified_attestation,
    )?;
    Ok(())
}
```

After `verify_model_response` succeeds, the model signature is valid for the
exact request and response bytes, and its identity matches the verified model
evidence. It does not repeat quote, policy, or deployment verification, so
call `verify_model_attestation` first.

`verify_model_attestation` checks the nonce, Intel TDX quote, TCB policy,
runtime measurements, model signer, and supplied GPU evidence. Its result
includes the verified signer, TCB status and advisory IDs, measured deployment,
GPU-evidence status, and whether a caller-supplied deployment verifier accepted
the deployment.

Model fetches always request `include_tls_fingerprint=false`. Cloud API
connects to the model on the client's behalf, so model verification checks the
signer-and-nonce quote layout but does not establish a client-to-model TLS
binding.

`ModelAttestationsRequest::signing_algo` and `signing_address` are optional
Cloud API request filters. They can narrow the response, but they do not
replace `find_model_attestation_for_signature`, which performs the authoritative
local match against the `ProviderTee` signature signer.

## Verify a Gateway attestation or response

For an independent Gateway endpoint audit, `fetch_gateway_attestation` requests
the Gateway's TLS fingerprint using the Cloud API default signing algorithm. It
configures reqwest to expose the leaf certificate for that exact HTTPS request,
then returns the certificate's SHA-256 SPKI fingerprint with the fresh nonce in
`FetchedGatewayAttestation.client_binding`.

`verify_gateway_attestation` requires that observed peer fingerprint by
default. It verifies the quote's nonce and TLS binding, then compares the
quote-bound key with the client-observed peer. Do not replace the observed peer
fingerprint with the field inside the attestation: that would only compare the
evidence with itself.

For a `CompletionSignatureKind::Gateway` response, use
`GatewayAttestationRequest` with `signature.signer.signing_algo`; do not rely on
the standalone helper's service-selected signer:

```rust,no_run
use verifiable_ai_sdk::{
    fetch_completion_signature, verify_gateway_attestation, verify_gateway_response,
    CompletionSignatureKind, GatewayAttestationRequest,
};

async fn verify_gateway_completion(
    api_key: &str,
    completion_id: &str,
    request_body: &[u8],
    response_body: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let signature = fetch_completion_signature(api_key, completion_id).await?;
    if signature.kind != CompletionSignatureKind::Gateway {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "this completion requires the model flow",
        )
        .into());
    }

    let fetched = GatewayAttestationRequest::new(api_key)
        .signing_algo(signature.signer.signing_algo)
        .send()
        .await?;
    let verified_attestation = verify_gateway_attestation(
        &fetched.attestation,
        &fetched.client_binding,
        Some(&fetched.policy),
        Default::default(),
    )
    .await?;

    verify_gateway_response(
        request_body,
        response_body,
        &signature,
        &verified_attestation,
    )?;
    Ok(())
}
```

If a runtime does not expose the TLS peer certificate, it must opt out before
fetching the evidence. The policy controls both the request's
`include_tls_fingerprint` value and the quote layout checked later. With TLS
binding disabled, the SDK requests no fingerprint, verifies the signer-and-
nonce layout, returns `GatewayTlsBinding::None`, and ignores a supplied peer
fingerprint.

```rust,no_run
use verifiable_ai_sdk::{
    verify_gateway_attestation, GatewayAttestationPolicy, GatewayAttestationRequest,
};

async fn verify_without_a_tls_peer(api_key: &str) -> Result<(), Box<dyn std::error::Error>> {
    let policy = GatewayAttestationPolicy {
        verify_tls_binding: false,
        ..Default::default()
    };
    let fetched = GatewayAttestationRequest::new(api_key)
        .policy(policy)
        .send()
        .await?;
    let _verified = verify_gateway_attestation(
        &fetched.attestation,
        &fetched.client_binding,
        Some(&fetched.policy),
        Default::default(),
    )
    .await?;
    Ok(())
}
```

This verifies Gateway-service provenance and integrity for those bytes; it does
not establish model execution.

## Policy and trust roots

The default policy accepts `TcbStatus::UpToDate` and `TcbStatus::OutOfDate`.
Model GPU evidence is verified when supplied; reports without it are accepted
by default. Set `ModelAttestationPolicy { gpu_evidence:
GpuEvidenceRequirement::Required, ..Default::default() }` when GPU evidence is
mandatory.

`GatewayAttestationPolicy::verify_tls_binding` defaults to `true`. Set it to
`false` only for a runtime that cannot obtain the peer certificate for the
Gateway evidence request. Pass the same policy to `GatewayAttestationRequest`
that is later passed to verification; `FetchedGatewayAttestation.policy`
contains the resolved value for that request.

`AttestationVerifiers` and `ModelAttestationVerifiers` accept caller-owned
quote, deployment, and (for models) NVIDIA evidence verifiers. A supplied
verifier must return `Ok` only for evidence it accepts. The built-in Intel
verifier retrieves DCAP collateral from PCCS. The default NVIDIA verifier sends
supplied GPU evidence to NRAS and accepts its documented boolean overall
result; it does not locally validate the returned JWT/EAT signature.

## Handle errors

Cloud request and evidence-selection helpers return `Result<T, SdkError>`.
`SdkError::Api(ApiError)` represents a Cloud API request, response, nonce, or
candidate-selection failure. `SdkError::Verification(VerificationError)`
represents local input validation or verification that arose while preparing a
Cloud request. Attestation and response verification functions return
`VerificationError` directly.

Match an error enum variant when practical. `ApiError::code()` and
`VerificationError::code()` provide stable machine-readable codes; the enum
fields contain code-specific diagnostic details. Display text is for people and
must not be parsed. `retryable()` means a new attempt at the failed external
operation may succeed. It does not mean that re-verifying the same evidence
will succeed or that an inference request should be replayed.

`fetch_completion_signature` is the strict path: it returns a signature or an
`SdkError::Api(ApiError::CompletionSignatureUnavailable { .. })` with code
`api.completion_signature_unavailable` when Cloud API returns a valid 2xx
unavailable envelope. Use `lookup_completion_signature` when that unavailable
state is normal application control flow:

```rust,no_run
use verifiable_ai_sdk::{
    fetch_completion_signature, lookup_completion_signature, ApiError,
    CompletionSignatureLookup, SdkError,
};

async fn look_up_completion_signature(
    api_key: &str,
    completion_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    match lookup_completion_signature(api_key, completion_id).await? {
        CompletionSignatureLookup::Found(_signature) => {}
        CompletionSignatureLookup::Unavailable(unavailable) => {
            eprintln!("signature unavailable: {}", unavailable.error_code);
        }
    }

    if let Err(SdkError::Api(error)) = fetch_completion_signature(api_key, completion_id).await {
        match error {
            ApiError::CompletionSignatureUnavailable { provider_error_code } => {
                eprintln!("no usable signature: {provider_error_code}");
            }
            error => {
                if error.retryable() {
                    eprintln!("a later signature lookup may succeed");
                } else {
                    return Err(error.into());
                }
            }
        }
    }
    Ok(())
}
```

A `completion_signature` HTTP 404 is retryable, including when the signature
is still being recorded or is unknown. A valid 2xx unavailable envelope is an
ordinary `CompletionSignatureLookup::Unavailable` result only through the
non-strict helper.
