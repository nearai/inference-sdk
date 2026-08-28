# Rust verification guide

Use this SDK to verify NEAR AI Cloud deployment attestations and completion
signatures. It does not send inference requests: the application retains the
exact request and response bytes, then supplies them to the response verifier.

## Completion signature kinds

`fetch_completion_signature` exposes Cloud API's `signature_kind` as
`CompletionSignature.kind`. It selects the verification path and the resulting
trust guarantee, not merely the key that signed.

| `signature.kind` | Trust boundary | A successful response verification establishes | It does not establish |
| --- | --- | --- | --- |
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

| Goal | SDK calls | A successful result establishes | It does not establish |
| --- | --- | --- | --- |
| Audit a model deployment | `fetch_model_attestations` → `verify_model_attestation` | The model quote, nonce, signer, measurements, and configured policy checks passed. | That a particular response came from this deployment or that the client connected directly to its CVM. |
| Audit a Gateway endpoint | `fetch_gateway_attestation` → `verify_gateway_attestation` | The Gateway quote, deployment evidence, and quote-bound TLS identity passed. By default, the observed TLS peer also matched. | That a particular completion was served by that Gateway or that a model executed it. |
| Verify a model-issued response | `fetch_completion_signature` → `fetch_model_attestations` → `find_model_attestation_for_signature` → `verify_model_attestation` → `verify_model_response` | A verified model TEE signer signed the exact request and response bytes. | The Gateway deployment or TLS endpoint. |
| Verify a Gateway-issued response | `fetch_completion_signature` → `GatewayAttestationRequest::new(api_key).signing_algo(signature.signer.signing_algo).send()` → `verify_gateway_attestation` → `verify_gateway_response` | A verified Gateway signer signed the exact client-visible request and response bytes. | That an attested model executed or generated the response. |

`fetch_model_attestations` returns `FetchedModelAttestations`, preserving the
Cloud API `model_attestations` field. The SDK currently requires exactly one
candidate. For a deployment audit, verify its sole item with the returned
nonce. Use `find_model_attestation_for_signature` only when a `ProviderTee`
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
    fetch_completion_signature,
    find_model_attestation_for_signature, verify_model_attestation,
    verify_model_response, CompletionSignatureKind, CompletionSignatureReference,
    ModelAttestationsRequest,
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
    let model_evidence = ModelAttestationsRequest::new(api_key, model)
        .signing_algo(signature.signer.signing_algo)
        .signing_address(&signature.signer.signing_address)
        .send()
        .await?;
    let attestation = find_model_attestation_for_signature(
        &model_evidence.attestations,
        &signature_reference,
    )?;
    let verified_attestation = verify_model_attestation(
        attestation,
        &model_evidence.nonce,
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
the deployment. A declared model SPKI fingerprint is not proof of a direct
client-to-model TLS connection.

## Verify a Gateway attestation or response

For an independent Gateway endpoint audit, `fetch_gateway_attestation` requests
the Gateway's TLS fingerprint with its default Ed25519 signing algorithm. It
configures reqwest to expose the leaf certificate for that exact HTTPS request,
then returns the certificate's SHA-256 SPKI fingerprint with the fresh nonce in
`FetchedGatewayAttestation.client_binding`.

`verify_gateway_attestation` requires that observed peer fingerprint by
default. It verifies the quote's nonce and declared TLS identity, then compares
the declared key with the client-observed peer. Do not replace the observed
peer fingerprint with the declaration inside the attestation: that would only
compare the evidence with itself.

For a `CompletionSignatureKind::Gateway` response, use
`GatewayAttestationRequest` with `signature.signer.signing_algo`; do not rely on
the standalone helper's Ed25519 default:

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
        None,
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

If a runtime does not expose the TLS peer certificate, it must opt out
explicitly. This still verifies the nonce and the quote-bound TLS identity, but
does not compare a peer fingerprint and returns `GatewayTlsBinding::Attested`.
When peer binding is disabled, a supplied peer fingerprint is ignored.

```rust,no_run
use verifiable_ai_sdk::{
    fetch_gateway_attestation, verify_gateway_attestation, GatewayAttestationPolicy,
};

async fn verify_without_a_tls_peer(api_key: &str) -> Result<(), Box<dyn std::error::Error>> {
    let fetched = fetch_gateway_attestation(api_key).await?;
    let policy = GatewayAttestationPolicy {
        verify_peer_tls_binding: false,
        ..Default::default()
    };
    let _verified = verify_gateway_attestation(
        &fetched.attestation,
        &fetched.client_binding,
        Some(&policy),
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

`GatewayAttestationPolicy::verify_peer_tls_binding` defaults to `true`. Set it
to `false` only for a runtime that cannot obtain the peer certificate for the
Gateway evidence request.

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
