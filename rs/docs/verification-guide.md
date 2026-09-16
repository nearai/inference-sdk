# Rust verification guide

Use this SDK to verify NEAR AI Cloud deployments before requesting inference,
then verify the receipt returned for a particular completion. The SDK does not
send inference requests itself: your application keeps the exact request and
response bytes and supplies them to the response verifier.

## Recommended flow

Treat deployment verification and response verification as separate stages.

| Stage | SDK calls | What it establishes |
| --- | --- | --- |
| Verify deployments | `fetch_gateway_attestation` → `verify_gateway_attestation`; `fetch_model_attestations` → `verify_model_attestation` | The Gateway and every returned model deployment satisfy their quote, policy, measurement, and signer checks; Gateway verification includes TLS peer binding by default. |
| Send chat | Your HTTP client | A request naming the canonical model ID used during preflight. Retain the exact request and response bytes. |
| Verify the completion receipt | `fetch_completion_signature` → response verifier selected by `signature.kind` | The exact bytes were signed by the corresponding verified signer. |

Complete both deployment checks before sending chat. The Gateway may return zero
or more model-attestation candidates: reject an empty preflight and verify every
returned candidate. Retain their verified results for the final stage rather
than fetching new attestations after the completion.
Use a canonical model ID and send `x-no-aliasing: true` with the completion
request so the preflight model and request name the same deployment.

## Verify Gateway and model deployments

This example explicitly selects `SigningAlgo::Ecdsa` for all evidence and
signature requests. Pass the same explicit algorithm to both attestation
fetches and the completion-signature fetch: the Gateway's report and signature
endpoints have different defaults. The APIs also accept `None` for individual
calls, but omitting the algorithm is not suitable for this three-stage flow.

```rust,no_run
use verifiable_ai_sdk::{
    verify_gateway_attestation, verify_model_attestation, AttestationClient,
    GatewayAttestationFetchOptions, SigningAlgo, VerifiedGatewayAttestation,
    VerifiedModelAttestation,
};

const MODEL: &str = "z-ai/glm-5.3-flash";

async fn verify_deployments(
    client: &AttestationClient,
) -> Result<
    (
        VerifiedGatewayAttestation,
        Vec<VerifiedModelAttestation>,
    ),
    Box<dyn std::error::Error>,
> {
    let fetched_gateway = client
        .fetch_gateway_attestation(GatewayAttestationFetchOptions {
            signing_algo: Some(SigningAlgo::Ecdsa),
            ..Default::default()
        })
        .await?;
    let verified_gateway = verify_gateway_attestation(
        &fetched_gateway.attestation,
        &fetched_gateway.client_binding,
        None,
        Default::default(),
    )
    .await?;

    let fetched_models = client
        .fetch_model_attestations(MODEL, Some(SigningAlgo::Ecdsa), None)
        .await?;
    if fetched_models.attestations.is_empty() {
        return Err(std::io::Error::other("Gateway returned no model attestations").into());
    }

    let mut verified = Vec::with_capacity(fetched_models.attestations.len());
    for attestation in &fetched_models.attestations {
        verified.push(
            verify_model_attestation(
                attestation,
                &fetched_models.client_binding,
                None,
                Default::default(),
            )
            .await?,
        );
    }

    Ok((
        verified_gateway,
        verified,
    ))
}
```

Gateway fetches request a TLS SPKI fingerprint by default. The Rust client
captures the certificate peer for that same HTTPS evidence request, and
`verify_gateway_attestation` verifies the quote-bound fingerprint against it.
If the runtime cannot expose the TLS peer certificate, set
`include_spki_fingerprint: false` before fetching. That verifies the Gateway
quote's signer-and-nonce layout but makes no TLS identity claim.

Model fetches always request `include_tls_fingerprint=false`: the Gateway
connects to the model on the client's behalf, so a client cannot make a direct
model TLS binding.

## Send chat

After both preflight checks succeed, send the completion with the canonical
model ID and retain the original bytes. For streaming responses, retain the
original SSE bytes, including framing; do not parse and serialize them again.

## Verify the completion receipt

Fetch the completion signature after the chat request completes. The only part
of this stage that depends on `signature.kind` is the response verifier:

```rust,no_run
use verifiable_ai_sdk::{
    find_model_attestation_for_signature, verify_gateway_response,
    verify_model_response, AttestationClient, CompletionSignature,
    CompletionSignatureKind, SigningAlgo, VerifiedGatewayAttestation,
    VerifiedModelAttestation,
};

async fn verify_completion_receipt(
    client: &AttestationClient,
    completion_id: &str,
    request_body: &[u8],
    response_body: &[u8],
    gateway: &VerifiedGatewayAttestation,
    models: &[VerifiedModelAttestation],
) -> Result<(), Box<dyn std::error::Error>> {
    let signature = client
        .fetch_completion_signature(completion_id, Some(SigningAlgo::Ecdsa))
        .await?;

    match signature.kind {
        CompletionSignatureKind::ProviderTee => {
            let model = find_model_attestation_for_signature(models, &signature)?;
            verify_model_response(request_body, response_body, &signature, model)?;
        }
        CompletionSignatureKind::Gateway => {
            verify_gateway_response(request_body, response_body, &signature, gateway)?;
        }
    }
    Ok(())
}
```

`ProviderTee` proves that one preflight-verified model signer signed the exact
request and response bytes. Use `find_model_attestation_for_signature` to
require exactly one verified result for that signer. `Gateway` proves that the preflight-verified
Gateway signer signed the exact client-visible bytes. It is not a choice
between doing model verification and Gateway verification: both were completed
before chat. The kind only determines which signer issued this completion's
receipt.

## Evidence currently available

The preflight attestations and receipt answer complementary questions:

| Evidence | It proves | It does not prove |
| --- | --- | --- |
| Verified Gateway attestation | A Gateway deployment met the configured quote, policy, and optional TLS binding checks. | That this Gateway processed a particular completion. |
| Verified model attestation | A model-serving deployment met the configured quote, policy, signer, and GPU-evidence checks. | That this model produced a particular completion. |
| `ProviderTee` receipt | The verified model signer signed these exact bytes. | Gateway deployment or TLS provenance. |
| `Gateway` receipt | The verified Gateway signer signed these exact client-visible bytes. | That an attested model produced those bytes. |

The Gateway currently returns one response signature, not a cryptographically
linked provider signature and Gateway receipt. As a result, independently
verified preflight evidence plus one current receipt does not prove a complete
model → Gateway → final-response chain for a particular inference.
[cloud-api#986](https://github.com/nearai/cloud-api/issues/986) tracks the
planned evidence model for that chain. Do not infer it from matching model
names, timestamps, signing algorithms, or the signature kind.

## Policy and trust roots

The default policy accepts `TcbStatus::UpToDate` and `TcbStatus::OutOfDate`.
Model GPU evidence is verified when supplied; reports without it are accepted
by default. Set `ModelAttestationPolicy { gpu_evidence:
GpuEvidenceRequirement::Required, ..Default::default() }` when GPU evidence is
mandatory.

`AttestationVerifiers` and `ModelAttestationVerifiers` accept caller-owned
quote, deployment, and—for models—NVIDIA evidence verifiers. A supplied
verifier must return `Ok` only for evidence it accepts. The built-in Intel
verifier retrieves DCAP collateral from PCCS. The default NVIDIA verifier submits
evidence to NRAS, then verifies the overall JWT's ES384 signature against NVIDIA's
JWKS, issuer, expiration, not-before and issued-at times, and signed `eat_nonce`.
The overall verdict must be `true`; detached per-device claims are not consumed.
See [NVIDIA's claims reference](https://docs.nvidia.com/attestation/advanced-documentation/latest/claims-guide/gpu_claims.html).

## Verify an image's build provenance

Image provenance is optional. Use a digest from a verified deployment's
`app_compose` and choose the GitHub repository and workflow your application
trusts. Do not treat a compose variable's default image as the resolved image
when its value may be overridden.

```rust,no_run
use verifiable_ai_sdk::{
    fetch_image_provenance, verify_image_provenance, ImageProvenancePolicy,
    VerifiedImageProvenance,
};

async fn verify_image(
    digest: &str,
) -> Result<VerifiedImageProvenance, Box<dyn std::error::Error>> {
    let mut policy = ImageProvenancePolicy::new(
        "nearai/compose-manager".to_owned(),
        ".github/workflows/build.yml".to_owned(),
    );
    policy.git_ref = Some("refs/heads/master".to_owned());
    // Set policy.commit as well when your application approves one source commit.
    let bundles = fetch_image_provenance(&policy.repository, digest, None).await?;
    let provenance = verify_image_provenance(&bundles, digest, &policy).await?;
    Ok(provenance)
}
```

The verifier accepts a bundle only after its Sigstore signature, certificate,
transparency-log evidence, artifact digest and signed SLSA source identity pass.
The SLSA source commit must match the certificate's authenticated source digest,
even without `policy.commit`; that optional pin must then match the same commit.
It tries every supplied bundle until one satisfies the policy. Fetching uses
GitHub's public API; supply an optional GitHub token for authenticated rate
limits. It is not a Gateway API key.

Verification uses `sigstore-verify`'s embedded Sigstore public-good trust-root
snapshot, without a runtime trust-root download. Keep the dependency updated
when Sigstore rotates trust material. This verifies build provenance, not
reproducibility, all deployment images, or the software currently serving a
model. Attestation verification does not call these helpers automatically.

To check required images from measured Compose, call
`verify_deployment_image_provenance` in your `DeploymentVerifier`:

```rust,no_run
use std::collections::BTreeMap;
use async_trait::async_trait;
use verifiable_ai_sdk::{
    verify_deployment_image_provenance, DeploymentVerifier,
    ImageProvenancePolicy, MeasuredDeployment, VerificationError,
};

struct ApprovedImages(BTreeMap<String, ImageProvenancePolicy>);

#[async_trait]
impl DeploymentVerifier for ApprovedImages {
    async fn verify(&self, deployment: &MeasuredDeployment) -> Result<(), VerificationError> {
        verify_deployment_image_provenance(&deployment.app_compose, &self.0, None).await
    }
}
```

Populate the nonempty map with container image repository keys and your own
GitHub build policies, then pass this verifier through
`AttestationVerifiers.deployment` or `ModelAttestationVerifiers.deployment`.
The SDK checks the quote and Compose measurement binding before calling it.
Every configured repository is required, and every matching reference must
include a SHA-256 digest (a tag alongside the digest is allowed). Unlisted
literal images are ignored; any unresolved `$` image reference is rejected,
including defaults. This checks only images in the measured Compose, not model
runtime images loaded later by a launcher or another service.

## Handle errors

Cloud client methods and evidence selection return `Result<T, ApiError>`.
That includes client configuration and input errors, such as an invalid custom
base URL, an API key that cannot be used in an HTTP header, or a non-provider
signature passed to model-evidence selection. These helpers retrieve or select
evidence; they do not verify it. Attestation and response verification
functions return `VerificationError` directly. Keep the boundaries separate:
client and selection code only handles `ApiError`, while explicit verification
code only handles `VerificationError`.

At either boundary, match the relevant error enum variant when practical. Its
`code()` provides a stable machine-readable code, and enum fields contain
code-specific diagnostic details. Display text is for people and must not be
parsed. `retryable()` means a new attempt at the failed external operation may
succeed. It does not mean that re-verifying the same evidence will succeed or
that an inference request should be replayed.

`AttestationClient::fetch_completion_signature` returns a signature or an
`ApiError::CompletionSignatureUnavailable { .. }` with code
`api.completion_signature_unavailable` when the Gateway returns a valid 2xx
unavailable envelope. The error preserves the service's
`provider_error_code` and `provider_message`.

```rust,no_run
use verifiable_ai_sdk::{ApiError, AttestationClient};

async fn fetch_completion_signature(
    api_key: &str,
    completion_id: &str,
) -> Result<(), ApiError> {
    let client = AttestationClient::new(api_key.to_owned());
    match client.fetch_completion_signature(completion_id, None).await {
        Ok(_signature) => {}
        Err(ApiError::CompletionSignatureUnavailable {
            provider_error_code,
            provider_message,
        }) => {
            eprintln!("no usable signature ({provider_error_code}): {provider_message}");
        }
        Err(error) if error.retryable() => {
            eprintln!("the signature request may succeed on a later attempt");
        }
        Err(error) => return Err(error),
    }
    Ok(())
}
```

A completion-signature HTTP 404 is classified as retryable because it can be
observed before a completion reaches its terminal state. It can also mean an
unknown completion ID, so retry only when the application knows that the
completion may still be finishing. A valid 2xx unavailable envelope is not
retryable: it reports that the Gateway cannot provide a usable signature for that
completion.
