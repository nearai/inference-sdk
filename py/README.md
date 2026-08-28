# NEAR AI verification SDK for Python

This asynchronous SDK fetches and verifies NEAR AI Cloud attestation evidence
and completion signatures. It separates the evidence for a deployment from a
signature over a particular request and response.

## What it verifies

| Evidence | Successful verification establishes |
| --- | --- |
| Model attestation | The model CVM quote, client nonce, signing identity, TCB policy, report-data binding, event-log replay, and `MRCONFIGID`/`app_compose` binding are valid. NVIDIA GPU evidence is verified when supplied; set `ModelAttestationPolicy(gpu_evidence='required')` to require it. |
| Gateway attestation | The same deployment evidence, plus that the quote-bound Gateway TLS SPKI fingerprint equals the TLS peer fingerprint observed by the caller. |
| `provider_tee` response signature | The exact request/response bytes are signed by the signer established by verified model evidence. |
| `gateway` response signature | The exact client-visible request/response bytes are signed by the signer established by verified Gateway evidence. |

The SDK does not infer a signature's trust boundary from signed text.
`CompletionSignature.kind` selects the matching verification path.

## Public API

All Cloud helpers take `NearAiCloudOptions` and are asynchronous. Attestation
fetch results contain the fresh client nonce required by the corresponding
attestation verifier.

| Function | Purpose |
| --- | --- |
| `fetch_model_attestations` | Fetch the current model evidence for a canonical model name. |
| `find_model_attestation_for_signature` | Select the one model attestation that matches a `provider_tee` signer. |
| `fetch_model_attestation_for_signature` | Fetch and select model evidence in one call. |
| `fetch_gateway_attestation` | Fetch Gateway evidence with TLS-fingerprint evidence requested. |
| `lookup_completion_signature` | Look up a completion signature and preserve a successful unavailable response. |
| `fetch_completion_signature` | Look up a completion signature and raise `signature.unavailable` if it is unavailable. |
| `verify_model_attestation` | Verify `ModelAttestation` using `VerifyModelAttestationInput`. |
| `verify_gateway_attestation` | Verify `GatewayAttestation` using `VerifyGatewayAttestationInput`. |
| `verify_model_response` | Verify a `provider_tee` signature using `VerifyModelResponseInput`. |
| `verify_gateway_response` | Verify a `gateway` signature using `VerifyGatewayResponseInput`. |

`NearAiCloudOptions` defaults to `https://cloud-api.near.ai/v1` and accepts an
optional async `fetch(url, headers)` override. `NearAiCloudResponse` is the
small, explicit response type required by that override. A TLS-aware override
can return its exact-request SPKI fingerprint; `fetch_gateway_attestation`
returns the normalized value as `peer_spki_fingerprint`.

## Choosing a flow

1. To audit a model deployment, call `fetch_model_attestations`, then call
   `verify_model_attestation` for the returned attestation and nonce.
2. To verify a model-generated completion, fetch its signature, require
   `kind == 'provider_tee'`, select matching model evidence, verify that
   evidence, then call `verify_model_response` with the exact request and
   response bytes.
3. To audit a Gateway endpoint, call `fetch_gateway_attestation`, independently
   obtain that HTTPS connection's SPKI fingerprint, then call
   `verify_gateway_attestation`.
4. To verify a Gateway-signed completion, require `kind == 'gateway'`, verify
   Gateway evidence, then call `verify_gateway_response` with the exact bytes.

Model and Gateway evidence are independently verifiable. A successful
attestation establishes the deployment evidence; a response verifier adds the
binding to one exact request/response pair.

The SDK's default HTTP transport does not expose a TLS peer certificate, so its
Gateway fetch result has no peer fingerprint. Applications that need Gateway
verification must collect it in their TLS-aware connection layer and return it
from a custom `fetch` override.

## Errors and policies

Cloud retrieval failures raise `ApiError`; local cryptographic, policy, and
binding failures raise `VerificationError`. Inspect `error.failure.code`,
`error.failure.details`, and `error.retryable` rather than parsing the message.

The default TCB policy accepts `UpToDate` and `OutOfDate`. Pass
`AttestationPolicy` or `ModelAttestationPolicy` to tighten it. The default
NVIDIA verifier sends supplied GPU evidence to NVIDIA NRAS and uses its
documented boolean overall verdict; applications needing a different trust
model can provide `ModelAttestationVerifiers(nvidia=...)`.

## Development checks

From this directory:

```sh
uv sync
make lint
uv build
```

The test suite is deterministic and uses local fixtures; it does not contact
Cloud API, Intel PCCS, or NVIDIA NRAS.
