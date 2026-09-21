"""Model-serving TEE attestation verification."""

from __future__ import annotations

from ..types.verification import (
    GpuEvidenceVerifier,
    ModelAttestationPolicy,
    ModelAttestationVerifiers,
    ModelClientBinding,
    VerifiedModelAttestation,
)
from ..types.attestation_model import ModelAttestation
from ..utils.common import maybe_await
from ..utils.errors import (
    VerificationError,
    verification_failure,
)
from ..utils.nvidia import decode_nvidia_payload_nonce, verify_nvidia_nras
from .attestation_common import verify_report_data_binding, verify_reported_nonce
from .dstack_attestation import verify_dstack_deployment, verify_dstack_quote


async def verify_model_attestation(
    attestation: ModelAttestation,
    client_binding: ModelClientBinding,
    *,
    policy: ModelAttestationPolicy | None = None,
    verifiers: ModelAttestationVerifiers | None = None,
) -> VerifiedModelAttestation:
    """Verify model evidence returned through NEAR AI Cloud."""

    nonce = client_binding.nonce
    verified_quote = await verify_dstack_quote(
        attestation=attestation,
        advertised_report_data=attestation.reported_quote_data,
        nonce=nonce,
        policy=policy,
        quote_verifier=None if verifiers is None else verifiers.quote,
    )
    verify_report_data_binding(
        report_data=verified_quote.quote.report_data,
        nonce=nonce,
        signer=verified_quote.signer,
    )
    evidence = await verify_dstack_deployment(
        verified_quote, None if verifiers is None else verifiers.deployment
    )
    gpu_evidence = await _verify_gpu_evidence(
        payload=attestation.nvidia_payload,
        nonce=nonce,
        policy=policy,
        verifier=None if verifiers is None else verifiers.gpu,
    )
    return VerifiedModelAttestation(
        signer=evidence.signer,
        tcb_status=evidence.tcb_status,
        advisory_ids=evidence.advisory_ids,
        deployment=evidence.deployment,
        deployment_provenance=evidence.deployment_provenance,
        gpu_evidence=gpu_evidence,
    )


async def _verify_gpu_evidence(
    *,
    payload: str | None,
    nonce: str,
    policy: ModelAttestationPolicy | None,
    verifier: GpuEvidenceVerifier | None,
) -> str:
    requirement = 'if-present' if policy is None else policy.gpu_evidence
    if payload is None:
        if requirement == 'required':
            raise verification_failure('policy.gpu_evidence_required')
        return 'not_provided'

    payload_nonce = decode_nvidia_payload_nonce(payload)
    verify_reported_nonce(payload_nonce, nonce, 'nvidiaPayload')

    try:
        if verifier is None:
            await verify_nvidia_nras(payload, nonce)
        else:
            await maybe_await(verifier(payload))
    except VerificationError:
        raise
    except Exception as error:
        raise verification_failure(
            'gpu.attestation_rejected',
            {'source': 'custom_verifier'},
            cause=error,
        ) from error
    return 'verified'
