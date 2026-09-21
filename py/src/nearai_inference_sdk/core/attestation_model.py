"""Model-serving TEE attestation verification."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import ec
from eth_utils import keccak

from ..types.verification import (
    GpuEvidenceVerifier,
    ModelAttestationPolicy,
    ModelAttestationVerifiers,
    ModelClientBinding,
    VerifiedModelAttestation,
)
from ..types.attestation_model import ModelAttestation
from ..utils.common import hex_to_bytes, maybe_await
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
        tdx_quote_verifier=None if verifiers is None else verifiers.tdx_quote,
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
        verifier=None if verifiers is None else verifiers.gpu_evidence,
    )
    return VerifiedModelAttestation(
        signer=evidence.signer,
        tcb_status=evidence.tcb_status,
        advisory_ids=evidence.advisory_ids,
        deployment=evidence.deployment,
        deployment_provenance=evidence.deployment_provenance,
        gpu_evidence=gpu_evidence,
        signing_public_key=_verify_signing_public_key(attestation),
    )


def _verify_signing_public_key(attestation: ModelAttestation) -> str | None:
    """Bind an optional E2EE key to the quote-authenticated model signer."""

    if attestation.signing_public_key is None:
        return None
    public_key = hex_to_bytes(
        attestation.signing_public_key, 'attestation.signing_public_key'
    )
    address = hex_to_bytes(attestation.signer.signing_address, 'signer.signing_address')
    if attestation.signer.signing_algo == 'ed25519':
        matches = len(public_key) == 32 and public_key == address
    else:
        if len(public_key) == 65 and public_key[0] == 4:
            public_key = public_key[1:]
        matches = False
        if len(public_key) == 64:
            try:
                ec.EllipticCurvePublicKey.from_encoded_point(
                    ec.SECP256K1(), b'\x04' + public_key
                )
                matches = keccak(public_key)[-20:] == address
            except ValueError:
                pass
    if not matches:
        raise verification_failure('binding.model_public_key_mismatch')
    return public_key.hex()


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
