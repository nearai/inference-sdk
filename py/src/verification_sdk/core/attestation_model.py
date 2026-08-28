"""Model-serving TEE attestation verification."""

from __future__ import annotations

import json

from ..types.verification import (
    ModelAttestationPolicy,
    ModelAttestationVerifiers,
    NvidiaEvidenceVerifier,
    VerifiedModelAttestation,
    VerifyModelAttestationInput,
)
from ..types.attestation_model import ModelAttestation
from ..utils.common import maybe_await, require_instance
from ..utils.errors import (
    VerificationError,
    verification_failure,
    wrap_verification_failure,
)
from ..utils.nvidia import verify_nvidia_nras
from .attestation_common import verify_model_report_data_binding, verify_reported_nonce
from .dstack_attestation import verify_dstack_deployment, verify_dstack_quote


async def verify_model_attestation(
    input: VerifyModelAttestationInput,
) -> VerifiedModelAttestation:
    """Verify model evidence returned through NEAR AI Cloud."""

    input = require_instance(input, VerifyModelAttestationInput, 'input')
    attestation = require_instance(input.attestation, ModelAttestation, 'attestation')
    policy = (
        None
        if input.policy is None
        else require_instance(input.policy, ModelAttestationPolicy, 'policy')
    )
    verifiers = (
        None
        if input.verifiers is None
        else require_instance(input.verifiers, ModelAttestationVerifiers, 'verifiers')
    )
    verified_quote = await verify_dstack_quote(
        attestation=attestation,
        nonce=input.nonce,
        policy=policy,
        quote_verifier=None if verifiers is None else verifiers.quote,
    )
    tls_binding = verify_model_report_data_binding(
        report_data=verified_quote.quote.report_data,
        nonce=input.nonce,
        signer=verified_quote.signer,
        reported_spki_fingerprint=attestation.declared_spki_fingerprint,
    )
    evidence = await verify_dstack_deployment(
        verified_quote, None if verifiers is None else verifiers.deployment
    )
    gpu_evidence = await _verify_nvidia_evidence(
        payload=attestation.nvidia_payload,
        nonce=input.nonce,
        policy=policy,
        verifier=None if verifiers is None else verifiers.nvidia,
    )
    return VerifiedModelAttestation(
        signer=evidence.signer,
        tcb_status=evidence.tcb_status,
        advisory_ids=evidence.advisory_ids,
        deployment=evidence.deployment,
        deployment_provenance=evidence.deployment_provenance,
        tls_binding=tls_binding,
        gpu_evidence=gpu_evidence,
    )


async def _verify_nvidia_evidence(
    *,
    payload: str | None,
    nonce: str,
    policy: ModelAttestationPolicy | None,
    verifier: NvidiaEvidenceVerifier | None,
) -> str:
    requirement = 'if-present' if policy is None else policy.gpu_evidence
    if requirement not in {'if-present', 'required'}:
        raise verification_failure(
            'input',
            'input.invalid',
            {
                'field': 'policy.gpu_evidence',
                'reason': 'unsupported_value',
                'expected': "'if-present' or 'required'",
            },
        )
    if payload is None:
        if requirement == 'required':
            raise verification_failure('policy', 'policy.gpu_evidence_required')
        return 'not_provided'
    if not isinstance(payload, str):
        raise verification_failure(
            'input',
            'input.invalid',
            {
                'field': 'attestation.nvidia_payload',
                'reason': 'unsupported_value',
                'expected': 'string or null',
            },
        )

    try:
        parsed = json.loads(payload)
    except json.JSONDecodeError as error:
        raise verification_failure(
            'gpu', 'gpu.payload_invalid', {'reason': 'invalid_json'}, cause=error
        ) from error
    if not isinstance(parsed, dict) or not isinstance(parsed.get('nonce'), str):
        raise verification_failure(
            'gpu', 'gpu.payload_invalid', {'reason': 'nonce_missing'}
        )
    verify_reported_nonce(parsed['nonce'], nonce, 'nvidiaPayload')

    actual_verifier = verify_nvidia_nras if verifier is None else verifier
    try:
        await maybe_await(actual_verifier(payload))
    except VerificationError:
        raise
    except Exception as error:
        raise wrap_verification_failure(
            'gpu', 'gpu.attestation_rejected', {'source': 'custom_verifier'}, error
        ) from error
    return 'verified'
