"""Direct model verification, including the report set and observed TLS peer."""

from ..types.direct import (
    DirectModelAttestation,
    DirectTlsBinding,
    FetchedDirectModelAttestations,
    VerifiedDirectModelAttestation,
    VerifiedDirectModelAttestations,
)
from ..types.verification import (
    ModelAttestationPolicy,
    ModelAttestationVerifiers,
    ModelClientBinding,
    VerifiedAttestationEvidence,
)
from ..utils.common import gather_cancel_on_error
from ..utils.errors import verification_failure
from .attestation_common import (
    verify_peer_spki_fingerprint,
    verify_report_data_binding,
    verify_report_data_binding_with_tls_fingerprint,
)
from .attestation_model import (
    _verify_gpu_evidence,
    _verify_signing_public_key,
    verify_model_deployment,
)
from .dstack_attestation import verify_dstack_quote


async def verify_direct_model_attestation(
    attestation: DirectModelAttestation,
    client_binding: ModelClientBinding,
    *,
    policy: ModelAttestationPolicy | None = None,
    verifiers: ModelAttestationVerifiers | None = None,
) -> VerifiedDirectModelAttestation:
    """Verify one report, authenticating its optional SPKI without observing a peer."""

    (evidence, fingerprint), gpu = await gather_cancel_on_error(
        _verify_direct_cpu(attestation, client_binding, policy, verifiers),
        _verify_gpu_evidence(
            payload=attestation.nvidia_payload,
            nonce=client_binding.nonce,
            policy=policy,
            verifier=None if verifiers is None else verifiers.gpu_evidence,
        ),
    )
    return VerifiedDirectModelAttestation(
        signer=evidence.signer,
        tcb_status=evidence.tcb_status,
        advisory_ids=evidence.advisory_ids,
        deployment=evidence.deployment,
        deployment_provenance=evidence.deployment_provenance,
        gpu_evidence=gpu,
        signing_public_key=_verify_signing_public_key(attestation),
        model_name=attestation.model_name,
        instance_id=attestation.instance_id,
        spki_fingerprint=fingerprint,
    )


async def _verify_direct_cpu(
    attestation: DirectModelAttestation,
    client_binding: ModelClientBinding,
    policy: ModelAttestationPolicy | None,
    verifiers: ModelAttestationVerifiers | None,
) -> tuple[VerifiedAttestationEvidence, str | None]:
    quote = await verify_dstack_quote(
        attestation=attestation,
        advertised_report_data=attestation.reported_quote_data,
        nonce=client_binding.nonce,
        policy=policy,
        tdx_quote_verifier=None if verifiers is None else verifiers.tdx_quote,
    )
    fingerprint = None
    if attestation.spki_fingerprint is None:
        verify_report_data_binding(
            report_data=quote.quote.report_data,
            nonce=client_binding.nonce,
            signer=quote.signer,
        )
    else:
        fingerprint = verify_report_data_binding_with_tls_fingerprint(
            report_data=quote.quote.report_data,
            nonce=client_binding.nonce,
            signer=quote.signer,
            reported_spki_fingerprint=attestation.spki_fingerprint,
        )
    evidence = await verify_model_deployment(
        attestation, quote, client_binding.nonce, policy, verifiers
    )
    return evidence, fingerprint


async def verify_direct_model_attestations(
    fetched_attestations: FetchedDirectModelAttestations,
    *,
    policy: ModelAttestationPolicy | None = None,
    verifiers: ModelAttestationVerifiers | None = None,
) -> VerifiedDirectModelAttestations:
    """Verify every report and bind the serving report to the observed TLS peer."""

    reports = fetched_attestations.attestations
    if not reports:
        raise verification_failure('policy.model_attestation_required')
    try:
        index = reports.index(fetched_attestations.serving_attestation)
    except ValueError:
        raise verification_failure(
            'input.invalid',
            {'field': 'serving_attestation', 'reason': 'not_in_attestation_set'},
        ) from None
    attestations = tuple(
        await gather_cancel_on_error(
            *(
                verify_direct_model_attestation(
                    item,
                    fetched_attestations.client_binding,
                    policy=policy,
                    verifiers=verifiers,
                )
                for item in reports
            )
        )
    )
    serving = attestations[index]
    tls_binding = DirectTlsBinding(kind='none')
    if serving.spki_fingerprint is not None:
        peer = fetched_attestations.client_binding.spki_fingerprint
        if peer is None:
            raise verification_failure('binding.spki_fingerprint_required')
        verify_peer_spki_fingerprint(serving.spki_fingerprint, peer)
        tls_binding = DirectTlsBinding(
            kind='attested', spki_fingerprint=serving.spki_fingerprint
        )
    return VerifiedDirectModelAttestations(
        serving_attestation=serving,
        attestations=attestations,
        tls_binding=tls_binding,
        spki_fingerprints=tuple(
            dict.fromkeys(
                item.spki_fingerprint
                for item in attestations
                if item.spki_fingerprint is not None
            )
        ),
    )
