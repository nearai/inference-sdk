"""Shared dstack quote and deployment verification for model and Gateway evidence."""

from __future__ import annotations

from dataclasses import dataclass

from ..types.attestation_common import AttestationEvidence, SigningIdentity, TcbStatus
from ..types.verification import (
    AttestationPolicy,
    DeploymentVerifier,
    MeasuredDeployment,
    QuoteVerificationResult,
    QuoteVerifier,
    VerifiedAttestationEvidence,
)
from ..utils.common import maybe_await, require_byte_length, require_instance
from ..utils.errors import (
    VerificationError,
    verification_failure,
    wrap_verification_failure,
)
from ..utils.intel import verify_dcap_quote
from .attestation_common import (
    verify_advertised_report_data,
    verify_app_compose_mrconfig_binding,
    verify_reported_nonce,
)
from .event_log import verify_and_replay_rtmr3


DEFAULT_ACCEPTED_TCB_STATUSES: tuple[TcbStatus, ...] = ('UpToDate', 'OutOfDate')
ALL_TCB_STATUSES = frozenset(
    {
        'UpToDate',
        'SWHardeningNeeded',
        'ConfigurationNeeded',
        'ConfigurationAndSWHardeningNeeded',
        'OutOfDate',
        'OutOfDateConfigurationNeeded',
        'Revoked',
        'Unknown',
    }
)


@dataclass(frozen=True, kw_only=True)
class VerifiedDstackQuote:
    attestation: AttestationEvidence
    quote: QuoteVerificationResult
    signer: SigningIdentity


async def verify_dstack_quote(
    *,
    attestation: AttestationEvidence,
    nonce: str,
    policy: AttestationPolicy | None,
    quote_verifier: QuoteVerifier | None,
) -> VerifiedDstackQuote:
    require_instance(attestation.app_compose, str, 'attestation.app_compose')
    verify_reported_nonce(attestation.nonce, nonce)
    signer = _verify_signing_identity(attestation.signer)

    verifier = verify_dcap_quote if quote_verifier is None else quote_verifier
    try:
        quote = await maybe_await(verifier(attestation.intel_quote))
    except VerificationError:
        raise
    except Exception as error:
        raise wrap_verification_failure(
            'quote', 'quote.verification_failed', {'reason': 'verifier_error'}, error
        ) from error
    _validate_quote_result(quote)

    verify_advertised_report_data(attestation.reported_quote_data, quote.report_data)
    if quote.debug_enabled:
        raise verification_failure('policy', 'policy.debug_enabled')

    accepted = _accepted_tcb_statuses(policy)
    if quote.tcb_status not in accepted:
        raise verification_failure(
            'policy',
            'policy.tcb_status_not_allowed',
            {
                'actual': quote.tcb_status,
                'accepted': list(accepted),
                'advisoryIds': list(quote.advisory_ids),
            },
        )
    return VerifiedDstackQuote(attestation=attestation, quote=quote, signer=signer)


async def verify_dstack_deployment(
    verified_quote: VerifiedDstackQuote,
    deployment_verifier: DeploymentVerifier | None,
) -> VerifiedAttestationEvidence:
    runtime_measurements = verify_and_replay_rtmr3(
        verified_quote.attestation.event_log, verified_quote.quote.rt_mr3
    )
    verify_app_compose_mrconfig_binding(
        verified_quote.attestation.app_compose, verified_quote.quote.mr_config_id
    )
    deployment = MeasuredDeployment(
        app_compose=verified_quote.attestation.app_compose,
        runtime_measurements=runtime_measurements,
    )

    provenance = 'not_checked'
    if deployment_verifier is not None:
        try:
            await maybe_await(deployment_verifier(deployment))
        except VerificationError:
            raise
        except Exception as error:
            raise wrap_verification_failure(
                'provenance', 'provenance.verification_failed', None, error
            ) from error
        provenance = 'verified'

    return VerifiedAttestationEvidence(
        signer=verified_quote.signer,
        tcb_status=verified_quote.quote.tcb_status,
        advisory_ids=tuple(verified_quote.quote.advisory_ids),
        deployment=deployment,
        deployment_provenance=provenance,
    )


def _verify_signing_identity(signer: SigningIdentity) -> SigningIdentity:
    signer = require_instance(signer, SigningIdentity, 'attestation.signer')
    if signer.signing_algo not in {'ecdsa', 'ed25519'}:
        raise verification_failure(
            'input',
            'input.invalid',
            {
                'field': 'attestation.signer.signing_algo',
                'reason': 'unsupported_value',
                'expected': "'ecdsa' or 'ed25519'",
            },
        )
    require_byte_length(
        signer.signing_address,
        20 if signer.signing_algo == 'ecdsa' else 32,
        'attestation.signer.signing_address',
    )
    return signer


def _accepted_tcb_statuses(policy: AttestationPolicy | None) -> tuple[TcbStatus, ...]:
    if policy is None or policy.accepted_tcb_statuses is None:
        return DEFAULT_ACCEPTED_TCB_STATUSES
    try:
        statuses = tuple(policy.accepted_tcb_statuses)
    except TypeError as error:
        raise verification_failure(
            'input',
            'input.invalid',
            {
                'field': 'policy.accepted_tcb_statuses',
                'reason': 'unsupported_value',
                'expected': 'supported TCB statuses',
            },
            cause=error,
        ) from error
    if not all(
        isinstance(status, str) and status in ALL_TCB_STATUSES for status in statuses
    ):
        raise verification_failure(
            'input',
            'input.invalid',
            {
                'field': 'policy.accepted_tcb_statuses',
                'reason': 'unsupported_value',
                'expected': 'supported TCB statuses',
            },
        )
    return statuses


def _validate_quote_result(quote: QuoteVerificationResult) -> None:
    if not isinstance(quote, QuoteVerificationResult):
        raise verification_failure(
            'quote',
            'quote.invalid_result',
            {
                'path': 'quote',
                'expected': 'QuoteVerificationResult',
                'actual': type(quote).__name__,
            },
        )
    if (
        not isinstance(quote.tcb_status, str)
        or quote.tcb_status not in ALL_TCB_STATUSES
    ):
        raise verification_failure(
            'quote',
            'quote.invalid_result',
            {
                'path': 'quote.tcb_status',
                'expected': 'supported TCB status',
                'actual': str(quote.tcb_status),
            },
        )
    for path, value in (
        ('quote.report_data', quote.report_data),
        ('quote.mr_config_id', quote.mr_config_id),
        ('quote.rt_mr3', quote.rt_mr3),
    ):
        if not isinstance(value, bytes):
            raise verification_failure(
                'quote',
                'quote.invalid_result',
                {'path': path, 'expected': 'bytes', 'actual': type(value).__name__},
            )
    if (
        not isinstance(quote.debug_enabled, bool)
        or not isinstance(quote.advisory_ids, (list, tuple))
        or not all(isinstance(advisory, str) for advisory in quote.advisory_ids)
    ):
        raise verification_failure(
            'quote',
            'quote.invalid_result',
            {'path': 'quote', 'expected': 'verified quote fields', 'actual': 'invalid'},
        )
