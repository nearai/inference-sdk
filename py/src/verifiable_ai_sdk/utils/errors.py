"""Structured errors exposed by the verification SDK.

The error code and details are the public contract. Messages are deliberately
short and are only intended for people reading logs.
"""

from __future__ import annotations

from dataclasses import dataclass

ErrorDetails = dict[str, object]


@dataclass(frozen=True, kw_only=True)
class ApiFailure:
    """A Cloud API request, response, or evidence-selection failure."""

    code: str
    details: ErrorDetails | None = None
    retryable: bool = False


@dataclass(frozen=True, kw_only=True)
class VerificationFailure:
    """A local cryptographic, policy, binding, or input failure."""

    code: str
    details: ErrorDetails | None = None
    retryable: bool = False


class ApiError(Exception):
    """A machine-readable failure while retrieving Cloud API evidence."""

    def __init__(self, failure: ApiFailure, *, cause: BaseException | None = None):
        self.failure = failure
        self.cause = cause
        super().__init__(_format_failure(failure))

    @property
    def retryable(self) -> bool:
        return self.failure.retryable

    def to_dict(self) -> dict[str, object]:
        failure: dict[str, object] = {'code': self.failure.code}
        if self.failure.details is not None:
            failure['details'] = dict(self.failure.details)
        return {
            'name': type(self).__name__,
            'message': str(self),
            'failure': failure,
            'retryable': self.retryable,
        }


class VerificationError(Exception):
    """A machine-readable local verification failure."""

    def __init__(
        self,
        failure: VerificationFailure,
        *,
        cause: BaseException | None = None,
    ):
        self.failure = failure
        self.cause = cause
        super().__init__(_format_failure(failure))

    @property
    def retryable(self) -> bool:
        return self.failure.retryable

    def to_dict(self) -> dict[str, object]:
        failure: dict[str, object] = {'code': self.failure.code}
        if self.failure.details is not None:
            failure['details'] = dict(self.failure.details)
        return {
            'name': type(self).__name__,
            'message': str(self),
            'failure': failure,
            'retryable': self.retryable,
        }


def api_failure(
    code: str,
    details: ErrorDetails | None = None,
    *,
    retryable: bool = False,
    cause: BaseException | None = None,
) -> ApiError:
    return ApiError(
        ApiFailure(code=code, details=details, retryable=retryable),
        cause=cause,
    )


def verification_failure(
    code: str,
    details: ErrorDetails | None = None,
    *,
    retryable: bool = False,
    cause: BaseException | None = None,
) -> VerificationError:
    return VerificationError(
        VerificationFailure(
            code=code,
            details=details,
            retryable=retryable,
        ),
        cause=cause,
    )


def _format_failure(failure: ApiFailure | VerificationFailure) -> str:
    details = failure.details or {}
    code = failure.code

    match code:
        case 'input.invalid':
            return f'[{code}] {_format_input_failure(details)}'
        case 'api.transport_failed':
            resource = _api_resource(details)
            reason = details.get('reason')
            message = (
                'response body could not be read'
                if reason == 'response_body'
                else 'request failed'
            )
            return f'[{code}] Cloud API {resource} {message}'
        case 'api.http_status':
            return (
                f'[{code}] Cloud API {_api_resource(details)} returned HTTP '
                f'{_detail(details, "status")}'
            )
        case 'api.invalid_json':
            return f'[{code}] Cloud API {_api_resource(details)} returned invalid JSON'
        case 'api.invalid_response':
            return (
                f'[{code}] Cloud API response has an invalid '
                f'{_detail(details, "path")}: expected {_detail(details, "expected")}, '
                f'received {_detail(details, "actual")}'
            )
        case 'api.nonce_mismatch':
            return (
                f'[{code}] Cloud API {_api_resource(details)} nonce does not match '
                'the request'
            )
        case 'api.unexpected_model_attestation_count':
            return (
                f'[{code}] Cloud API returned {_detail(details, "actualCount")} '
                'model attestations; expected exactly one'
            )
        case 'api.ambiguous_model_attestation_signer':
            return (
                f'[{code}] Cloud API returned {_detail(details, "matchingCount")} '
                'model attestations for the requested signer '
                f'({_detail(details, "totalCount")} total)'
            )
        case 'api.model_attestation_signer_not_found':
            return f'[{code}] Cloud API returned no model attestation for the requested signer'
        case 'api.completion_signature_unavailable':
            return (
                f'[{code}] Cloud API did not provide a completion signature '
                f'({_detail(details, "providerErrorCode")})'
            )
        case 'quote.collateral_unavailable':
            return f'[{code}] Intel quote collateral is unavailable'
        case 'quote.verification_failed':
            return f'[{code}] Intel TDX quote verification failed: {_detail(details, "reason")}'
        case 'quote.invalid_result':
            return (
                f'[{code}] Quote verifier returned an invalid {_detail(details, "path")}: '
                f'expected {_detail(details, "expected")}, received {_detail(details, "actual")}'
            )
        case 'quote.unsupported_report_type':
            return (
                f'[{code}] Verified quote has an unsupported report type; expected '
                f'{_detail(details, "expected")}'
            )
        case 'policy.debug_enabled':
            return f'[{code}] TDX debug mode is enabled'
        case 'policy.tcb_status_not_allowed':
            return (
                f'[{code}] TDX TCB status {_detail(details, "actual")} '
                'is not allowed by policy'
            )
        case 'policy.gpu_evidence_required':
            return f'[{code}] GPU evidence is required by policy'
        case 'binding.nonce_mismatch':
            return f'[{code}] Nonce in {_detail(details, "source")} does not match'
        case 'binding.report_data_invalid':
            return (
                f'[{code}] {_detail(details, "source")} is invalid: '
                f'{_detail(details, "reason")}'
            )
        case 'binding.report_data_mismatch':
            return (
                f'[{code}] {_detail(details, "source")} does not match the '
                'verified quote'
            )
        case 'binding.spki_fingerprint_missing':
            return f'[{code}] Attestation is missing its SPKI fingerprint'
        case 'binding.spki_fingerprint_mismatch':
            return (
                f'[{code}] Attestation SPKI fingerprint does not match the observed '
                'TLS peer'
            )
        case 'measurement.event_log_invalid':
            return (
                f'[{code}] Attestation event log is invalid at {_detail(details, "path")}: '
                f'{_detail(details, "reason")}'
            )
        case 'measurement.rtmr3_mismatch':
            return (
                f'[{code}] Attestation event log does not match RTMR3: '
                f'{_detail(details, "reason")}'
            )
        case 'measurement.mrconfigid_invalid':
            return f'[{code}] Quote MRCONFIGID is invalid: {_detail(details, "reason")}'
        case 'measurement.app_compose_mrconfigid_mismatch':
            return f'[{code}] App compose does not match quote MRCONFIGID'
        case 'gpu.payload_invalid':
            return f'[{code}] GPU evidence payload is invalid: {_detail(details, "reason")}'
        case 'gpu.nras_request_failed':
            return f'[{code}] NVIDIA NRAS request failed: {_detail(details, "reason")}'
        case 'gpu.nras_response_invalid':
            return f'[{code}] NVIDIA NRAS response is invalid: {_detail(details, "reason")}'
        case 'gpu.attestation_rejected':
            return f'[{code}] GPU evidence was rejected by {_detail(details, "source")}'
        case 'provenance.verification_failed':
            return f'[{code}] Deployment provenance verification failed'
        case 'signature.kind_mismatch':
            return (
                f'[{code}] Expected a {_detail(details, "expected")} signature, '
                f'received {_detail(details, "actual")}'
            )
        case 'signature.payload_mismatch':
            return (
                f'[{code}] Completion signature does not match the '
                f'{_detail(details, "source")}: {_detail(details, "reason")}'
            )
        case 'signature.format_invalid':
            return (
                f'[{code}] Completion {_detail(details, "field")} is invalid: '
                f'{_detail(details, "reason")}'
            )
        case 'signature.invalid':
            return (
                f'[{code}] Completion signature is invalid for '
                f'{_detail(details, "signingAlgo")}'
            )
        case 'signature.signer_mismatch':
            return (
                f'[{code}] Completion signature signer does not match the attestation'
            )
        case _:
            return f'[{code}] {code.replace(".", " ").replace("_", " ")}'


def _detail(details: ErrorDetails, name: str) -> object:
    return details.get(name, 'unknown')


def _api_resource(details: ErrorDetails) -> str:
    resource = details.get('resource')
    match resource:
        case 'model_attestation':
            return 'model attestation'
        case 'gateway_attestation':
            return 'Gateway attestation'
        case 'completion_signature':
            return 'completion signature'
        case _:
            return 'resource'


def _format_input_failure(details: ErrorDetails) -> str:
    field = _detail(details, 'field')
    match details.get('reason'):
        case 'missing':
            return f'{field} is required'
        case 'invalid_hex':
            return f'{field} must be hexadecimal'
        case 'wrong_length':
            expected_text = details.get('expected')
            if expected_text is not None:
                return f'{field} must be {expected_text}'
            expected = details.get('expectedBytes')
            actual = details.get('actualBytes')
            if expected is not None and actual is not None:
                return f'{field} must be {expected} bytes; received {actual}'
            return f'{field} has the wrong length'
        case 'invalid_json':
            return f'{field} must be valid JSON'
        case 'invalid_jwt':
            return f'{field} must be a valid JWT'
        case 'invalid_url':
            expected = details.get('expected')
            return (
                f'{field} must be {expected}'
                if expected is not None
                else f'{field} is not a valid URL'
            )
        case 'invalid_header':
            expected = details.get('expected')
            return (
                f'{field} must be {expected}'
                if expected is not None
                else f'{field} is not a valid HTTP header'
            )
        case 'unsupported_value':
            expected = details.get('expected')
            return (
                f'{field} must be {expected}'
                if expected is not None
                else f'{field} has an unsupported value'
            )
        case _:
            return f'Invalid {field}'
