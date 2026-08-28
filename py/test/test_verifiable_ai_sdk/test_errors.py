from __future__ import annotations

from verifiable_ai_sdk import (
    ApiError,
    ApiFailure,
    VerificationError,
    VerificationFailure,
)


def test_errors_serialize_stable_failure_data() -> None:
    api_error = ApiError(
        ApiFailure(
            code='api.invalid_response',
            details={'path': 'response'},
            retryable=True,
        )
    )
    verification_error = VerificationError(
        VerificationFailure(code='policy.gpu_evidence_required')
    )

    assert api_error.to_dict()['failure'] == {
        'code': 'api.invalid_response',
        'details': {'path': 'response'},
    }
    assert api_error.retryable is True

    assert verification_error.to_dict()['failure'] == {
        'code': 'policy.gpu_evidence_required',
    }
    assert verification_error.retryable is False
