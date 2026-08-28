"""Structured errors exposed by the verification SDK.

The error code and details are the public contract. Messages are deliberately
short and are only intended for people reading logs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


ErrorDetails = dict[str, object]


@dataclass(frozen=True, kw_only=True)
class ApiFailure:
    """A Cloud API request, response, or evidence-selection failure."""

    code: str
    details: ErrorDetails = field(default_factory=dict)
    retryable: bool = False
    phase: Literal['api'] = 'api'


@dataclass(frozen=True, kw_only=True)
class VerificationFailure:
    """A local cryptographic, policy, binding, or input failure."""

    phase: str
    code: str
    details: ErrorDetails = field(default_factory=dict)
    retryable: bool = False


class ApiError(Exception):
    """A machine-readable failure while retrieving Cloud API evidence."""

    def __init__(self, failure: ApiFailure, *, cause: BaseException | None = None):
        self.failure = failure
        self.cause = cause
        super().__init__(_format_failure(failure))

    @property
    def code(self) -> str:
        return self.failure.code

    @property
    def retryable(self) -> bool:
        return self.failure.retryable

    def to_dict(self) -> dict[str, object]:
        return {
            'name': type(self).__name__,
            'message': str(self),
            'failure': {
                'phase': self.failure.phase,
                'code': self.failure.code,
                'details': dict(self.failure.details),
            },
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
    def code(self) -> str:
        return self.failure.code

    @property
    def retryable(self) -> bool:
        return self.failure.retryable

    def to_dict(self) -> dict[str, object]:
        return {
            'name': type(self).__name__,
            'message': str(self),
            'failure': {
                'phase': self.failure.phase,
                'code': self.failure.code,
                'details': dict(self.failure.details),
            },
            'retryable': self.retryable,
        }


def is_api_error(value: object) -> bool:
    return isinstance(value, ApiError)


def is_verification_error(value: object) -> bool:
    return isinstance(value, VerificationError)


def api_failure(
    code: str,
    details: ErrorDetails | None = None,
    *,
    retryable: bool = False,
    cause: BaseException | None = None,
) -> ApiError:
    return ApiError(
        ApiFailure(
            code=code, details={} if details is None else details, retryable=retryable
        ),
        cause=cause,
    )


def verification_failure(
    phase: str,
    code: str,
    details: ErrorDetails | None = None,
    *,
    retryable: bool = False,
    cause: BaseException | None = None,
) -> VerificationError:
    return VerificationError(
        VerificationFailure(
            phase=phase,
            code=code,
            details={} if details is None else details,
            retryable=retryable,
        ),
        cause=cause,
    )


def wrap_verification_failure(
    phase: str,
    code: str,
    details: ErrorDetails | None,
    cause: BaseException,
) -> VerificationError:
    if isinstance(cause, VerificationError):
        return cause
    return verification_failure(phase, code, details, cause=cause)


def _format_failure(failure: ApiFailure | VerificationFailure) -> str:
    return failure.code.replace('.', ' ')
