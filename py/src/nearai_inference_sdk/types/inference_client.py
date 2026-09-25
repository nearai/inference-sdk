"""Inference settings and successful response-verification results."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Literal, TypeAlias

from .chat import CompletionSignature
from .verification import (
    AttestationPolicy,
    AttestationVerifiers,
    MeasuredDeployment,
    ModelAttestationPolicy,
    ModelAttestationVerifiers,
    VerifiedGatewayAttestation,
    VerifiedModelAttestation,
)


DeploymentPolicy: TypeAlias = Callable[
    [str, MeasuredDeployment], Awaitable[None] | None
]


@dataclass(frozen=True, kw_only=True)
class GatewayVerificationOptions:
    include_spki_fingerprint: bool = True
    policy: AttestationPolicy | None = None
    verifiers: AttestationVerifiers | None = None


@dataclass(frozen=True, kw_only=True)
class ModelVerificationOptions:
    policy: ModelAttestationPolicy | None = None
    verifiers: ModelAttestationVerifiers | None = None


@dataclass(frozen=True, kw_only=True)
class VerifiedModelCompletionReceipt:
    completion_id: str
    signature: CompletionSignature
    attestation: VerifiedModelAttestation
    signature_kind: Literal['provider_tee'] = 'provider_tee'


@dataclass(frozen=True, kw_only=True)
class VerifiedGatewayCompletionReceipt:
    completion_id: str
    signature: CompletionSignature
    attestation: VerifiedGatewayAttestation
    signature_kind: Literal['gateway'] = 'gateway'


VerifiedCompletionReceipt: TypeAlias = (
    VerifiedModelCompletionReceipt | VerifiedGatewayCompletionReceipt
)
