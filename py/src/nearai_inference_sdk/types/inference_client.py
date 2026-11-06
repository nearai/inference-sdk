"""Inference settings and successful attestation and response-verification results."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Literal

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

type DeploymentPolicy = Callable[[str, MeasuredDeployment], Awaitable[None] | None]


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
class AttestationVerificationResult:
    """Gateway and model results shared by verify() and Chat for this model."""

    gateway: VerifiedGatewayAttestation
    models: tuple[VerifiedModelAttestation, ...]
    # Unix milliseconds when verification completed; unchanged on cache hits.
    verified_at: int


@dataclass(frozen=True, kw_only=True)
class VerifiedModelCompletionResult:
    """Response verified against the request's selected signing identity.

    ``attestations`` contains all matching preflight reports, without claiming
    which instance served the response. Use ``attestations`` for model evidence.
    The deprecated ``attestation`` field retains the report used to select the
    request's model public key; it does not identify the serving instance.
    """

    id: str
    signature: CompletionSignature
    attestations: tuple[VerifiedModelAttestation, ...]
    #: Deprecated: use ``attestations`` for all verified reports sharing the
    #: selected signer. This is the report used to select the request's model
    #: public key, not the identity of the serving instance.
    attestation: VerifiedModelAttestation
    signature_kind: Literal['provider_tee'] = 'provider_tee'


@dataclass(frozen=True, kw_only=True)
class VerifiedGatewayCompletionResult:
    id: str
    signature: CompletionSignature
    attestation: VerifiedGatewayAttestation
    signature_kind: Literal['gateway'] = 'gateway'


type VerifiedCompletionResult = (
    VerifiedModelCompletionResult | VerifiedGatewayCompletionResult
)
