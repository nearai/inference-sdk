"""Verification policies, callbacks, and verified results."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Literal, TypeAlias

from .attestation_common import SigningIdentity, TcbStatus


@dataclass(frozen=True, kw_only=True)
class RuntimeMeasurements:
    os_image_hash: str | None = None
    compose_hash: str | None = None


@dataclass(frozen=True, kw_only=True)
class MeasuredDeployment:
    app_compose: str
    runtime_measurements: RuntimeMeasurements


@dataclass(frozen=True, kw_only=True)
class QuoteVerificationResult:
    tcb_status: TcbStatus
    advisory_ids: tuple[str, ...]
    debug_enabled: bool
    report_data: bytes
    mr_config_id: bytes
    rt_mr3: bytes


QuoteVerifier: TypeAlias = Callable[
    [str], Awaitable[QuoteVerificationResult] | QuoteVerificationResult
]
NvidiaEvidenceVerifier: TypeAlias = Callable[[str], Awaitable[None] | None]
DeploymentVerifier: TypeAlias = Callable[[MeasuredDeployment], Awaitable[None] | None]


@dataclass(frozen=True, kw_only=True)
class AttestationPolicy:
    accepted_tcb_statuses: tuple[TcbStatus, ...] | None = None


@dataclass(frozen=True, kw_only=True)
class ModelAttestationPolicy(AttestationPolicy):
    gpu_evidence: Literal['if-present', 'required'] = 'if-present'


@dataclass(frozen=True, kw_only=True)
class GatewayAttestationPolicy(AttestationPolicy):
    """Policy controls specific to Gateway evidence verification."""

    #: Request and verify TLS fingerprint evidence. When false, use the
    #: signer-and-nonce report-data layout instead.
    verify_tls_binding: bool = True


@dataclass(frozen=True, kw_only=True)
class AttestationVerifiers:
    quote: QuoteVerifier | None = None
    deployment: DeploymentVerifier | None = None


@dataclass(frozen=True, kw_only=True)
class ModelAttestationVerifiers(AttestationVerifiers):
    nvidia: NvidiaEvidenceVerifier | None = None


@dataclass(frozen=True, kw_only=True)
class ModelClientBinding:
    """Values supplied by the client for a model-attestation request."""

    nonce: str


@dataclass(frozen=True, kw_only=True)
class GatewayClientBinding:
    """Values supplied or observed by the client for a Gateway request."""

    nonce: str
    peer_spki_fingerprint: str | None = None


@dataclass(frozen=True, kw_only=True)
class GatewayTlsBinding:
    kind: Literal['none', 'attested']
    spki_fingerprint: str | None = None


@dataclass(frozen=True, kw_only=True)
class VerifiedAttestationEvidence:
    signer: SigningIdentity
    tcb_status: TcbStatus
    advisory_ids: tuple[str, ...]
    deployment: MeasuredDeployment
    deployment_provenance: Literal['not_checked', 'verified']


@dataclass(frozen=True, kw_only=True)
class VerifiedModelAttestation(VerifiedAttestationEvidence):
    gpu_evidence: Literal['not_provided', 'verified']


@dataclass(frozen=True, kw_only=True)
class VerifiedGatewayAttestation(VerifiedAttestationEvidence):
    tls_binding: GatewayTlsBinding


__all__ = [
    'RuntimeMeasurements',
    'MeasuredDeployment',
    'QuoteVerificationResult',
    'QuoteVerifier',
    'NvidiaEvidenceVerifier',
    'DeploymentVerifier',
    'AttestationPolicy',
    'ModelAttestationPolicy',
    'GatewayAttestationPolicy',
    'AttestationVerifiers',
    'ModelAttestationVerifiers',
    'ModelClientBinding',
    'GatewayClientBinding',
    'GatewayTlsBinding',
    'VerifiedAttestationEvidence',
    'VerifiedModelAttestation',
    'VerifiedGatewayAttestation',
]
