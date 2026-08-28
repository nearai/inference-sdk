"""Verification inputs, policies, callbacks, and verified results."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Literal, TypeAlias

from .attestation_common import SigningIdentity, TcbStatus
from .attestation_gateway import GatewayAttestation
from .attestation_model import ModelAttestation
from .chat import CompletionSignature


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
class AttestationVerifiers:
    quote: QuoteVerifier | None = None
    deployment: DeploymentVerifier | None = None


@dataclass(frozen=True, kw_only=True)
class ModelAttestationVerifiers(AttestationVerifiers):
    nvidia: NvidiaEvidenceVerifier | None = None


@dataclass(frozen=True, kw_only=True)
class VerifyModelAttestationInput:
    attestation: ModelAttestation
    nonce: str
    policy: ModelAttestationPolicy | None = None
    verifiers: ModelAttestationVerifiers | None = None


@dataclass(frozen=True, kw_only=True)
class VerifyGatewayAttestationInput:
    attestation: GatewayAttestation
    nonce: str
    peer_spki_fingerprint: str
    policy: AttestationPolicy | None = None
    verifiers: AttestationVerifiers | None = None


@dataclass(frozen=True, kw_only=True)
class ModelTlsBinding:
    kind: Literal['none', 'declared']
    spki_fingerprint: str | None = None


@dataclass(frozen=True, kw_only=True)
class GatewayTlsBinding:
    kind: Literal['peer']
    spki_fingerprint: str


@dataclass(frozen=True, kw_only=True)
class VerifiedAttestationEvidence:
    signer: SigningIdentity
    tcb_status: TcbStatus
    advisory_ids: tuple[str, ...]
    deployment: MeasuredDeployment
    deployment_provenance: Literal['not_checked', 'verified']


@dataclass(frozen=True, kw_only=True)
class VerifiedModelAttestation(VerifiedAttestationEvidence):
    tls_binding: ModelTlsBinding
    gpu_evidence: Literal['not_provided', 'verified']


@dataclass(frozen=True, kw_only=True)
class VerifiedGatewayAttestation(VerifiedAttestationEvidence):
    tls_binding: GatewayTlsBinding


@dataclass(frozen=True, kw_only=True)
class VerifyModelResponseInput:
    request_body: bytes
    response_body: bytes
    signature: CompletionSignature
    attestation: VerifiedModelAttestation


@dataclass(frozen=True, kw_only=True)
class VerifyGatewayResponseInput:
    request_body: bytes
    response_body: bytes
    signature: CompletionSignature
    attestation: VerifiedGatewayAttestation


__all__ = [
    'RuntimeMeasurements',
    'MeasuredDeployment',
    'QuoteVerificationResult',
    'QuoteVerifier',
    'NvidiaEvidenceVerifier',
    'DeploymentVerifier',
    'AttestationPolicy',
    'ModelAttestationPolicy',
    'AttestationVerifiers',
    'ModelAttestationVerifiers',
    'VerifyModelAttestationInput',
    'VerifyGatewayAttestationInput',
    'ModelTlsBinding',
    'GatewayTlsBinding',
    'VerifiedAttestationEvidence',
    'VerifiedModelAttestation',
    'VerifiedGatewayAttestation',
    'VerifyModelResponseInput',
    'VerifyGatewayResponseInput',
]
