"""Direct endpoint evidence, client bindings, and verified signer groups."""

from dataclasses import dataclass
from typing import Literal

from .attestation_model import ModelAttestation
from .chat import CompletionSignature
from .inference_client import ModelVerificationOptions
from .ohttp import OhttpAttestation
from .verification import (
    DeploymentVerifier,
    GatewayTlsBinding,
    ModelClientBinding,
    VerifiedModelAttestation,
)


@dataclass(frozen=True, kw_only=True)
class DirectModelVerificationOptions(ModelVerificationOptions):
    """Per-report checks plus an optional serving-only deployment policy."""

    serving_deployment: DeploymentVerifier | None = None


@dataclass(frozen=True, kw_only=True)
class DirectModelAttestation(ModelAttestation):
    model_name: str
    instance_id: str | None = None
    spki_fingerprint: str | None = None


@dataclass(frozen=True, kw_only=True)
class DirectClientBinding(ModelClientBinding):
    spki_fingerprint: str | None = None


@dataclass(frozen=True, kw_only=True)
class FetchedDirectModelAttestations:
    serving_attestation: DirectModelAttestation
    attestations: tuple[DirectModelAttestation, ...]
    client_binding: DirectClientBinding
    ohttp_attestation: OhttpAttestation | None = None


@dataclass(frozen=True, kw_only=True)
class VerifiedDirectModelAttestation(VerifiedModelAttestation):
    # Endpoint metadata is not a model-name claim authenticated by the quote.
    model_name: str
    instance_id: str | None = None
    spki_fingerprint: str | None = None


DirectTlsBinding = GatewayTlsBinding


@dataclass(frozen=True, kw_only=True)
class VerifiedDirectModelAttestations:
    serving_attestation: VerifiedDirectModelAttestation
    attestations: tuple[VerifiedDirectModelAttestation, ...]
    tls_binding: DirectTlsBinding
    spki_fingerprints: tuple[str, ...]


@dataclass(frozen=True, kw_only=True)
class DirectAttestationVerificationResult(VerifiedDirectModelAttestations):
    """All verified direct reports shared by verify() and Chat."""

    # Unix milliseconds when verification completed; unchanged on cache hits.
    verified_at: int


@dataclass(frozen=True, kw_only=True)
class VerifiedDirectCompletionResult:
    id: str
    signature: CompletionSignature
    attestations: tuple[VerifiedDirectModelAttestation, ...]
    signature_kind: Literal['provider_tee'] = 'provider_tee'
