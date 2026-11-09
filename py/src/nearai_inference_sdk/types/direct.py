"""Direct endpoint evidence, client bindings, and verified signer groups."""

from dataclasses import dataclass
from typing import Literal

from .attestation_model import ModelAttestation
from .chat import CompletionSignature
from .inference_client import ModelVerificationOptions
from .ohttp import OhttpAttestation
from .verification import (
    GatewayTlsBinding,
    ModelClientBinding,
    VerifiedModelAttestation,
)

DirectModelVerificationOptions = ModelVerificationOptions


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
    """The quote does not authenticate the endpoint's model_name or instance_id."""

    report: DirectModelAttestation
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

    # Unix milliseconds when verification completed.
    verified_at: int


@dataclass(frozen=True, kw_only=True)
class VerifiedDirectCompletionResult:
    id: str
    signature: CompletionSignature
    attestations: tuple[VerifiedDirectModelAttestation, ...]
    signature_kind: Literal['provider_tee'] = 'provider_tee'
