"""Public NEAR AI Cloud request-result and Gateway transport types."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass

from .attestation_gateway import GatewayAttestation
from .attestation_model import ModelAttestation


DEFAULT_NEAR_AI_CLOUD_BASE_URL = 'https://cloud-api.near.ai/v1'
NO_ALIASING_HEADER = 'x-no-aliasing'


@dataclass(frozen=True, kw_only=True)
class GatewayAttestationResponse:
    """Response returned by a custom Gateway-attestation transport."""

    status: int
    body: str
    peer_spki_fingerprint: str | None = None


GatewayAttestationTransport = Callable[
    [str, Mapping[str, str]], Awaitable[GatewayAttestationResponse]
]


@dataclass(frozen=True, kw_only=True)
class FetchedModelAttestation:
    attestation: ModelAttestation
    nonce: str


@dataclass(frozen=True, kw_only=True)
class FetchedGatewayAttestation:
    attestation: GatewayAttestation
    nonce: str
    peer_spki_fingerprint: str | None


@dataclass(frozen=True, kw_only=True)
class FetchedModelAttestations:
    attestations: tuple[ModelAttestation, ...]
    nonce: str


__all__ = [
    'DEFAULT_NEAR_AI_CLOUD_BASE_URL',
    'NO_ALIASING_HEADER',
    'GatewayAttestationResponse',
    'GatewayAttestationTransport',
    'FetchedModelAttestation',
    'FetchedGatewayAttestation',
    'FetchedModelAttestations',
]
