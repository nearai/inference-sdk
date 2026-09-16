"""Public NEAR AI Cloud request-result types."""

from __future__ import annotations

from dataclasses import dataclass

from .attestation_gateway import GatewayAttestation
from .attestation_model import ModelAttestation
from .verification import (
    GatewayClientBinding,
    ModelClientBinding,
)


DEFAULT_NEAR_AI_CLOUD_BASE_URL = 'https://cloud-api.near.ai/v1'
NO_ALIASING_HEADER = 'x-no-aliasing'


@dataclass(frozen=True, kw_only=True)
class FetchedGatewayAttestation:
    attestation: GatewayAttestation
    client_binding: GatewayClientBinding


@dataclass(frozen=True, kw_only=True)
class FetchedModelAttestations:
    attestations: tuple[ModelAttestation, ...]
    client_binding: ModelClientBinding


__all__ = [
    'DEFAULT_NEAR_AI_CLOUD_BASE_URL',
    'NO_ALIASING_HEADER',
    'FetchedGatewayAttestation',
    'FetchedModelAttestations',
]
