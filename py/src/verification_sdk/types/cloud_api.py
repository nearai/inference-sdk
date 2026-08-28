"""Public NEAR AI Cloud request helpers and their input/result types."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass

from .attestation_common import SigningAlgo
from .attestation_gateway import GatewayAttestation
from .attestation_model import ModelAttestation
from .chat import CompletionSignatureReference


DEFAULT_NEAR_AI_CLOUD_BASE_URL = 'https://cloud-api.near.ai/v1'
NO_ALIASING_HEADER = 'x-no-aliasing'


@dataclass(frozen=True, kw_only=True)
class NearAiCloudResponse:
    """Minimal response returned by an optional custom Cloud transport."""

    status: int
    body: str
    peer_spki_fingerprint: str | None = None

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300


NearAiCloudFetch = Callable[[str, Mapping[str, str]], Awaitable[NearAiCloudResponse]]


@dataclass(frozen=True, kw_only=True)
class NearAiCloudOptions:
    """Cloud API credentials and optional HTTPS transport override."""

    api_key: str
    base_url: str = DEFAULT_NEAR_AI_CLOUD_BASE_URL
    fetch: NearAiCloudFetch | None = None


@dataclass(frozen=True, kw_only=True)
class FetchModelAttestationsInput:
    model: str
    signing_algo: SigningAlgo | None = None
    signing_address: str | None = None


@dataclass(frozen=True, kw_only=True)
class FetchModelAttestationForSignatureInput:
    model: str
    signature: CompletionSignatureReference


@dataclass(frozen=True, kw_only=True)
class FindModelAttestationForSignatureInput:
    attestations: tuple[ModelAttestation, ...] | list[ModelAttestation]
    signature: CompletionSignatureReference


@dataclass(frozen=True, kw_only=True)
class FetchGatewayAttestationInput:
    signing_algo: SigningAlgo = 'ed25519'


@dataclass(frozen=True, kw_only=True)
class FetchCompletionSignatureInput:
    completion_id: str
    signing_algo: SigningAlgo | None = None


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
    'NearAiCloudResponse',
    'NearAiCloudFetch',
    'NearAiCloudOptions',
    'FetchModelAttestationsInput',
    'FetchModelAttestationForSignatureInput',
    'FindModelAttestationForSignatureInput',
    'FetchGatewayAttestationInput',
    'FetchCompletionSignatureInput',
    'FetchedModelAttestation',
    'FetchedGatewayAttestation',
    'FetchedModelAttestations',
]
