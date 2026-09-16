"""Caller-owned trust rules and verified container-image build provenance."""

from dataclasses import dataclass


@dataclass(frozen=True, kw_only=True)
class ImageProvenancePolicy:
    """The GitHub build identity to trust, optionally pinned to a ref or commit."""

    repository: str
    workflow: str
    ref: str | None = None
    commit: str | None = None
    issuer: str = 'https://token.actions.githubusercontent.com'


@dataclass(frozen=True, kw_only=True)
class VerifiedImageProvenance:
    """Build facts extracted only after the bundle and policy have been verified."""

    digest: str
    repository: str
    workflow: str
    ref: str
    commit: str
    certificate_identity: str
    issuer: str
    predicate_type: str
