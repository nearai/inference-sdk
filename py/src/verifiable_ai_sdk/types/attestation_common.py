"""Shared public attestation data types."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, get_args


SigningAlgo = Literal['ecdsa', 'ed25519']
TcbStatus = Literal[
    'UpToDate',
    'SWHardeningNeeded',
    'ConfigurationNeeded',
    'ConfigurationAndSWHardeningNeeded',
    'OutOfDate',
    'OutOfDateConfigurationNeeded',
    'Revoked',
    'Unknown',
]
SUPPORTED_TCB_STATUSES: frozenset[TcbStatus] = frozenset(get_args(TcbStatus))
AttestationEventLog = str | list[object]


@dataclass(frozen=True, kw_only=True)
class SigningIdentity:
    """The public key identity advertised by evidence or a signature."""

    signing_algo: SigningAlgo
    signing_address: str


@dataclass(frozen=True, kw_only=True)
class AttestationEvidence:
    """Fields shared by raw model and Gateway evidence."""

    nonce: str
    signer: SigningIdentity
    intel_quote: str
    event_log: AttestationEventLog
    app_compose: str
    declared_spki_fingerprint: str | None = None
