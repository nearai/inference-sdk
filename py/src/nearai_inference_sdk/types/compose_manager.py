"""Compose Manager's signed deployment actions, not current-runtime state."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from .attestation_common import AttestationEventLog, TcbStatus

if TYPE_CHECKING:
    from .verification import RuntimeMeasurements

type ComposeManagerAction = dict[str, str | list[str]]


@dataclass(frozen=True, kw_only=True)
class ComposeManagerAttestation:
    actions: tuple[ComposeManagerAction, ...]
    actions_hash: str
    nonce: str
    intel_quote: str
    event_log: AttestationEventLog
    reported_quote_data: str | None = None


@dataclass(frozen=True, kw_only=True)
class VerifiedComposeManagerAttestation:
    """Actions authenticated under the model's measured app-compose configuration.

    Matching measurements do not identify a unique CVM or prove action success.
    """

    actions: tuple[ComposeManagerAction, ...]
    tcb_status: TcbStatus
    advisory_ids: tuple[str, ...]
    runtime_measurements: RuntimeMeasurements
