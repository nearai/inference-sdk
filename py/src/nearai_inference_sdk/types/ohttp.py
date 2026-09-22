"""Signed OHTTP key configuration advertised by Gateway evidence."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True, kw_only=True)
class OhttpAttestation:
    """Hexadecimal key material and a signature over raw configuration bytes."""

    signing_algo: Literal['ed25519']
    signing_key: str
    key_config: str
    signature: str
