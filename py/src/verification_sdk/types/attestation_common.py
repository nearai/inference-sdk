from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict


@dataclass
class TcbInfo:
    """Subset of TcbInfo we care about for compose verification."""

    app_compose: str
    # Additional fields are allowed but not modeled strictly here
    extra: Dict[str, Any] | None = None


