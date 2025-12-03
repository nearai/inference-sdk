from __future__ import annotations

import base64
from typing import Any, Dict, Union


def decode_jwt(jwt: str) -> Dict[str, Any]:
    """Decode the payload section of a JWT token (no verification)."""
    parts = jwt.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT format")

    payload = parts[1]

    try:
        data = base64.b64decode(payload)
        return json_loads(data)
    except Exception as e:
        raise ValueError("Invalid JWT payload") from e


def hex_to_bytes(value: str) -> bytes:
    """Convert hex string (with or without 0x prefix) to bytes."""
    value = value.lower()
    if value.startswith("0x"):
        value = value[2:]
    if not value or any(c not in "0123456789abcdef" for c in value):
        raise ValueError("Invalid hex string")
    return bytes.fromhex(value)


def json_loads(data: Union[bytes, str]) -> Dict[str, Any]:
    """Small wrapper to load JSON from bytes or str."""
    import json

    if isinstance(data, bytes):
        return json.loads(data.decode("utf-8"))
    return json.loads(data)

