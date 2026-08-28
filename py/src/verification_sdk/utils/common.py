"""Small encoding and asynchronous helpers shared by verification modules."""

from __future__ import annotations

import base64
import hashlib
import inspect
import json
import re
import secrets
from collections.abc import Awaitable
from typing import TypeVar

from .errors import verification_failure


T = TypeVar('T')


def decode_jwt(jwt: str) -> dict[str, object]:
    if not isinstance(jwt, str):
        raise ValueError('Invalid JWT format')
    parts = jwt.split('.')
    if len(parts) != 3:
        raise ValueError('Invalid JWT format')

    payload = parts[1] + '=' * ((4 - len(parts[1]) % 4) % 4)
    try:
        decoded = json.loads(base64.urlsafe_b64decode(payload))
    except Exception as error:
        raise ValueError('Invalid JWT payload') from error
    if not isinstance(decoded, dict):
        raise ValueError('Invalid JWT payload')
    return decoded


def hex_to_bytes(value: str, field: str = 'hex') -> bytes:
    if not isinstance(value, str):
        raise verification_failure(
            'input', 'input.invalid', {'field': field, 'reason': 'invalid_hex'}
        )
    normalized = trim_hex_prefix(value)
    if (
        not normalized
        or len(normalized) % 2 != 0
        or re.fullmatch(r'[0-9a-fA-F]+', normalized) is None
    ):
        raise verification_failure(
            'input', 'input.invalid', {'field': field, 'reason': 'invalid_hex'}
        )
    return bytes.fromhex(normalized)


def trim_hex_prefix(value: str) -> str:
    if value.startswith(('0x', '0X')):
        return value[2:]
    return value


def normalize_hex(value: str, field: str = 'hex') -> str:
    return hex_to_bytes(value, field).hex()


def require_byte_length(value: str, length: int, field: str) -> bytes:
    raw = hex_to_bytes(value, field)
    if len(raw) != length:
        raise verification_failure(
            'input',
            'input.invalid',
            {
                'field': field,
                'reason': 'wrong_length',
                'expectedBytes': length,
                'actualBytes': len(raw),
            },
        )
    return raw


def require_instance(value: object, expected: type[T], field: str) -> T:
    """Require one public input type without turning it into a schema boundary."""

    if not isinstance(value, expected):
        raise verification_failure(
            'input',
            'input.invalid',
            {
                'field': field,
                'reason': 'unsupported_value',
                'expected': expected.__name__,
            },
        )
    return value


def generate_nonce() -> str:
    return secrets.token_hex(32)


def sha256(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def sha384(value: bytes) -> bytes:
    return hashlib.sha384(value).digest()


async def maybe_await(value: T | Awaitable[T]) -> T:
    if inspect.isawaitable(value):
        return await value
    return value
