"""Small encoding and asynchronous helpers shared by verification modules."""

from __future__ import annotations

import hashlib
import inspect
import re
import secrets
from collections.abc import Awaitable
from typing import TypeVar

from .errors import verification_failure


T = TypeVar('T')


def hex_to_bytes(value: str, field: str = 'hex') -> bytes:
    normalized = trim_hex_prefix(value)
    if (
        not normalized
        or len(normalized) % 2 != 0
        or re.fullmatch(r'[0-9a-fA-F]+', normalized) is None
    ):
        raise verification_failure(
            'input.invalid', {'field': field, 'reason': 'invalid_hex'}
        )
    return bytes.fromhex(normalized)


def trim_hex_prefix(value: str) -> str:
    if value.startswith(('0x', '0X')):
        return value[2:]
    return value


def require_byte_length(value: str, length: int, field: str) -> bytes:
    raw = hex_to_bytes(value, field)
    if len(raw) != length:
        raise verification_failure(
            'input.invalid',
            {
                'field': field,
                'reason': 'wrong_length',
                'expectedBytes': length,
                'actualBytes': len(raw),
            },
        )
    return raw


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
