import base64
import re
import json


def decode_jwt(jwt: str) -> dict:
    parts = jwt.split('.')
    if len(parts) != 3:
        raise ValueError('Invalid JWT format')

    payload = parts[1]

    try:
        data = base64.b64decode(payload)
        return json.loads(data)
    except Exception as e:
        raise ValueError('Invalid JWT payload') from e


def hex_to_bytes(value: str) -> bytes:
    m = re.compile(r'^(?:0x)?([0-9a-f]+)$', re.IGNORECASE).match(value)

    if not m:
        raise ValueError('Invalid hex string')

    return bytes.fromhex(m.group(1))

