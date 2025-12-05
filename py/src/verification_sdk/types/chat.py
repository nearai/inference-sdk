from dataclasses import dataclass
from typing import Literal


SigningAlgo = Literal["ecdsa", "ed25519"]


@dataclass
class Chat:
    """Chat message pair used for signature verification."""

    request_body: bytes
    response_body: bytes


@dataclass
class ChatSignature:
    """Signature payload returned by the NEAR AI Cloud API."""

    text: str
    signature: str
    signing_address: str
    signing_algo: SigningAlgo


