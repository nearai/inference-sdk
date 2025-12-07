from __future__ import annotations
from dataclasses import dataclass
from pydantic import BaseModel

from verification_sdk.types.attestation_common import SigningAlgo


@dataclass
class Chat(BaseModel):
    request_body: bytes
    response_body: bytes


@dataclass
class ChatSignature(BaseModel):
    text: str
    signature: str
    signing_address: str
    signing_algo: SigningAlgo

