from __future__ import annotations
from dataclasses import dataclass
from pydantic import BaseModel
from typing import Literal


SigningAlgo = Literal["ecdsa", "ed25519"]


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

