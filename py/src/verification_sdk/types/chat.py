from pydantic import BaseModel

from .attestation_common import SigningAlgo


class Chat(BaseModel):
    request_body: bytes
    response_body: bytes


class ChatSignature(BaseModel):
    text: str
    signature: str
    signing_address: str
    signing_algo: SigningAlgo

