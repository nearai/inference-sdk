import nacl.signing

from hashlib import sha256
from eth_account import Account
from eth_account.messages import encode_defunct

from ..types.attestation_model import ModelAttestation
from ..types.chat import Chat, ChatSignature
from ..utils.common import hex_to_bytes
from ..utils.errors import VerificationError


def verify_chat(message: Chat, signature: ChatSignature):
    verify_chat_hash(signature.text, message.request_body, message.response_body)
    verify_chat_signature(signature)


def verify_signing_address(
    signature: ChatSignature,
    attestations: list[ModelAttestation],
):
    for attestation in attestations:
        if (
                signature.signing_algo == attestation.signing_algo
                and hex_to_bytes(signature.signing_address)
                == hex_to_bytes(attestation.signing_address)
        ):
            return

    raise VerificationError(
        'The signature signing algorithm or address does not match any of the model attestations'
    )


def verify_chat_signature(signature: ChatSignature):
    if signature.signing_algo == 'ecdsa':
        message = encode_defunct(text=signature.text)
        try:
            recovered = Account.recover_message(message, signature=signature.signature)
        except Exception as e:
            raise VerificationError('Invalid ECDSA chat signature') from e

        recovered_raw = hex_to_bytes(recovered)
        signing_raw = hex_to_bytes(signature.signing_address)
        if recovered_raw != signing_raw:
            raise VerificationError('Invalid ECDSA chat signature')
    else:
        public_key = hex_to_bytes(signature.signing_address)
        sig_bytes = hex_to_bytes(signature.signature)
        verify_key = nacl.signing.VerifyKey(public_key)
        try:
            verify_key.verify(signature.text.encode('utf-8'), sig_bytes)
        except Exception as e:
            raise VerificationError('Invalid ED25519 chat signature') from e


def verify_chat_hash(text: str, request_body: bytes, response_body: bytes):
    expected = f'{sha256(request_body).hexdigest()}:{sha256(response_body).hexdigest()}'
    if text != expected:
        raise VerificationError('Chat hash mismatching')

