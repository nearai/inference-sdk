"""Field encryption for the Gateway's Ed25519-v2 and legacy ECDSA protocols."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Literal

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from nacl import bindings
from nacl.signing import SigningKey

from ..types.attestation_common import SigningAlgo
from ..types.e2ee import E2eeModelKey
from ..utils.common import hex_to_bytes
from ..utils.errors import verification_failure


@dataclass(frozen=True, kw_only=True)
class Ed25519E2eeClientKeyPair:
    public_key: str
    x25519_secret_key: bytes
    signing_algo: Literal['ed25519'] = 'ed25519'


@dataclass(frozen=True, kw_only=True)
class EcdsaE2eeClientKeyPair:
    public_key: str
    private_key: ec.EllipticCurvePrivateKey
    signing_algo: Literal['ecdsa'] = 'ecdsa'


type E2eeClientKeyPair = Ed25519E2eeClientKeyPair | EcdsaE2eeClientKeyPair


def create_e2ee_client_key_pair(
    signing_algo: SigningAlgo = 'ed25519',
) -> E2eeClientKeyPair:
    """Create a fresh response key; never reuse it between Chat requests."""

    if signing_algo == 'ecdsa':
        private_key = ec.generate_private_key(ec.SECP256K1())
        return EcdsaE2eeClientKeyPair(
            public_key=_ecdsa_public_bytes(private_key)[1:].hex(),
            private_key=private_key,
        )
    key = SigningKey.generate()
    return Ed25519E2eeClientKeyPair(
        public_key=bytes(key.verify_key).hex(),
        x25519_secret_key=bytes(key.to_curve25519_private_key()),
    )


def encrypt_e2ee_text(plaintext: str, model_key: E2eeModelKey) -> str:
    """Encrypt a UTF-8 field for a quote-bound model public key."""

    public_key = hex_to_bytes(model_key.public_key, 'modelSigningPublicKey')
    if model_key.signing_algo == 'ecdsa':
        if len(public_key) == 64:
            public_key = b'\x04' + public_key
        if len(public_key) != 65 or public_key[0] != 4:
            raise verification_failure('e2ee.model_public_key_invalid')
        try:
            recipient = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256K1(), public_key
            )
        except ValueError as cause:
            raise verification_failure('e2ee.model_public_key_invalid', cause=cause)
        ephemeral = ec.generate_private_key(ec.SECP256K1())
        # ECDH returns the shared point's X coordinate, as in the server protocol.
        key = _derive_key(ephemeral.exchange(ec.ECDH(), recipient), b'ecdsa_encryption')
        nonce = secrets.token_bytes(12)
        ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode(), None)
        return (_ecdsa_public_bytes(ephemeral) + nonce + ciphertext).hex()

    try:
        recipient = bindings.crypto_sign_ed25519_pk_to_curve25519(public_key)
    except (ValueError, RuntimeError) as cause:
        raise verification_failure('e2ee.model_public_key_invalid', cause=cause)
    ephemeral_secret = secrets.token_bytes(32)
    ephemeral_public = bindings.crypto_scalarmult_base(ephemeral_secret)
    key = _derive_key(
        bindings.crypto_scalarmult(ephemeral_secret, recipient), b'ed25519_encryption'
    )
    nonce = secrets.token_bytes(24)
    ciphertext = bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintext.encode(), None, nonce, key
    )
    return (ephemeral_public + nonce + ciphertext).hex()


def decrypt_e2ee_text(
    ciphertext: str, client_key_pair: E2eeClientKeyPair, field: str
) -> str:
    """Decrypt a server field, reporting which field failed authentication."""

    # Empty encrypted fields are represented by an empty string on the wire.
    if ciphertext == '':
        return ''
    try:
        envelope = hex_to_bytes(ciphertext, field)
        if isinstance(client_key_pair, EcdsaE2eeClientKeyPair):
            if len(envelope) < 65 + 12 + 16 or envelope[0] != 4:
                raise ValueError('Invalid ECDSA envelope')
            ephemeral = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256K1(), envelope[:65]
            )
            key = _derive_key(
                client_key_pair.private_key.exchange(ec.ECDH(), ephemeral),
                b'ecdsa_encryption',
            )
            plaintext = AESGCM(key).decrypt(envelope[65:77], envelope[77:], None)
        else:
            if len(envelope) < 32 + 24 + 16:
                raise ValueError('Invalid Ed25519 envelope')
            key = _derive_key(
                bindings.crypto_scalarmult(
                    client_key_pair.x25519_secret_key, envelope[:32]
                ),
                b'ed25519_encryption',
            )
            plaintext = bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
                envelope[56:], None, envelope[32:56], key
            )
        return plaintext.decode('utf-8')
    except Exception as cause:
        raise verification_failure(
            'e2ee.decryption_failed', {'field': field}, cause=cause
        ) from cause


def _derive_key(shared_secret: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(
        shared_secret
    )


def _ecdsa_public_bytes(private_key: ec.EllipticCurvePrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
