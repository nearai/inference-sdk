"""Cross-language protocol fixtures for the two supported E2EE algorithms."""

from cryptography.hazmat.primitives.asymmetric import ec
from nacl.signing import SigningKey

from nearai_inference_sdk.core.e2ee import (
    EcdsaE2eeClientKeyPair,
    Ed25519E2eeClientKeyPair,
    decrypt_e2ee_text,
)


def test_decrypts_fixed_ed25519_v2_protocol_vector():
    key = SigningKey(bytes([11]) * 32)
    client_key_pair = Ed25519E2eeClientKeyPair(
        public_key=bytes(key.verify_key).hex(),
        x25519_secret_key=bytes(key.to_curve25519_private_key()),
    )
    # Shared with the TypeScript fixture; independently generated server envelope.
    ciphertext = (
        '07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c'
        'a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7'
        '43d22a6968fbbdf88cd066c79b3dacd53a6991f06ce8c564e03b7eb60e2376'
    )
    assert (
        decrypt_e2ee_text(ciphertext, client_key_pair, 'content') == 'fixed v2 vector'
    )


def test_decrypts_fixed_ecdsa_protocol_vector():
    client_key_pair = EcdsaE2eeClientKeyPair(
        public_key=(
            '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
            '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'
        ),
        private_key=ec.derive_private_key(1, ec.SECP256K1()),
    )
    ciphertext = (
        '04c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5'
        '1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a'
        '000102030405060708090a0b'
        'b70c17944e668fbe04a547595e40927c708a34b9e7c4cb5b9917a6fb2240653b2a142b86'
    )
    assert (
        decrypt_e2ee_text(ciphertext, client_key_pair, 'content')
        == 'near-ai ecdsa vector'
    )
