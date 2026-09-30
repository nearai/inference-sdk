"""Authenticate OHTTP configuration bytes against a verified Gateway signer."""

from __future__ import annotations

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from ..types.attestation_common import SigningIdentity
from ..types.ohttp import OhttpAttestation
from ..utils.common import hex_to_bytes, require_byte_length
from ..utils.errors import verification_failure


def verify_ohttp_key_config(
    ohttp_attestation: OhttpAttestation, signer: SigningIdentity
) -> bytes:
    """Return signed raw configuration bytes bound to a verified Gateway signer.

    The caller must first verify the Gateway attestation that supplied ``signer``.
    The returned configuration still requires protocol parsing before use.
    """

    if signer.signing_algo != 'ed25519':
        raise verification_failure('ohttp.signer_mismatch')
    signing_key = require_byte_length(
        ohttp_attestation.signing_key, 32, 'ohttp_attestation.signing_key'
    )
    authenticated_key = require_byte_length(
        signer.signing_address, 32, 'signer.signing_address'
    )
    if signing_key != authenticated_key:
        raise verification_failure('ohttp.signer_mismatch')
    key_config = hex_to_bytes(
        ohttp_attestation.key_config, 'ohttp_attestation.key_config'
    )
    signature = hex_to_bytes(ohttp_attestation.signature, 'ohttp_attestation.signature')
    if len(signature) != 64:
        raise verification_failure('ohttp.signature_invalid')
    try:
        VerifyKey(signing_key).verify(key_config, signature)
    except (BadSignatureError, ValueError) as error:
        raise verification_failure('ohttp.signature_invalid', cause=error) from error
    return key_config
