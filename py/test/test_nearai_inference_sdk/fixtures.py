"""Deterministic evidence used by the public SDK contract tests."""

from __future__ import annotations

from dataclasses import replace

from nearai_inference_sdk import (
    GatewayAttestation,
    ModelClientBinding,
    ModelAttestation,
    QuoteVerificationResult,
    SigningIdentity,
)

from nearai_inference_sdk.utils.common import sha256, sha384


NONCE = '11' * 32
MODEL_CLIENT_BINDING = ModelClientBinding(nonce=NONCE)
SIGNING_ADDRESS = f'0x{"22" * 20}'
TLS_FINGERPRINT = '33' * 32
APP_COMPOSE = (
    '{"services":{"model":"example@sha256:'
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}'
)


def create_gateway_tls_quote(
    *,
    signing_address: str = SIGNING_ADDRESS,
    tls_fingerprint: str = TLS_FINGERPRINT,
    **overrides: object,
) -> QuoteVerificationResult:
    signing_address_bytes = bytes.fromhex(signing_address.removeprefix('0x'))
    report_prefix = sha256(signing_address_bytes + bytes.fromhex(tls_fingerprint))
    quote = QuoteVerificationResult(
        tcb_status='UpToDate',
        advisory_ids=(),
        debug_enabled=False,
        report_data=report_prefix + bytes.fromhex(NONCE),
        mr_config_id=b'\x01' + sha256(APP_COMPOSE.encode()) + bytes(15),
        rt_mr3=sha384(bytes(48) + bytes(48)),
    )
    return replace(quote, **overrides)


def create_model_quote(
    *,
    signing_address: str = SIGNING_ADDRESS,
    **overrides: object,
) -> QuoteVerificationResult:
    signing_address_bytes = bytes.fromhex(signing_address.removeprefix('0x'))
    report_prefix = signing_address_bytes.ljust(32, b'\x00')
    quote = QuoteVerificationResult(
        tcb_status='UpToDate',
        advisory_ids=(),
        debug_enabled=False,
        report_data=report_prefix + bytes.fromhex(NONCE),
        mr_config_id=b'\x01' + sha256(APP_COMPOSE.encode()) + bytes(15),
        rt_mr3=sha384(bytes(48) + bytes(48)),
    )
    return replace(quote, **overrides)


def create_model_attestation(**overrides: object) -> ModelAttestation:
    attestation = ModelAttestation(
        nonce=NONCE,
        signer=SigningIdentity(signing_algo='ecdsa', signing_address=SIGNING_ADDRESS),
        intel_quote='aa',
        event_log=[
            {
                'digest': '00' * 48,
                'event_type': 0,
                'event': 'compose-hash',
                'event_payload': 'beef',
                'imr': 3,
            }
        ],
        app_compose=APP_COMPOSE,
    )
    return replace(attestation, **overrides)


def create_gateway_attestation(**overrides: object) -> GatewayAttestation:
    quote = create_gateway_tls_quote()
    attestation = GatewayAttestation(
        nonce=NONCE,
        signer=SigningIdentity(signing_algo='ecdsa', signing_address=SIGNING_ADDRESS),
        intel_quote='aa',
        event_log=[
            {
                'digest': '00' * 48,
                'event_type': 0,
                'event': 'compose-hash',
                'event_payload': 'beef',
                'imr': 3,
            }
        ],
        app_compose=APP_COMPOSE,
        spki_fingerprint=TLS_FINGERPRINT,
        reported_quote_data=quote.report_data.hex(),
    )
    return replace(attestation, **overrides)
