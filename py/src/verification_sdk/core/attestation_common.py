"""Nonce, report-data, and compose bindings shared by attestation flows."""

from __future__ import annotations

from ..types.attestation_common import SigningIdentity
from ..types.verification import GatewayTlsBinding, ModelTlsBinding
from ..utils.common import hex_to_bytes, require_byte_length, sha256
from ..utils.errors import VerificationError, verification_failure


def verify_reported_nonce(
    reported_nonce: str,
    nonce: str,
    source: str = 'attestationNonce',
) -> None:
    expected = require_byte_length(nonce, 32, 'nonce')
    field = 'nvidia_payload.nonce' if source == 'nvidiaPayload' else 'attestation.nonce'
    reported = require_byte_length(reported_nonce, 32, field)
    if reported != expected:
        raise verification_failure(
            'binding', 'binding.nonce_mismatch', {'source': source}
        )


def verify_advertised_report_data(
    advertised_report_data: str | None,
    quote_report_data: bytes,
) -> None:
    if advertised_report_data is None:
        return
    try:
        advertised = hex_to_bytes(
            advertised_report_data, 'attestation.reported_quote_data'
        )
    except VerificationError as error:
        raise verification_failure(
            'binding',
            'binding.report_data_invalid',
            {
                'source': 'reportedQuoteData',
                'reason': 'invalid_hex',
                'expectedBytes': 64,
            },
            cause=error,
        ) from error
    if len(advertised) != 64:
        raise verification_failure(
            'binding',
            'binding.report_data_invalid',
            {
                'source': 'reportedQuoteData',
                'reason': 'wrong_length',
                'expectedBytes': 64,
                'actualBytes': len(advertised),
            },
        )
    if advertised != quote_report_data:
        raise verification_failure(
            'binding',
            'binding.report_data_mismatch',
            {'source': 'reportedQuoteData'},
        )


def verify_model_report_data_binding(
    *,
    report_data: bytes,
    nonce: str,
    signer: SigningIdentity,
    reported_spki_fingerprint: str | None,
) -> ModelTlsBinding:
    _verify_quote_report_data_length_and_nonce(report_data, nonce)
    signing_address = hex_to_bytes(signer.signing_address, 'signer.signing_address')

    if reported_spki_fingerprint is not None:
        fingerprint = require_byte_length(
            reported_spki_fingerprint, 32, 'attestation.declared_spki_fingerprint'
        )
        expected = sha256(signing_address + fingerprint)
        if report_data[:32] != expected:
            raise verification_failure(
                'binding',
                'binding.report_data_mismatch',
                {'source': 'signerTlsBinding'},
            )
        return ModelTlsBinding(kind='declared', spki_fingerprint=fingerprint.hex())

    expected = signing_address.ljust(32, b'\x00')
    if report_data[:32] != expected:
        raise verification_failure(
            'binding',
            'binding.report_data_mismatch',
            {'source': 'signerBinding'},
        )
    return ModelTlsBinding(kind='none')


def verify_gateway_report_data_binding(
    *,
    report_data: bytes,
    nonce: str,
    signer: SigningIdentity,
    reported_spki_fingerprint: str | None,
    peer_spki_fingerprint: str,
) -> GatewayTlsBinding:
    _verify_quote_report_data_length_and_nonce(report_data, nonce)
    if not reported_spki_fingerprint:
        raise verification_failure('binding', 'binding.spki_fingerprint_missing')

    reported = require_byte_length(
        reported_spki_fingerprint, 32, 'attestation.declared_spki_fingerprint'
    )
    peer = require_byte_length(peer_spki_fingerprint, 32, 'peer_spki_fingerprint')
    if reported != peer:
        raise verification_failure(
            'binding',
            'binding.spki_fingerprint_mismatch',
            {'source': 'peer_tls_connection'},
        )

    signing_address = hex_to_bytes(signer.signing_address, 'signer.signing_address')
    if report_data[:32] != sha256(signing_address + reported):
        raise verification_failure(
            'binding',
            'binding.report_data_mismatch',
            {'source': 'signerTlsBinding'},
        )
    return GatewayTlsBinding(kind='peer', spki_fingerprint=reported.hex())


def verify_app_compose_mrconfig_binding(app_compose: str, mr_config_id: bytes) -> None:
    if len(mr_config_id) < 33:
        raise verification_failure(
            'measurement',
            'measurement.mrconfigid_invalid',
            {
                'reason': 'wrong_length',
                'minimumBytes': 33,
                'actualBytes': len(mr_config_id),
            },
        )
    if mr_config_id[0] != 1:
        raise verification_failure(
            'measurement',
            'measurement.mrconfigid_invalid',
            {'reason': 'unsupported_version', 'version': mr_config_id[0]},
        )
    if mr_config_id[1:33] != sha256(app_compose.encode('utf-8')):
        raise verification_failure(
            'measurement', 'measurement.app_compose_mrconfigid_mismatch'
        )


def _verify_quote_report_data_length_and_nonce(report_data: bytes, nonce: str) -> None:
    if len(report_data) != 64:
        raise verification_failure(
            'binding',
            'binding.report_data_invalid',
            {
                'source': 'quoteReportData',
                'reason': 'wrong_length',
                'expectedBytes': 64,
                'actualBytes': len(report_data),
            },
        )
    expected_nonce = require_byte_length(nonce, 32, 'nonce')
    if report_data[32:64] != expected_nonce:
        raise verification_failure(
            'binding', 'binding.nonce_mismatch', {'source': 'quoteReportData'}
        )
