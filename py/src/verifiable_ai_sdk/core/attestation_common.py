"""Nonce, report-data, and compose bindings shared by attestation flows."""

from __future__ import annotations

from ..types.attestation_common import SigningIdentity
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
        raise verification_failure('binding.nonce_mismatch', {'source': source})


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
            'binding.report_data_mismatch',
            {'source': 'reportedQuoteData'},
        )


def verify_report_data_binding(
    *,
    report_data: bytes,
    nonce: str,
    signer: SigningIdentity,
) -> None:
    """Verify the signer-and-nonce report-data layout.

    This layout is used for every Cloud model report and for Gateway reports
    fetched with TLS binding disabled.
    """

    _verify_quote_report_data_length_and_nonce(report_data, nonce)
    signing_address = hex_to_bytes(signer.signing_address, 'signer.signing_address')
    expected = signing_address.ljust(32, b'\x00')
    if report_data[:32] != expected:
        raise verification_failure(
            'binding.report_data_mismatch',
            {'source': 'signerBinding'},
        )


def verify_report_data_binding_with_tls_fingerprint(
    *,
    report_data: bytes,
    nonce: str,
    signer: SigningIdentity,
    reported_tls_spki_fingerprint: str | None,
    peer_tls_spki_fingerprint: str,
) -> str:
    """Verify the signer-and-TLS report-data layout and return its fingerprint."""

    _verify_quote_report_data_length_and_nonce(report_data, nonce)
    if reported_tls_spki_fingerprint is None:
        raise verification_failure('policy.tls_binding_required')
    reported = require_byte_length(
        reported_tls_spki_fingerprint, 32, 'attestation.tls_spki_fingerprint'
    )
    signing_address = hex_to_bytes(signer.signing_address, 'signer.signing_address')
    if report_data[:32] != sha256(signing_address + reported):
        raise verification_failure(
            'binding.report_data_mismatch',
            {'source': 'signerTlsBinding'},
        )

    peer = require_byte_length(
        peer_tls_spki_fingerprint,
        32,
        'client_binding.peer_spki_fingerprint',
    )
    if reported != peer:
        raise verification_failure('binding.spki_fingerprint_mismatch')
    return reported.hex()


def verify_app_compose_mrconfig_binding(app_compose: str, mr_config_id: bytes) -> None:
    if len(mr_config_id) < 33:
        raise verification_failure(
            'measurement.mrconfigid_invalid',
            {
                'reason': 'wrong_length',
                'minimumBytes': 33,
                'actualBytes': len(mr_config_id),
            },
        )
    if mr_config_id[0] != 1:
        raise verification_failure(
            'measurement.mrconfigid_invalid',
            {'reason': 'unsupported_version', 'version': mr_config_id[0]},
        )
    if mr_config_id[1:33] != sha256(app_compose.encode('utf-8')):
        raise verification_failure('measurement.app_compose_mrconfigid_mismatch')


def _verify_quote_report_data_length_and_nonce(report_data: bytes, nonce: str) -> None:
    if len(report_data) != 64:
        raise verification_failure(
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
            'binding.nonce_mismatch', {'source': 'quoteReportData'}
        )
