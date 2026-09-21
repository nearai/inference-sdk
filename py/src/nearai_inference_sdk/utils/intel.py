"""Default Intel DCAP quote adapter."""

from __future__ import annotations

import json
from typing import cast

from dcap_qvl import Quote, get_collateral, verify

from ..types.attestation_common import SUPPORTED_TCB_STATUSES, TcbStatus
from ..types.verification import TdxQuoteVerificationResult, TdxQuoteVerifier
from .common import hex_to_bytes
from .consts import INTEL_PCCS_API_URL
from .errors import VerificationError, verification_failure


def create_tdx_quote_verifier(
    pccs_url: str = INTEL_PCCS_API_URL,
) -> TdxQuoteVerifier:
    """Create the Intel DCAP verifier with a PCCS-compatible collateral URL."""

    async def verify_quote(quote: str) -> TdxQuoteVerificationResult:
        return await verify_dcap_quote(quote, pccs_url)

    return verify_quote


async def verify_dcap_quote(
    quote: str, pccs_url: str = INTEL_PCCS_API_URL
) -> TdxQuoteVerificationResult:
    """Verify a TDX quote and expose the facts used by the SDK core."""

    try:
        quote_bytes = hex_to_bytes(quote, 'attestation.intel_quote')
    except VerificationError as error:
        raise verification_failure(
            'quote.verification_failed',
            {'reason': 'invalid_encoding'},
            cause=error,
        ) from error

    try:
        Quote.parse(quote_bytes)
    except Exception as error:
        raise verification_failure(
            'quote.verification_failed',
            {'reason': 'invalid_quote'},
            cause=error,
        ) from error

    try:
        collateral = await get_collateral(pccs_url, quote_bytes)
    except Exception as error:
        raise verification_failure(
            'quote.collateral_unavailable', retryable=True, cause=error
        ) from error

    try:
        verified = verify(quote_bytes, collateral, _unix_time())
    except Exception as error:
        raise verification_failure(
            'quote.verification_failed',
            {'reason': 'verifier_error'},
            cause=error,
        ) from error

    try:
        raw = json.loads(verified.to_json())
        td10 = _td10_base(raw['report'])
        report_data = _decode_quote_bytes(td10['report_data'], 'report_data')
        mr_config_id = _decode_quote_bytes(td10['mr_config_id'], 'mr_config_id')
        rt_mr3 = _decode_quote_bytes(td10['rt_mr3'], 'rt_mr3')
        attributes = _decode_quote_bytes(td10['td_attributes'], 'td_attributes')
        status = verified.status
        advisory_ids = tuple(verified.advisory_ids)
    except KeyError as error:
        if error.args == ('TD10',):
            raise verification_failure(
                'quote.unsupported_report_type',
                {'expected': 'TD10'},
                cause=error,
            ) from error
        raise _invalid_quote_result(error) from error
    except (TypeError, ValueError) as error:
        raise _invalid_quote_result(error) from error

    if not isinstance(status, str) or status not in SUPPORTED_TCB_STATUSES:
        raise _invalid_quote_result()
    if not all(isinstance(advisory, str) for advisory in advisory_ids):
        raise _invalid_quote_result()
    if not attributes:
        raise _invalid_quote_result()

    return TdxQuoteVerificationResult(
        tcb_status=cast(TcbStatus, status),
        advisory_ids=advisory_ids,
        debug_enabled=(attributes[0] & 0x01) != 0,
        report_data=report_data,
        mr_config_id=mr_config_id,
        rt_mr3=rt_mr3,
    )


def _decode_quote_bytes(value: object, path: str) -> bytes:
    """Decode dcap-qvl's JSON byte encoding across supported package releases."""

    if isinstance(value, str):
        try:
            return hex_to_bytes(value, path)
        except VerificationError as error:
            raise ValueError(f'{path} is not hexadecimal text') from error
    if isinstance(value, list) and all(
        isinstance(item, int) and not isinstance(item, bool) and 0 <= item <= 255
        for item in value
    ):
        return bytes(value)
    raise ValueError(f'{path} is not a byte sequence')


def _td10_base(report: object) -> dict[str, object]:
    """Return TD1.0 measurements from a TD1.0 or TD1.5 report."""

    if not isinstance(report, dict):
        raise TypeError('report is not an object')
    if 'TD10' in report:
        td10 = report['TD10']
        if isinstance(td10, dict):
            return td10
        raise TypeError('TD10 is not an object')
    if 'TD15' not in report:
        raise KeyError('TD10')
    td15 = report['TD15']
    if not isinstance(td15, dict):
        raise TypeError('TD15 is not an object')
    base = td15.get('base')
    if not isinstance(base, dict):
        raise TypeError('TD15.base is not an object')
    return base


def _invalid_quote_result(cause: BaseException | None = None) -> VerificationError:
    return verification_failure(
        'quote.invalid_result',
        {
            'path': 'dcap_result',
            'expected': 'verified TD10 or TD15 quote',
            'actual': 'unreadable',
        },
        cause=cause,
    )


def _unix_time() -> int:
    import time

    return int(time.time())
