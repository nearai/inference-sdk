from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from nearai_inference_sdk import VerificationError, create_tdx_quote_verifier
from nearai_inference_sdk.core.dstack_attestation import verify_tdx_quote
from nearai_inference_sdk.types.attestation_common import TcbStatus
from nearai_inference_sdk.types.verification import AttestationPolicy
from nearai_inference_sdk.utils import intel

from .fixtures import create_model_quote


async def test_quote_factories_route_collateral_and_keep_configuration_isolated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    quote = create_model_quote()
    collateral = object()
    requests: list[tuple[str, bytes]] = []
    verified_quotes: list[tuple[bytes, object, int]] = []
    parsed_quotes: list[bytes] = []
    report = {
        'report': {
            'TD10': {
                'report_data': quote.report_data.hex(),
                'mr_config_id': quote.mr_config_id.hex(),
                'rt_mr3': quote.rt_mr3.hex(),
                'td_attributes': '00' * 8,
            }
        }
    }

    async def get_collateral(url: str, raw: bytes) -> object:
        requests.append((url, raw))
        return collateral

    def verify(raw: bytes, supplied_collateral: object, now: int) -> object:
        verified_quotes.append((raw, supplied_collateral, now))
        return SimpleNamespace(
            status=quote.tcb_status,
            advisory_ids=quote.advisory_ids,
            to_json=lambda: json.dumps(report),
        )

    monkeypatch.setattr(intel, 'Quote', SimpleNamespace(parse=parsed_quotes.append))
    monkeypatch.setattr(intel, 'get_collateral', get_collateral)
    monkeypatch.setattr(intel, 'verify', verify)
    monkeypatch.setattr(intel, '_unix_time', lambda: 1800000000)
    first = create_tdx_quote_verifier(pccs_url='https://first.example/pccs')
    second = create_tdx_quote_verifier(pccs_url='https://second.example/pccs')
    default = create_tdx_quote_verifier()
    for verifier in (first, second, first, default, intel.verify_dcap_quote):
        assert await verifier('aabb') == quote

    assert requests == [
        ('https://first.example/pccs', b'\xaa\xbb'),
        ('https://second.example/pccs', b'\xaa\xbb'),
        ('https://first.example/pccs', b'\xaa\xbb'),
        ('https://api.trustedservices.intel.com', b'\xaa\xbb'),
        ('https://api.trustedservices.intel.com', b'\xaa\xbb'),
    ]
    assert parsed_quotes == [b'\xaa\xbb'] * 5
    assert verified_quotes == [(b'\xaa\xbb', collateral, 1800000000)] * 5


@pytest.mark.parametrize(
    ('report_type', 'status', 'accepted_by_default'),
    [
        ('TD15', 'TDRelaunchAdvised', True),
        ('TD15Ex', 'TDRelaunchAdvisedConfigurationNeeded', False),
    ],
)
async def test_dcap_td15_reports_and_tcb_policy(
    monkeypatch: pytest.MonkeyPatch,
    report_type: str,
    status: TcbStatus,
    accepted_by_default: bool,
) -> None:
    quote = create_model_quote()
    td10 = {
        'report_data': quote.report_data.hex(),
        'mr_config_id': quote.mr_config_id.hex(),
        'rt_mr3': quote.rt_mr3.hex(),
        'td_attributes': '00' * 8,
    }
    report_body = {'base': td10}
    if report_type == 'TD15Ex':
        report_body = {'base': report_body}
    verified = SimpleNamespace(
        status=status,
        advisory_ids=(),
        to_json=lambda: json.dumps({'report': {report_type: report_body}}),
    )

    async def get_collateral(_: str, __: bytes) -> object:
        return object()

    monkeypatch.setattr(intel, 'Quote', SimpleNamespace(parse=lambda _: None))
    monkeypatch.setattr(intel, 'get_collateral', get_collateral)
    monkeypatch.setattr(intel, 'verify', lambda *_: verified)
    result = await intel.verify_dcap_quote('aabb')
    assert result.report_data == quote.report_data
    assert result.mr_config_id == quote.mr_config_id
    assert result.rt_mr3 == quote.rt_mr3
    assert result.tcb_status == status
    if accepted_by_default:
        assert await verify_tdx_quote('aabb', None, None) == result
    else:
        with pytest.raises(VerificationError) as raised:
            await verify_tdx_quote('aabb', None, None)
        assert raised.value.failure.code == 'policy.tcb_status_not_allowed'
    policy = AttestationPolicy(accepted_tcb_statuses=(status,))
    assert await verify_tdx_quote('aabb', policy, None) == result


@pytest.mark.parametrize('stage', ['collateral', 'verification'])
async def test_quote_factory_propagates_collateral_and_verification_failures(
    monkeypatch: pytest.MonkeyPatch, stage: str
) -> None:
    requests: list[str] = []
    verification_calls: list[bytes] = []

    async def get_collateral(url: str, _: bytes) -> object:
        requests.append(url)
        if stage == 'collateral':
            raise OSError('unavailable')
        return object()

    def verify(raw: bytes, _: object, __: int) -> None:
        verification_calls.append(raw)
        raise ValueError('untrusted collateral')

    monkeypatch.setattr(intel, 'Quote', SimpleNamespace(parse=lambda _: None))
    monkeypatch.setattr(intel, 'get_collateral', get_collateral)
    monkeypatch.setattr(intel, 'verify', verify)
    verifier = create_tdx_quote_verifier(pccs_url='https://proxy.example/pccs')
    with pytest.raises(VerificationError) as raised:
        await verifier('aabb')

    assert requests == ['https://proxy.example/pccs']
    if stage == 'collateral':
        assert raised.value.failure.code == 'quote.collateral_unavailable'
        assert raised.value.retryable
        assert verification_calls == []
    else:
        assert raised.value.failure.code == 'quote.verification_failed'
        assert raised.value.failure.details == {'reason': 'verifier_error'}
        assert not raised.value.retryable
        assert verification_calls == [b'\xaa\xbb']
