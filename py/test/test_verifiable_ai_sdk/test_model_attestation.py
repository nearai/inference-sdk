from __future__ import annotations

import base64
import json
from dataclasses import replace

import pytest

import verifiable_ai_sdk.utils.nvidia as nvidia
from verifiable_ai_sdk import (
    ModelAttestationPolicy,
    ModelAttestationVerifiers,
    VerificationError,
    verify_model_attestation,
)
from verifiable_ai_sdk.utils.fetch import FetchResponse

from .fixtures import (
    APP_COMPOSE,
    MODEL_CLIENT_BINDING,
    NONCE,
    create_model_attestation,
    create_model_quote,
    create_gateway_tls_quote,
)


def nras_jwt(claims: object) -> str:
    encoded_payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode()
    return f'header.{encoded_payload.rstrip("=")}.signature'


def use_fake_nras_response(monkeypatch: pytest.MonkeyPatch, body: object) -> None:
    async def fake_fetch(_: str, **__: object) -> FetchResponse:
        return FetchResponse(status=200, body=json.dumps(body).encode())

    monkeypatch.setattr(nvidia, 'fetch', fake_fetch)


async def test_model_attestation_returns_verified_evidence() -> None:
    result = await verify_model_attestation(
        create_model_attestation(),
        MODEL_CLIENT_BINDING,
        verifiers=ModelAttestationVerifiers(quote=lambda _: create_model_quote()),
    )

    assert result.tcb_status == 'UpToDate'
    assert result.gpu_evidence == 'not_provided'
    assert result.deployment.app_compose == APP_COMPOSE
    assert result.deployment_provenance == 'not_checked'


async def test_model_attestation_uses_signer_nonce_report_data_binding() -> None:
    result = await verify_model_attestation(
        create_model_attestation(),
        MODEL_CLIENT_BINDING,
        verifiers=ModelAttestationVerifiers(quote=lambda _: create_model_quote()),
    )

    assert not hasattr(result, 'tls_binding')


async def test_model_attestation_rejects_gateway_tls_report_data_layout() -> None:
    with pytest.raises(VerificationError) as raised:
        await verify_model_attestation(
            create_model_attestation(),
            MODEL_CLIENT_BINDING,
            verifiers=ModelAttestationVerifiers(
                quote=lambda _: create_gateway_tls_quote()
            ),
        )

    assert raised.value.failure.code == 'binding.report_data_mismatch'
    assert raised.value.failure.details == {'source': 'signerBinding'}


async def test_model_attestation_checks_advertised_quote_report_data() -> None:
    quote = create_model_quote()

    result = await verify_model_attestation(
        create_model_attestation(reported_quote_data=quote.report_data.hex()),
        MODEL_CLIENT_BINDING,
        verifiers=ModelAttestationVerifiers(quote=lambda _: quote),
    )
    assert result.tcb_status == 'UpToDate'

    with pytest.raises(VerificationError) as raised:
        await verify_model_attestation(
            create_model_attestation(reported_quote_data='44' * 64),
            MODEL_CLIENT_BINDING,
            verifiers=ModelAttestationVerifiers(quote=lambda _: quote),
        )
    assert raised.value.failure.code == 'binding.report_data_mismatch'


async def test_model_attestation_rejects_mismatched_nonce_before_quote() -> None:
    with pytest.raises(VerificationError) as raised:
        await verify_model_attestation(
            create_model_attestation(nonce='44' * 32),
            MODEL_CLIENT_BINDING,
            verifiers=ModelAttestationVerifiers(quote=lambda _: create_model_quote()),
        )

    assert raised.value.failure.code == 'binding.nonce_mismatch'
    assert raised.value.failure.details == {'source': 'attestationNonce'}


async def test_model_policy_accepts_out_of_date_by_default_and_can_tighten() -> None:
    quote = create_model_quote(tcb_status='OutOfDate')
    result = await verify_model_attestation(
        create_model_attestation(),
        MODEL_CLIENT_BINDING,
        verifiers=ModelAttestationVerifiers(quote=lambda _: quote),
    )
    assert result.tcb_status == 'OutOfDate'

    with pytest.raises(VerificationError) as raised:
        await verify_model_attestation(
            create_model_attestation(),
            MODEL_CLIENT_BINDING,
            policy=ModelAttestationPolicy(accepted_tcb_statuses=('UpToDate',)),
            verifiers=ModelAttestationVerifiers(quote=lambda _: quote),
        )
    assert raised.value.failure.code == 'policy.tcb_status_not_allowed'


async def test_model_gpu_policy_and_nonce_binding() -> None:
    with pytest.raises(VerificationError) as missing:
        await verify_model_attestation(
            create_model_attestation(),
            MODEL_CLIENT_BINDING,
            policy=ModelAttestationPolicy(gpu_evidence='required'),
            verifiers=ModelAttestationVerifiers(quote=lambda _: create_model_quote()),
        )
    assert missing.value.failure.code == 'policy.gpu_evidence_required'

    async def verify_gpu(_: str) -> None:
        pass

    with pytest.raises(VerificationError) as mismatch:
        await verify_model_attestation(
            create_model_attestation(nvidia_payload=json.dumps({'nonce': '55' * 32})),
            MODEL_CLIENT_BINDING,
            verifiers=ModelAttestationVerifiers(
                quote=lambda _: create_model_quote(), nvidia=verify_gpu
            ),
        )
    assert mismatch.value.failure.code == 'binding.nonce_mismatch'

    result = await verify_model_attestation(
        create_model_attestation(nvidia_payload=json.dumps({'nonce': NONCE})),
        MODEL_CLIENT_BINDING,
        verifiers=ModelAttestationVerifiers(
            quote=lambda _: create_model_quote(), nvidia=verify_gpu
        ),
    )
    assert result.gpu_evidence == 'verified'


async def test_empty_gpu_payload_remains_invalid_supplied_json() -> None:
    with pytest.raises(VerificationError) as raised:
        await verify_model_attestation(
            create_model_attestation(nvidia_payload=''),
            MODEL_CLIENT_BINDING,
            verifiers=ModelAttestationVerifiers(quote=lambda _: create_model_quote()),
        )
    assert raised.value.failure.code == 'gpu.payload_invalid'
    assert raised.value.failure.details == {'reason': 'invalid_json'}


async def test_default_nras_rejects_a_malformed_envelope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    use_fake_nras_response(monkeypatch, [['TOKEN', 'not-a-jwt']])

    with pytest.raises(VerificationError) as raised:
        await verify_model_attestation(
            create_model_attestation(nvidia_payload=json.dumps({'nonce': NONCE})),
            MODEL_CLIENT_BINDING,
            verifiers=ModelAttestationVerifiers(quote=lambda _: create_model_quote()),
        )

    assert raised.value.failure.code == 'gpu.nras_response_invalid'
    assert raised.value.failure.details == {'reason': 'invalid_schema'}


async def test_default_nras_rejects_an_invalid_jwt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    use_fake_nras_response(monkeypatch, [['JWT', 'not-a-jwt']])

    with pytest.raises(VerificationError) as raised:
        await verify_model_attestation(
            create_model_attestation(nvidia_payload=json.dumps({'nonce': NONCE})),
            MODEL_CLIENT_BINDING,
            verifiers=ModelAttestationVerifiers(quote=lambda _: create_model_quote()),
        )

    assert raised.value.failure.code == 'gpu.nras_response_invalid'
    assert raised.value.failure.details == {'reason': 'invalid_jwt'}


async def test_default_nras_rejects_a_non_boolean_verdict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    use_fake_nras_response(
        monkeypatch,
        [['JWT', nras_jwt({'x-nvidia-overall-att-result': 'PASS'})]],
    )

    with pytest.raises(VerificationError) as raised:
        await verify_model_attestation(
            create_model_attestation(nvidia_payload=json.dumps({'nonce': NONCE})),
            MODEL_CLIENT_BINDING,
            verifiers=ModelAttestationVerifiers(quote=lambda _: create_model_quote()),
        )

    assert raised.value.failure.code == 'gpu.nras_response_invalid'
    assert raised.value.failure.details == {'reason': 'invalid_verdict_type'}


async def test_default_nras_rejects_a_false_verdict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    use_fake_nras_response(
        monkeypatch,
        [['JWT', nras_jwt({'x-nvidia-overall-att-result': False})]],
    )

    with pytest.raises(VerificationError) as raised:
        await verify_model_attestation(
            create_model_attestation(nvidia_payload=json.dumps({'nonce': NONCE})),
            MODEL_CLIENT_BINDING,
            verifiers=ModelAttestationVerifiers(quote=lambda _: create_model_quote()),
        )

    assert raised.value.failure.code == 'gpu.attestation_rejected'
    assert raised.value.failure.details == {'source': 'nras'}


async def test_model_attestation_rejects_invalid_custom_quote_results() -> None:
    quote = replace(create_model_quote(), tcb_status=[])

    with pytest.raises(VerificationError) as raised:
        await verify_model_attestation(
            create_model_attestation(),
            MODEL_CLIENT_BINDING,
            verifiers=ModelAttestationVerifiers(quote=lambda _: quote),
        )

    assert raised.value.failure.code == 'quote.invalid_result'


async def test_measurement_and_deployment_policy_are_bound_to_quote() -> None:
    deployment_calls: list[str] = []

    async def verify_deployment(deployment) -> None:
        deployment_calls.append(deployment.app_compose)

    result = await verify_model_attestation(
        create_model_attestation(),
        MODEL_CLIENT_BINDING,
        verifiers=ModelAttestationVerifiers(
            quote=lambda _: create_model_quote(), deployment=verify_deployment
        ),
    )
    assert deployment_calls == [APP_COMPOSE]
    assert result.deployment_provenance == 'verified'

    with pytest.raises(VerificationError) as raised:
        await verify_model_attestation(
            create_model_attestation(app_compose='{"changed":true}'),
            MODEL_CLIENT_BINDING,
            verifiers=ModelAttestationVerifiers(quote=lambda _: create_model_quote()),
        )
    assert raised.value.failure.code == 'measurement.app_compose_mrconfigid_mismatch'
