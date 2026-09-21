from __future__ import annotations

import json
import time
from dataclasses import replace

import pytest
import jwt
from cryptography.hazmat.primitives.asymmetric import ec

import nearai_inference_sdk.utils.nvidia as nvidia
from nearai_inference_sdk import (
    GpuEvidenceVerifier,
    ModelAttestationPolicy,
    ModelAttestationVerifiers,
    VerificationError,
    create_gpu_evidence_verifier,
    verify_model_attestation,
)
from nearai_inference_sdk.utils.fetch import FetchResponse

from .fixtures import (
    APP_COMPOSE,
    MODEL_CLIENT_BINDING,
    NONCE,
    create_model_attestation,
    create_model_quote,
    create_gateway_tls_quote,
)


NRAS_TEST_KEY = ec.generate_private_key(ec.SECP384R1())
NRAS_TEST_JWK = jwt.algorithms.ECAlgorithm.to_jwk(
    NRAS_TEST_KEY.public_key(), as_dict=True
)
NRAS_TEST_JWK['kid'] = 'test-nras'
PROXY_JWKS_URL = 'https://nras.example/keys'


def nras_jwt(claims: dict[str, object], kid: str = 'test-nras') -> str:
    now = int(time.time())
    payload = {
        'iss': nvidia.NVIDIA_ISSUER,
        'exp': now + 3600,
        'nbf': now - 60,
        'iat': now - 60,
        'eat_nonce': NONCE,
        'x-nvidia-overall-att-result': True,
        **claims,
    }
    return jwt.encode(payload, NRAS_TEST_KEY, algorithm='ES384', headers={'kid': kid})


def use_fake_nras_response(monkeypatch: pytest.MonkeyPatch, body: object) -> None:
    async def fake_fetch(url: str, **__: object) -> FetchResponse:
        response = (
            {'keys': [NRAS_TEST_JWK]}
            if url in (nvidia.NVIDIA_JWKS_URL, PROXY_JWKS_URL)
            else body
        )
        return FetchResponse(status=200, body=json.dumps(response).encode())

    monkeypatch.setattr(nvidia, 'fetch', fake_fetch)


@pytest.fixture
def nras_verifier() -> GpuEvidenceVerifier:
    return create_gpu_evidence_verifier(
        nras_url='https://nras.example/gpu', jwks_url=PROXY_JWKS_URL
    )


async def test_nras_factories_route_evidence_and_jwks_independently(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, dict[str, object]]] = []
    payload = json.dumps({'nonce': NONCE, 'evidence': 'unchanged'})
    token = nras_jwt({})

    async def fake_fetch(url: str, **kwargs: object) -> FetchResponse:
        calls.append((url, kwargs))
        body = (
            {'keys': [NRAS_TEST_JWK]}
            if url
            in (
                nvidia.NVIDIA_JWKS_URL,
                'https://first.example/keys',
                'https://second.example/keys',
            )
            else [['JWT', token]]
        )
        return FetchResponse(status=200, body=json.dumps(body).encode())

    monkeypatch.setattr(nvidia, 'fetch', fake_fetch)
    first = create_gpu_evidence_verifier(
        nras_url='https://first.example/gpu', jwks_url='https://first.example/keys'
    )
    second = create_gpu_evidence_verifier(
        nras_url='https://second.example/gpu', jwks_url='https://second.example/keys'
    )
    default = create_gpu_evidence_verifier()
    nras_only = create_gpu_evidence_verifier(nras_url='https://first.example/gpu')
    jwks_only = create_gpu_evidence_verifier(jwks_url='https://first.example/keys')
    for verifier in (first, second, first, default, nras_only, jwks_only):
        await verifier(payload)

    expected_calls = []
    for url, jwks_url in (
        ('https://first.example/gpu', 'https://first.example/keys'),
        ('https://second.example/gpu', 'https://second.example/keys'),
        ('https://first.example/gpu', 'https://first.example/keys'),
        (
            'https://nras.attestation.nvidia.com/v3/attest/gpu',
            'https://nras.attestation.nvidia.com/.well-known/jwks.json',
        ),
        (
            'https://first.example/gpu',
            'https://nras.attestation.nvidia.com/.well-known/jwks.json',
        ),
        (
            'https://nras.attestation.nvidia.com/v3/attest/gpu',
            'https://first.example/keys',
        ),
    ):
        expected_calls.extend(
            [
                (
                    url,
                    {
                        'method': 'POST',
                        'data': payload,
                        'headers': {'content-type': 'application/json'},
                    },
                ),
                (jwks_url, {}),
            ]
        )
    assert calls == expected_calls


@pytest.mark.parametrize('mode', ['standalone', 'model'])
@pytest.mark.parametrize(
    ('payload', 'code', 'reason'),
    [
        ('{', 'gpu.payload_invalid', 'invalid_json'),
        ('{}', 'gpu.payload_invalid', 'nonce_missing'),
        ('[]', 'gpu.payload_invalid', 'nonce_missing'),
        ('{"nonce":32}', 'gpu.payload_invalid', 'nonce_missing'),
        ('{"nonce":""}', 'input.invalid', 'invalid_hex'),
        ('{"nonce":"11"}', 'input.invalid', 'wrong_length'),
        (json.dumps({'nonce': 'gg' * 32}), 'input.invalid', 'invalid_hex'),
        (json.dumps({'nonce': '11 ' * 32}), 'input.invalid', 'invalid_hex'),
    ],
)
async def test_nras_factory_rejects_invalid_payload_nonce_before_network(
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    payload: str,
    code: str,
    reason: str,
) -> None:
    calls: list[str] = []

    async def unexpected_fetch(url: str, **_: object) -> FetchResponse:
        calls.append(url)
        raise AssertionError('invalid evidence must not be sent')

    monkeypatch.setattr(nvidia, 'fetch', unexpected_fetch)
    verifier = create_gpu_evidence_verifier(nras_url='https://nras.example/gpu')
    with pytest.raises(VerificationError) as raised:
        if mode == 'standalone':
            await verifier(payload)
        else:
            await verify_model_attestation(
                create_model_attestation(nvidia_payload=payload),
                MODEL_CLIENT_BINDING,
                verifiers=ModelAttestationVerifiers(
                    quote=lambda _: create_model_quote(), gpu=verifier
                ),
            )
    assert raised.value.failure.code == code
    assert raised.value.failure.details['reason'] == reason
    assert calls == []


async def test_nras_factory_compares_payload_and_signed_nonce_as_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    use_fake_nras_response(monkeypatch, [['JWT', nras_jwt({'eat_nonce': 'AB' * 32})]])
    verifier = create_gpu_evidence_verifier(nras_url='https://nras.example/gpu')
    await verifier(json.dumps({'nonce': '0X' + 'ab' * 32}))


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

    gpu_calls: list[str] = []

    async def verify_gpu(payload: str) -> None:
        gpu_calls.append(payload)

    with pytest.raises(VerificationError) as mismatch:
        await verify_model_attestation(
            create_model_attestation(nvidia_payload=json.dumps({'nonce': '55' * 32})),
            MODEL_CLIENT_BINDING,
            verifiers=ModelAttestationVerifiers(
                quote=lambda _: create_model_quote(), gpu=verify_gpu
            ),
        )
    assert mismatch.value.failure.code == 'binding.nonce_mismatch'
    assert gpu_calls == []

    result = await verify_model_attestation(
        create_model_attestation(nvidia_payload=json.dumps({'nonce': NONCE})),
        MODEL_CLIENT_BINDING,
        verifiers=ModelAttestationVerifiers(
            quote=lambda _: create_model_quote(), gpu=verify_gpu
        ),
    )
    assert result.gpu_evidence == 'verified'
    assert gpu_calls == [json.dumps({'nonce': NONCE})]


async def test_empty_gpu_payload_remains_invalid_supplied_json() -> None:
    with pytest.raises(VerificationError) as raised:
        await verify_model_attestation(
            create_model_attestation(nvidia_payload=''),
            MODEL_CLIENT_BINDING,
            verifiers=ModelAttestationVerifiers(quote=lambda _: create_model_quote()),
        )
    assert raised.value.failure.code == 'gpu.payload_invalid'
    assert raised.value.failure.details == {'reason': 'invalid_json'}


async def test_gpu_evidence_requires_an_echoed_nonce() -> None:
    with pytest.raises(VerificationError) as raised:
        await verify_model_attestation(
            create_model_attestation(nvidia_payload='{}'),
            MODEL_CLIENT_BINDING,
            verifiers=ModelAttestationVerifiers(quote=lambda _: create_model_quote()),
        )

    assert raised.value.failure.code == 'gpu.payload_invalid'
    assert raised.value.failure.details == {'reason': 'nonce_missing'}


async def test_model_attestation_rejects_an_invalid_event_log_entry() -> None:
    with pytest.raises(VerificationError) as raised:
        await verify_model_attestation(
            create_model_attestation(event_log='[{}]'),
            MODEL_CLIENT_BINDING,
            verifiers=ModelAttestationVerifiers(quote=lambda _: create_model_quote()),
        )

    assert raised.value.failure.code == 'measurement.event_log_invalid'
    assert raised.value.failure.details == {
        'path': 'eventLog[0].digest',
        'reason': 'invalid_type',
        'expected': 'string',
    }


async def test_model_attestation_rejects_boolean_event_types() -> None:
    with pytest.raises(VerificationError) as raised:
        await verify_model_attestation(
            create_model_attestation(
                event_log=[
                    {
                        'digest': '00' * 48,
                        'imr': 3,
                        'event_type': True,
                    }
                ]
            ),
            MODEL_CLIENT_BINDING,
            verifiers=ModelAttestationVerifiers(quote=lambda _: create_model_quote()),
        )

    assert raised.value.failure.code == 'measurement.event_log_invalid'
    assert raised.value.failure.details == {
        'path': 'eventLog[0].event_type',
        'reason': 'invalid_type',
        'expected': 'unsigned 32-bit integer',
    }


async def test_model_attestation_rejects_invalid_serialized_event_log() -> None:
    with pytest.raises(VerificationError) as raised:
        await verify_model_attestation(
            create_model_attestation(event_log='['),
            MODEL_CLIENT_BINDING,
            verifiers=ModelAttestationVerifiers(quote=lambda _: create_model_quote()),
        )

    assert raised.value.failure.code == 'measurement.event_log_invalid'
    assert raised.value.failure.details == {
        'path': 'eventLog',
        'reason': 'invalid_json',
    }


async def test_nras_rejects_a_malformed_envelope(
    monkeypatch: pytest.MonkeyPatch,
    nras_verifier: GpuEvidenceVerifier | None,
) -> None:
    use_fake_nras_response(monkeypatch, [['TOKEN', 'not-a-jwt']])

    with pytest.raises(VerificationError) as raised:
        await verify_model_attestation(
            create_model_attestation(nvidia_payload=json.dumps({'nonce': NONCE})),
            MODEL_CLIENT_BINDING,
            verifiers=ModelAttestationVerifiers(
                quote=lambda _: create_model_quote(), gpu=nras_verifier
            ),
        )

    assert raised.value.failure.code == 'gpu.nras_response_invalid'
    assert raised.value.failure.details == {'reason': 'invalid_schema'}


async def test_nras_rejects_an_invalid_jwt(
    monkeypatch: pytest.MonkeyPatch,
    nras_verifier: GpuEvidenceVerifier | None,
) -> None:
    use_fake_nras_response(monkeypatch, [['JWT', 'not-a-jwt']])

    with pytest.raises(VerificationError) as raised:
        await verify_model_attestation(
            create_model_attestation(nvidia_payload=json.dumps({'nonce': NONCE})),
            MODEL_CLIENT_BINDING,
            verifiers=ModelAttestationVerifiers(
                quote=lambda _: create_model_quote(), gpu=nras_verifier
            ),
        )

    assert raised.value.failure.code == 'gpu.jwt_verification_failed'
    assert raised.value.failure.details == {'reason': 'invalid_claims'}


async def test_nras_rejects_a_non_boolean_verdict(
    monkeypatch: pytest.MonkeyPatch,
    nras_verifier: GpuEvidenceVerifier | None,
) -> None:
    use_fake_nras_response(
        monkeypatch,
        [['JWT', nras_jwt({'x-nvidia-overall-att-result': 'PASS'})]],
    )

    with pytest.raises(VerificationError) as raised:
        await verify_model_attestation(
            create_model_attestation(nvidia_payload=json.dumps({'nonce': NONCE})),
            MODEL_CLIENT_BINDING,
            verifiers=ModelAttestationVerifiers(
                quote=lambda _: create_model_quote(), gpu=nras_verifier
            ),
        )

    assert raised.value.failure.code == 'gpu.jwt_verification_failed'
    assert raised.value.failure.details == {'reason': 'invalid_claims'}


async def test_nras_rejects_a_false_verdict(
    monkeypatch: pytest.MonkeyPatch,
    nras_verifier: GpuEvidenceVerifier | None,
) -> None:
    use_fake_nras_response(
        monkeypatch,
        [['JWT', nras_jwt({'x-nvidia-overall-att-result': False})]],
    )

    with pytest.raises(VerificationError) as raised:
        await verify_model_attestation(
            create_model_attestation(nvidia_payload=json.dumps({'nonce': NONCE})),
            MODEL_CLIENT_BINDING,
            verifiers=ModelAttestationVerifiers(
                quote=lambda _: create_model_quote(), gpu=nras_verifier
            ),
        )

    assert raised.value.failure.code == 'gpu.attestation_rejected'
    assert raised.value.failure.details == {'source': 'nras'}


@pytest.mark.parametrize('use_factory', [False, True])
async def test_nras_verifies_a_signed_overall_token(
    monkeypatch: pytest.MonkeyPatch,
    nras_verifier: GpuEvidenceVerifier | None,
    use_factory: bool,
) -> None:
    use_fake_nras_response(monkeypatch, [['JWT', nras_jwt({})]])
    result = await verify_model_attestation(
        create_model_attestation(nvidia_payload=json.dumps({'nonce': NONCE})),
        MODEL_CLIENT_BINDING,
        verifiers=ModelAttestationVerifiers(
            quote=lambda _: create_model_quote(),
            gpu=nras_verifier if use_factory else None,
        ),
    )
    assert result.gpu_evidence == 'verified'


@pytest.mark.parametrize(
    ('claims', 'reason'),
    [
        ({'exp': 1}, 'expired'),
        ({'nbf': 4102444800}, 'not_yet_valid'),
        ({'iat': 4102444800}, 'not_yet_valid'),
        ({'iss': 'https://untrusted.example'}, 'invalid_claims'),
        ({'exp': None}, 'invalid_claims'),
        ({'exp': []}, 'invalid_claims'),
        ({'eat_nonce': None}, 'invalid_claims'),
        ({'eat_nonce': '44' * 32}, 'nonce_mismatch'),
    ],
)
async def test_nras_rejects_unacceptable_signed_claims(
    monkeypatch: pytest.MonkeyPatch,
    nras_verifier: GpuEvidenceVerifier | None,
    claims: dict[str, object],
    reason: str,
) -> None:
    use_fake_nras_response(monkeypatch, [['JWT', nras_jwt(claims)]])
    with pytest.raises(VerificationError) as raised:
        await verify_model_attestation(
            create_model_attestation(nvidia_payload=json.dumps({'nonce': NONCE})),
            MODEL_CLIENT_BINDING,
            verifiers=ModelAttestationVerifiers(
                quote=lambda _: create_model_quote(), gpu=nras_verifier
            ),
        )
    assert raised.value.failure.code == 'gpu.jwt_verification_failed'
    assert raised.value.failure.details == {'reason': reason}


async def test_nras_rejects_an_invalid_jwks(
    monkeypatch: pytest.MonkeyPatch,
    nras_verifier: GpuEvidenceVerifier | None,
) -> None:
    monkeypatch.setitem(NRAS_TEST_JWK, 'alg', ['ES384'])
    use_fake_nras_response(monkeypatch, [['JWT', nras_jwt({})]])

    with pytest.raises(VerificationError) as raised:
        await verify_model_attestation(
            create_model_attestation(nvidia_payload=json.dumps({'nonce': NONCE})),
            MODEL_CLIENT_BINDING,
            verifiers=ModelAttestationVerifiers(
                quote=lambda _: create_model_quote(), gpu=nras_verifier
            ),
        )

    assert raised.value.failure.code == 'gpu.nras_response_invalid'
    assert raised.value.failure.details == {'reason': 'invalid_jwks'}


@pytest.mark.parametrize('case', ['modified', 'unknown_key', 'unsigned'])
async def test_nras_rejects_untrusted_signatures(
    monkeypatch: pytest.MonkeyPatch,
    nras_verifier: GpuEvidenceVerifier | None,
    case: str,
) -> None:
    if case == 'modified':
        token = nras_jwt({})
        header, payload, signature = token.split('.')
        replacement = ('A' if signature[0] != 'A' else 'B') + signature[1:]
        token = f'{header}.{payload}.{replacement}'
        reason = 'invalid_signature'
    elif case == 'unknown_key':
        token = nras_jwt({}, kid='unknown')
        reason = 'key_not_found'
    else:
        token = jwt.encode({'eat_nonce': NONCE}, key=None, algorithm='none')
        reason = 'unsupported_algorithm'
    use_fake_nras_response(monkeypatch, [['JWT', token]])
    with pytest.raises(VerificationError) as raised:
        await verify_model_attestation(
            create_model_attestation(nvidia_payload=json.dumps({'nonce': NONCE})),
            MODEL_CLIENT_BINDING,
            verifiers=ModelAttestationVerifiers(
                quote=lambda _: create_model_quote(), gpu=nras_verifier
            ),
        )
    assert raised.value.failure.code == 'gpu.jwt_verification_failed'
    assert raised.value.failure.details == {'reason': reason}


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
