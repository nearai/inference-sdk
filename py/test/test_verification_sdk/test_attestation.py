from __future__ import annotations

import json
from dataclasses import replace

import pytest
import verification_sdk.utils.nvidia as nvidia

from verification_sdk import (
    AttestationVerifiers,
    ModelAttestationPolicy,
    ModelAttestationVerifiers,
    VerificationError,
    VerifyGatewayAttestationInput,
    VerifyModelAttestationInput,
    verify_gateway_attestation,
    verify_model_attestation,
)

from .fixtures import (
    APP_COMPOSE,
    NONCE,
    TLS_FINGERPRINT,
    create_gateway_attestation,
    create_model_attestation,
    create_quote,
)
from verification_sdk.utils.fetch import FetchResponse


async def test_model_attestation_returns_verified_evidence() -> None:
    result = await verify_model_attestation(
        VerifyModelAttestationInput(
            attestation=create_model_attestation(),
            nonce=NONCE,
            verifiers=ModelAttestationVerifiers(quote=lambda _: create_quote()),
        )
    )

    assert result.tcb_status == 'UpToDate'
    assert result.tls_binding.kind == 'declared'
    assert result.tls_binding.spki_fingerprint == TLS_FINGERPRINT
    assert result.gpu_evidence == 'not_provided'
    assert result.deployment.app_compose == APP_COMPOSE
    assert result.deployment_provenance == 'not_checked'


async def test_model_attestation_accepts_legacy_signer_nonce_layout() -> None:
    result = await verify_model_attestation(
        VerifyModelAttestationInput(
            attestation=create_model_attestation(declared_spki_fingerprint=None),
            nonce=NONCE,
            verifiers=ModelAttestationVerifiers(
                quote=lambda _: create_quote(legacy_model_layout=True)
            ),
        )
    )

    assert result.tls_binding.kind == 'none'


async def test_model_attestation_rejects_mismatched_nonce_before_quote() -> None:
    with pytest.raises(VerificationError) as raised:
        await verify_model_attestation(
            VerifyModelAttestationInput(
                attestation=create_model_attestation(nonce='44' * 32),
                nonce=NONCE,
                verifiers=ModelAttestationVerifiers(quote=lambda _: create_quote()),
            )
        )

    assert raised.value.code == 'binding.nonce_mismatch'
    assert raised.value.failure.details == {'source': 'attestationNonce'}


async def test_model_policy_accepts_out_of_date_by_default_and_can_tighten() -> None:
    quote = create_quote(tcb_status='OutOfDate')
    result = await verify_model_attestation(
        VerifyModelAttestationInput(
            attestation=create_model_attestation(),
            nonce=NONCE,
            verifiers=ModelAttestationVerifiers(quote=lambda _: quote),
        )
    )
    assert result.tcb_status == 'OutOfDate'

    with pytest.raises(VerificationError) as raised:
        await verify_model_attestation(
            VerifyModelAttestationInput(
                attestation=create_model_attestation(),
                nonce=NONCE,
                policy=ModelAttestationPolicy(accepted_tcb_statuses=('UpToDate',)),
                verifiers=ModelAttestationVerifiers(quote=lambda _: quote),
            )
        )
    assert raised.value.code == 'policy.tcb_status_not_allowed'


async def test_model_gpu_policy_and_nonce_binding() -> None:
    with pytest.raises(VerificationError) as missing:
        await verify_model_attestation(
            VerifyModelAttestationInput(
                attestation=create_model_attestation(),
                nonce=NONCE,
                policy=ModelAttestationPolicy(gpu_evidence='required'),
                verifiers=ModelAttestationVerifiers(quote=lambda _: create_quote()),
            )
        )
    assert missing.value.code == 'policy.gpu_evidence_required'

    called = False

    async def verify_gpu(_: str) -> None:
        nonlocal called
        called = True

    with pytest.raises(VerificationError) as mismatch:
        await verify_model_attestation(
            VerifyModelAttestationInput(
                attestation=create_model_attestation(
                    nvidia_payload=json.dumps({'nonce': '55' * 32})
                ),
                nonce=NONCE,
                verifiers=ModelAttestationVerifiers(
                    quote=lambda _: create_quote(), nvidia=verify_gpu
                ),
            )
        )
    assert mismatch.value.code == 'binding.nonce_mismatch'
    assert called is False

    result = await verify_model_attestation(
        VerifyModelAttestationInput(
            attestation=create_model_attestation(
                nvidia_payload=json.dumps({'nonce': NONCE})
            ),
            nonce=NONCE,
            verifiers=ModelAttestationVerifiers(
                quote=lambda _: create_quote(), nvidia=verify_gpu
            ),
        )
    )
    assert result.gpu_evidence == 'verified'
    assert called is True


async def test_empty_gpu_payload_remains_invalid_supplied_json() -> None:
    with pytest.raises(VerificationError) as raised:
        await verify_model_attestation(
            VerifyModelAttestationInput(
                attestation=create_model_attestation(nvidia_payload=''),
                nonce=NONCE,
                verifiers=ModelAttestationVerifiers(quote=lambda _: create_quote()),
            )
        )
    assert raised.value.code == 'gpu.payload_invalid'
    assert raised.value.failure.details == {'reason': 'invalid_json'}


async def test_model_attestation_rejects_an_invalid_gpu_payload_type() -> None:
    with pytest.raises(VerificationError) as raised:
        await verify_model_attestation(
            VerifyModelAttestationInput(
                attestation=create_model_attestation(nvidia_payload=object()),
                nonce=NONCE,
                verifiers=ModelAttestationVerifiers(quote=lambda _: create_quote()),
            )
        )

    assert raised.value.code == 'input.invalid'
    assert raised.value.failure.details['field'] == 'attestation.nvidia_payload'


async def test_default_nras_schema_error_is_not_wrapped_as_a_custom_verifier_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def invalid_nras_response(_: str, **__: object) -> FetchResponse:
        return FetchResponse(status=200, body=b'{}')

    monkeypatch.setattr(nvidia, 'fetch', invalid_nras_response)

    with pytest.raises(VerificationError) as raised:
        await verify_model_attestation(
            VerifyModelAttestationInput(
                attestation=create_model_attestation(
                    nvidia_payload=json.dumps({'nonce': NONCE})
                ),
                nonce=NONCE,
                verifiers=ModelAttestationVerifiers(quote=lambda _: create_quote()),
            )
        )

    assert raised.value.code == 'gpu.nras_response_invalid'
    assert raised.value.failure.details == {'reason': 'invalid_schema'}


@pytest.mark.parametrize(
    ('field', 'value'),
    [
        ('tcb_status', []),
        ('advisory_ids', None),
        ('advisory_ids', 'not-a-sequence'),
    ],
)
async def test_model_attestation_rejects_invalid_custom_quote_results(
    field: str,
    value: object,
) -> None:
    quote = replace(create_quote(), **{field: value})

    with pytest.raises(VerificationError) as raised:
        await verify_model_attestation(
            VerifyModelAttestationInput(
                attestation=create_model_attestation(),
                nonce=NONCE,
                verifiers=ModelAttestationVerifiers(quote=lambda _: quote),
            )
        )

    assert raised.value.code == 'quote.invalid_result'


@pytest.mark.parametrize('field', ['event', 'event_payload'])
async def test_model_attestation_rejects_null_optional_event_log_fields(
    field: str,
) -> None:
    with pytest.raises(VerificationError) as raised:
        await verify_model_attestation(
            VerifyModelAttestationInput(
                attestation=create_model_attestation(
                    event_log=[{'digest': '00' * 48, 'imr': 3, field: None}]
                ),
                nonce=NONCE,
                verifiers=ModelAttestationVerifiers(quote=lambda _: create_quote()),
            )
        )

    assert raised.value.code == 'measurement.event_log_invalid'
    assert raised.value.failure.details['path'] == f'eventLog[0].{field}'


async def test_measurement_and_deployment_policy_are_bound_to_quote() -> None:
    deployment_calls: list[str] = []

    async def verify_deployment(deployment) -> None:
        deployment_calls.append(deployment.app_compose)

    result = await verify_model_attestation(
        VerifyModelAttestationInput(
            attestation=create_model_attestation(),
            nonce=NONCE,
            verifiers=ModelAttestationVerifiers(
                quote=lambda _: create_quote(), deployment=verify_deployment
            ),
        )
    )
    assert deployment_calls == [APP_COMPOSE]
    assert result.deployment_provenance == 'verified'

    with pytest.raises(VerificationError) as raised:
        await verify_model_attestation(
            VerifyModelAttestationInput(
                attestation=create_model_attestation(app_compose='{"changed":true}'),
                nonce=NONCE,
                verifiers=ModelAttestationVerifiers(quote=lambda _: create_quote()),
            )
        )
    assert raised.value.code == 'measurement.app_compose_mrconfigid_mismatch'


async def test_gateway_attestation_binds_the_observed_tls_peer() -> None:
    result = await verify_gateway_attestation(
        VerifyGatewayAttestationInput(
            attestation=create_gateway_attestation(),
            nonce=NONCE,
            peer_spki_fingerprint=TLS_FINGERPRINT,
            verifiers=AttestationVerifiers(quote=lambda _: create_quote()),
        )
    )
    assert result.tls_binding.kind == 'peer'
    assert result.tls_binding.spki_fingerprint == TLS_FINGERPRINT

    with pytest.raises(VerificationError) as mismatch:
        await verify_gateway_attestation(
            VerifyGatewayAttestationInput(
                attestation=create_gateway_attestation(),
                nonce=NONCE,
                peer_spki_fingerprint='44' * 32,
                verifiers=AttestationVerifiers(quote=lambda _: create_quote()),
            )
        )
    assert mismatch.value.code == 'binding.spki_fingerprint_mismatch'

    with pytest.raises(VerificationError) as missing:
        await verify_gateway_attestation(
            VerifyGatewayAttestationInput(
                attestation=create_gateway_attestation(declared_spki_fingerprint=None),
                nonce=NONCE,
                peer_spki_fingerprint=TLS_FINGERPRINT,
                verifiers=AttestationVerifiers(quote=lambda _: create_quote()),
            )
        )
    assert missing.value.code == 'binding.spki_fingerprint_missing'


async def test_gateway_attestation_requires_reported_quote_data() -> None:
    with pytest.raises(VerificationError) as raised:
        await verify_gateway_attestation(
            VerifyGatewayAttestationInput(
                attestation=create_gateway_attestation(reported_quote_data=None),
                nonce=NONCE,
                peer_spki_fingerprint=TLS_FINGERPRINT,
                verifiers=AttestationVerifiers(quote=lambda _: create_quote()),
            )
        )

    assert raised.value.code == 'input.invalid'
    assert raised.value.failure.details['field'] == 'attestation.reported_quote_data'


async def test_attestation_verifier_rejects_an_invalid_input_object() -> None:
    with pytest.raises(VerificationError) as raised:
        await verify_model_attestation(None)

    assert raised.value.code == 'input.invalid'
    assert raised.value.failure.details['field'] == 'input'
