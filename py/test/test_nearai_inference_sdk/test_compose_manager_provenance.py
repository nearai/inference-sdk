import json
from dataclasses import replace
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from sigstore.models import TrustedRoot
from sigstore.verify import Verifier

from nearai_inference_sdk import (
    ApiError,
    ComposeManagerAttestation,
    ComposeManagerImagePolicy,
    DirectClientBinding,
    DirectModelAttestation,
    FetchedDirectModelAttestations,
    ImageProvenancePolicy,
    ModelAttestationVerifiers,
    VerificationError,
    verify_compose_manager_deployment_image_provenance,
    verify_direct_model_attestations,
    verify_model_attestation,
)
from nearai_inference_sdk.core import compose_manager_provenance, provenance
from nearai_inference_sdk.schemas import ComposeManagerAttestationSchema
from nearai_inference_sdk.utils.common import sha256
from nearai_inference_sdk.utils.fetch import FetchResponse

from .fixtures import (
    MODEL_CLIENT_BINDING,
    NONCE,
    create_model_attestation,
    create_model_quote,
)

FIXTURES = Path(__file__).resolve().parents[3] / 'test-fixtures'
FIXTURE = json.loads((FIXTURES / 'compose-manager/deployment.json').read_text())
POLICIES = {
    'nearaidev/compose-manager-launcher': ImageProvenancePolicy(
        repository='nearai/compose-manager', workflow='.github/workflows/build.yml'
    )
}

MANAGER_POLICY = ComposeManagerImagePolicy(
    image_repository='nearaidev/compose-manager-launcher',
    repository='nearai/compose-manager',
    workflow='.github/workflows/build.yml',
)


def manager_report() -> ComposeManagerAttestation:
    wire = ComposeManagerAttestationSchema.model_validate(
        {
            'actions': FIXTURE['actions'],
            'actions_hash': FIXTURE['actions_hash'],
            'nonce': NONCE,
            'quote': 'bb',
            'event_log': create_model_attestation().event_log,
        }
    )
    return ComposeManagerAttestation(
        actions=tuple(action.root for action in wire.actions),
        actions_hash=wire.actions_hash,
        nonce=wire.nonce,
        intel_quote=wire.quote,
        event_log=wire.event_log,
    )


def quote_verifier(quote: str):
    if quote == 'bb':
        return create_model_quote(
            report_data=bytes.fromhex(FIXTURE['actions_hash'] + NONCE)
        )
    return create_model_quote()


@pytest.mark.parametrize(
    'suffix', [':latest', '@sha256:abcd', ':bad tag@sha256:' + 'aa' * 32]
)
async def test_rejects_unpinned_manager_image_before_any_request(monkeypatch, suffix):
    verified = await verify_model_attestation(
        replace(
            create_model_attestation(), compose_manager_attestation=manager_report()
        ),
        MODEL_CLIENT_BINDING,
        verifiers=ModelAttestationVerifiers(tdx_quote=quote_verifier),
    )
    manager = verified.deployment.compose_manager
    assert manager is not None
    deployment = replace(
        verified.deployment,
        compose_manager=replace(
            manager,
            actions=tuple(
                {**action, 'image': MANAGER_POLICY.image_repository + suffix}
                if action['action'] == 'compose_manager_started'
                else action
                for action in manager.actions
            ),
        ),
    )
    fetch = AsyncMock(side_effect=AssertionError('Unexpected network request'))
    monkeypatch.setattr(compose_manager_provenance, 'fetch', fetch)
    monkeypatch.setattr(provenance, 'fetch_image_provenance', fetch)
    with pytest.raises(VerificationError) as error:
        await verify_compose_manager_deployment_image_provenance(
            deployment,
            POLICIES,
            manager_image_policy=MANAGER_POLICY,
            github_token='test-github-token',
        )
    assert error.value.failure.code == 'provenance.deployment_images_invalid'
    assert error.value.failure.details['reason'] == 'image_not_pinned'
    fetch.assert_not_awaited()


@pytest.mark.parametrize('direct', [False, True])
@pytest.mark.parametrize(
    'github_proxy_url',
    [
        None,
        'https://app.example/verification/github/',
        'http://localhost:8080/github/',
    ],
)
async def test_verifies_recorded_compose_and_real_image_proof_through_deployment_policy(
    monkeypatch,
    direct,
    github_proxy_url,
):
    root = TrustedRoot.from_file(str(FIXTURES / 'provenance/trusted-root.json'))
    monkeypatch.setattr(Verifier, 'production', lambda: Verifier(trusted_root=root))
    compose_fetch = AsyncMock(
        return_value=FetchResponse(status=200, body=FIXTURE['compose'].encode())
    )
    monkeypatch.setattr(compose_manager_provenance, 'fetch', compose_fetch)
    bundle = json.loads(
        (FIXTURES / 'provenance/compose-manager-launcher.bundle.json').read_text()
    )
    image_fetch = AsyncMock(
        return_value=FetchResponse(
            status=200,
            body=json.dumps({'attestations': [{'bundle': bundle}]}).encode(),
        )
    )
    monkeypatch.setattr(provenance, 'fetch', image_fetch)

    async def deployment_policy(deployment):
        await verify_compose_manager_deployment_image_provenance(
            deployment,
            POLICIES,
            manager_image_policy=MANAGER_POLICY,
            github_token='test-token',
            github_proxy_url=github_proxy_url,
        )

    attestation = create_model_attestation(compose_manager_attestation=manager_report())
    if direct:
        serving = DirectModelAttestation(**vars(attestation), model_name='glm-5.2')
        sibling = replace(serving, intel_quote='cc', compose_manager_attestation=None)
        checked = []

        def verify_quote(quote):
            checked.append(quote)
            return quote_verifier(quote)

        result = await verify_direct_model_attestations(
            FetchedDirectModelAttestations(
                serving_attestation=serving,
                attestations=(sibling, serving),
                client_binding=DirectClientBinding(nonce=NONCE),
            ),
            verifiers=ModelAttestationVerifiers(tdx_quote=verify_quote),
            serving_deployment=deployment_policy,
        )
        assert sorted(checked) == ['aa', 'bb', 'cc']
        assert result.attestations[0].deployment_provenance == 'not_checked'
        assert result.serving_attestation is result.attestations[1]
        verified = result.serving_attestation
    else:
        verified = await verify_model_attestation(
            attestation,
            MODEL_CLIENT_BINDING,
            verifiers=ModelAttestationVerifiers(
                tdx_quote=quote_verifier, deployment=deployment_policy
            ),
        )

    assert verified.deployment_provenance == 'verified'
    assert verified.deployment.compose_manager.actions == manager_report().actions
    api_url = (
        'https://api.github.com/' if github_proxy_url is None else github_proxy_url
    )
    assert compose_fetch.await_args.args[0] == (
        f'{api_url}repos/nearai/cvm-compose-files/contents/prod/model.yaml?ref='
        + '12' * 20
    )
    assert image_fetch.await_args.args[0].startswith(
        f'{api_url}repos/nearai/compose-manager/attestations/'
    )
    for request in (compose_fetch, image_fetch):
        assert request.await_args.kwargs['headers'].get('Authorization') == (
            'Bearer test-token' if github_proxy_url is None else None
        )


@pytest.mark.parametrize('request_path', ['compose', 'image'])
@pytest.mark.parametrize(
    'github_proxy_url',
    [
        '',
        '/verification/github',
        '//proxy.example/github',
        'ftp://proxy.example/github',
        'https:///github',
        'https://proxy.example:invalid/github',
        'https://user:password@proxy.example/github',
        'https://proxy.example/github?tenant=x',
        'https://proxy.example/github?',
        'https://proxy.example/github#section',
        'https://proxy.example/github#',
    ],
)
async def test_rejects_invalid_github_proxy_before_any_request(
    monkeypatch, request_path, github_proxy_url
):
    fetch = AsyncMock(side_effect=AssertionError('Unexpected network request'))
    monkeypatch.setattr(compose_manager_provenance, 'fetch', fetch)
    monkeypatch.setattr(provenance, 'fetch', fetch)
    with pytest.raises(ApiError) as error:
        if request_path == 'compose':
            verified = await verify_model_attestation(
                create_model_attestation(compose_manager_attestation=manager_report()),
                MODEL_CLIENT_BINDING,
                verifiers=ModelAttestationVerifiers(tdx_quote=quote_verifier),
            )
            await verify_compose_manager_deployment_image_provenance(
                verified.deployment,
                POLICIES,
                manager_image_policy=MANAGER_POLICY,
                github_proxy_url=github_proxy_url,
            )
        else:
            await provenance.fetch_image_provenance(
                MANAGER_POLICY.repository,
                'sha256:' + 'aa' * 32,
                github_proxy_url=github_proxy_url,
            )
    assert error.value.failure.code == 'api.invalid_input'
    assert error.value.failure.details['field'] == 'github_proxy_url'
    fetch.assert_not_awaited()


@pytest.mark.parametrize(
    'services,reason',
    [(['other'], 'image_missing'), (['model', 'missing'], 'service_missing')],
)
async def test_service_selection_must_satisfy_the_image_policy(
    monkeypatch, services, reason
):
    verified = await verify_model_attestation(
        create_model_attestation(compose_manager_attestation=manager_report()),
        MODEL_CLIENT_BINDING,
        verifiers=ModelAttestationVerifiers(tdx_quote=quote_verifier),
    )
    compose = FIXTURE['compose'] + '  other:\n    image: other/model:latest\n'
    manager = verified.deployment.compose_manager
    deployment = replace(
        verified.deployment,
        compose_manager=replace(
            manager,
            actions=(
                {
                    **manager.actions[0],
                    'services': services,
                    'file_sha256': sha256(compose.encode()).hex(),
                },
                *manager.actions[1:],
            ),
        ),
    )
    compose_fetch = AsyncMock(
        return_value=FetchResponse(status=200, body=compose.encode())
    )
    monkeypatch.setattr(compose_manager_provenance, 'fetch', compose_fetch)
    image_fetch = AsyncMock()
    monkeypatch.setattr(provenance, 'fetch_image_provenance', image_fetch)
    with pytest.raises(VerificationError) as raised:
        await verify_compose_manager_deployment_image_provenance(
            deployment, POLICIES, manager_image_policy=MANAGER_POLICY
        )
    assert raised.value.failure.code == 'provenance.deployment_images_invalid'
    assert raised.value.failure.details['reason'] == reason
    image_fetch.assert_not_awaited()


@pytest.mark.parametrize(
    'change,code',
    [
        (
            {'actions': ({**FIXTURE['actions'][0], 'file': 'other.yaml'},)},
            'binding.compose_manager_actions_mismatch',
        ),
        ({'nonce': 'ff' * 32}, 'binding.nonce_mismatch'),
    ],
)
async def test_rejects_tampered_or_replayed_manager_evidence_before_policy(
    change, code
):
    policy = AsyncMock()
    report = replace(manager_report(), **change)
    with pytest.raises(VerificationError) as raised:
        await verify_model_attestation(
            create_model_attestation(compose_manager_attestation=report),
            MODEL_CLIENT_BINDING,
            verifiers=ModelAttestationVerifiers(
                tdx_quote=quote_verifier, deployment=policy
            ),
        )
    assert raised.value.failure.code == code
    policy.assert_not_awaited()


async def test_rejects_changed_compose_before_image_proof_retrieval(monkeypatch):
    verified = await verify_model_attestation(
        create_model_attestation(compose_manager_attestation=manager_report()),
        MODEL_CLIENT_BINDING,
        verifiers=ModelAttestationVerifiers(tdx_quote=quote_verifier),
    )
    monkeypatch.setattr(
        compose_manager_provenance,
        'fetch',
        AsyncMock(return_value=FetchResponse(status=200, body=b'changed')),
    )
    image_fetch = AsyncMock()
    monkeypatch.setattr(provenance, 'fetch_image_provenance', image_fetch)
    with pytest.raises(VerificationError) as raised:
        await verify_compose_manager_deployment_image_provenance(
            verified.deployment,
            POLICIES,
            manager_image_policy=MANAGER_POLICY,
            github_proxy_url='https://app.example/verification/github',
        )
    assert raised.value.failure.code == 'provenance.compose_file_hash_mismatch'
    image_fetch.assert_not_awaited()


async def test_requires_manager_evidence_when_its_provenance_policy_is_used():
    verified = await verify_model_attestation(
        create_model_attestation(),
        MODEL_CLIENT_BINDING,
        verifiers=ModelAttestationVerifiers(tdx_quote=quote_verifier),
    )
    with pytest.raises(VerificationError) as raised:
        await verify_compose_manager_deployment_image_provenance(
            verified.deployment, POLICIES, manager_image_policy=MANAGER_POLICY
        )
    assert raised.value.failure.code == 'provenance.compose_manager_deployment_invalid'
    assert raised.value.failure.details == {'reason': 'attestation_missing'}


async def test_streamed_compose_file_is_bounded_before_hashing_or_image_fetch():
    from aiohttp import web
    from aiohttp.test_utils import TestServer

    requests = []

    async def oversized(request):
        requests.append(request.path)
        response = web.StreamResponse()
        await response.prepare(request)
        await response.write(b'x' * (8 * 1024 * 1024 + 1))
        return response

    app = web.Application()
    app.router.add_get('/{path:.*}', oversized)
    verified = await verify_model_attestation(
        create_model_attestation(compose_manager_attestation=manager_report()),
        MODEL_CLIENT_BINDING,
        verifiers=ModelAttestationVerifiers(tdx_quote=quote_verifier),
    )
    async with TestServer(app) as server:
        with pytest.raises(VerificationError) as raised:
            await verify_compose_manager_deployment_image_provenance(
                verified.deployment,
                POLICIES,
                manager_image_policy=MANAGER_POLICY,
                github_proxy_url=str(server.make_url('/')),
            )
    assert raised.value.failure.code == 'provenance.compose_manager_deployment_invalid'
    assert raised.value.failure.details['reason'] == 'compose_file_too_large'
    assert len(requests) == 1
