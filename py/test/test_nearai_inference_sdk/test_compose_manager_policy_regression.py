import json
from pathlib import Path
from unittest.mock import AsyncMock
from urllib.parse import parse_qs, urlsplit

import pytest
from sigstore.models import TrustedRoot
from sigstore.verify import Verifier

from nearai_inference_sdk import (
    ComposeManagerImagePolicy,
    DirectAttestationClient,
    ImageProvenancePolicy,
    MeasuredDeployment,
    RuntimeMeasurements,
    VerificationError,
    verify_compose_manager_deployment_image_provenance,
)
from nearai_inference_sdk.core import cloud_api, compose_manager_provenance, provenance
from nearai_inference_sdk.types.compose_manager import VerifiedComposeManagerAttestation
from nearai_inference_sdk.utils.common import sha256
from nearai_inference_sdk.utils.fetch import FetchResponse

from .test_cloud_api import cloud_attestation

FIXTURES = Path(__file__).resolve().parents[3] / 'test-fixtures'
FIXTURE = json.loads((FIXTURES / 'compose-manager/deployment.json').read_text())
COMPOSE = FIXTURE['compose'].replace(
    'nearaidev/compose-manager-launcher', 'nearaidev/compose-manager'
)
POLICIES = {
    'nearaidev/compose-manager': ImageProvenancePolicy(
        repository='nearai/compose-manager', workflow='.github/workflows/build.yml'
    )
}


def deployment(image=None):
    started = {'action': 'compose_manager_started', 'timestamp': '2026-10-02T00:00:00Z'}
    if image is not None:
        started['image'] = image
    return MeasuredDeployment(
        app_compose='{}',
        runtime_measurements=RuntimeMeasurements(),
        compose_manager=VerifiedComposeManagerAttestation(
            actions=(
                {
                    **FIXTURE['actions'][0],
                    'file_sha256': sha256(COMPOSE.encode()).hex(),
                },
                started,
            ),
            tcb_status='UpToDate',
            advisory_ids=(),
            runtime_measurements=RuntimeMeasurements(),
        ),
    )


@pytest.mark.parametrize('image', [None, 'unlisted/manager@sha256:' + 'bb' * 32])
async def test_rejects_unapproved_or_missing_current_manager(monkeypatch, image):
    fetch = AsyncMock(side_effect=AssertionError('Unexpected network request'))
    monkeypatch.setattr(compose_manager_provenance, 'fetch', fetch)
    monkeypatch.setattr(provenance, 'fetch', fetch)
    with pytest.raises(VerificationError) as result:
        await verify_compose_manager_deployment_image_provenance(
            deployment(image),
            POLICIES,
            manager_image_policy=ComposeManagerImagePolicy(
                image_repository='nearaidev/compose-manager',
                **vars(POLICIES['nearaidev/compose-manager']),
            ),
        )
    assert result.value.failure.details['reason'] == (
        'manager_image_missing' if image is None else 'manager_image_mismatch'
    )
    fetch.assert_not_awaited()


async def test_empty_policy_rejects_before_fetch(monkeypatch):
    fetch = AsyncMock(return_value=FetchResponse(status=503, body=b''))
    monkeypatch.setattr(compose_manager_provenance, 'fetch', fetch)
    with pytest.raises(VerificationError) as result:
        await verify_compose_manager_deployment_image_provenance(
            deployment(),
            {},
            manager_image_policy=ComposeManagerImagePolicy(
                image_repository='nearaidev/compose-manager',
                **vars(POLICIES['nearaidev/compose-manager']),
            ),
        )
    assert result.value.failure.code == 'provenance.deployment_images_invalid'
    assert result.value.failure.details['reason'] == 'empty_policy'
    fetch.assert_not_awaited()


async def test_nested_only_manager_is_not_serving_evidence(monkeypatch):
    async def fetch(url, **kwargs):
        nonce = parse_qs(urlsplit(url).query)['nonce'][0]
        report = cloud_attestation(nonce, model_name='test', tls_cert_fingerprint=None)
        manager = {
            'actions': [],
            'actions_hash': '00' * 32,
            'nonce': nonce,
            'quote': 'bb',
            'event_log': [],
        }
        return FetchResponse(
            status=200,
            body=json.dumps(
                {
                    **report,
                    'all_attestations': [
                        {**report, 'compose_manager_attestation': manager}
                    ],
                }
            ).encode(),
        )

    monkeypatch.setattr(cloud_api, 'default_fetch', fetch)
    result = await DirectAttestationClient(
        'https://model.example/v1'
    ).fetch_model_attestations(signing_algo='ecdsa')
    assert result.serving_attestation.compose_manager_attestation is None


async def test_stale_compose_cannot_vouch_for_current_manager_digest(monkeypatch):
    root = TrustedRoot.from_file(str(FIXTURES / 'provenance/trusted-root.json'))
    monkeypatch.setattr(Verifier, 'production', lambda: Verifier(trusted_root=root))
    compose_fetch = AsyncMock(
        return_value=FetchResponse(status=200, body=COMPOSE.encode())
    )
    monkeypatch.setattr(compose_manager_provenance, 'fetch', compose_fetch)
    bundle = json.loads(
        (FIXTURES / 'provenance/compose-manager-launcher.bundle.json').read_text()
    )
    fetch = AsyncMock(
        return_value=FetchResponse(
            status=200, body=json.dumps({'attestations': [{'bundle': bundle}]}).encode()
        )
    )
    monkeypatch.setattr(provenance, 'fetch', fetch)
    digest = 'sha256:' + 'bb' * 32
    with pytest.raises(VerificationError) as result:
        await verify_compose_manager_deployment_image_provenance(
            deployment('nearaidev/compose-manager@' + digest),
            POLICIES,
            manager_image_policy=ComposeManagerImagePolicy(
                image_repository='nearaidev/compose-manager',
                **vars(POLICIES['nearaidev/compose-manager']),
            ),
        )
    assert result.value.failure.code == 'provenance.image_verification_failed'
    assert result.value.failure.details['digest'] == digest
    assert result.value.failure.details['reasons'] == ['digest_mismatch']
    compose_fetch.assert_awaited_once()
    assert fetch.await_count == 2
