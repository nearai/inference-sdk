from __future__ import annotations

import json
from unittest.mock import AsyncMock, call

import pytest

import verifiable_ai_sdk.core.provenance as provenance
from verifiable_ai_sdk import (
    ApiError,
    ApiFailure,
    ImageProvenancePolicy,
    VerificationError,
    VerificationFailure,
    verify_deployment_image_provenance,
)


IMAGE = 'registry.example/gateway'
DIGEST = 'sha256:' + 'ab' * 32
POLICY = ImageProvenancePolicy(
    repository='example/gateway', workflow='.github/workflows/build.yml'
)
POLICIES = {IMAGE: POLICY}


def _compose(services: dict[str, object]) -> str:
    return json.dumps({'docker_compose_file': json.dumps({'services': services})})


async def test_verifies_selected_images_with_yaml_12_names_and_docker_io(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker_digest = 'sha256:' + 'cd' * 32
    worker_policy = ImageProvenancePolicy(
        repository='example/worker', workflow='.github/workflows/release.yml'
    )
    app_compose = json.dumps(
        {
            'docker_compose_file': f"""
services:
  yes:
    image: docker.io/{IMAGE}:stable@{DIGEST}
  worker:
    image: registry.example/worker@{worker_digest}
  unrelated:
    image: registry.example/other:latest
  build_only:
    build: .
  no_image:
    image: null
"""
        }
    )
    fetch = AsyncMock(return_value=['bundle'])
    verify = AsyncMock()
    monkeypatch.setattr(provenance, 'fetch_image_provenance', fetch)
    monkeypatch.setattr(provenance, 'verify_image_provenance', verify)

    await verify_deployment_image_provenance(
        app_compose,
        {IMAGE: POLICY, 'docker.io/registry.example/worker': worker_policy},
        'github-token',
    )

    assert fetch.await_args_list == [
        call(POLICY.repository, DIGEST, 'github-token'),
        call(worker_policy.repository, worker_digest, 'github-token'),
    ]
    assert verify.await_args_list == [
        call(['bundle'], DIGEST, POLICY),
        call(['bundle'], worker_digest, worker_policy),
    ]


@pytest.mark.parametrize(
    ('app_compose', 'policies', 'reason'),
    [
        ('', {}, 'empty_policy'),
        ('not JSON', POLICIES, 'invalid_app_compose'),
        (
            json.dumps({'docker_compose_file': 'services: ['}),
            POLICIES,
            'invalid_docker_compose',
        ),
        (
            json.dumps(
                {
                    'docker_compose_file': 'services:\n  gateway:\n'
                    f'    image: {IMAGE}:latest\n    image: {IMAGE}@{DIGEST}\n'
                }
            ),
            POLICIES,
            'invalid_docker_compose',
        ),
        (_compose({'gateway': {'image': 7}}), POLICIES, 'invalid_docker_compose'),
        (
            _compose({'other': {'image': '${UNRESOLVED_IMAGE}'}}),
            POLICIES,
            'unresolved_image',
        ),
        (
            _compose({'gateway': {'image': IMAGE + '@' + DIGEST}}),
            {IMAGE: POLICY, 'registry.example/worker': POLICY},
            'image_missing',
        ),
    ],
)
async def test_rejects_invalid_selection_before_fetching(
    monkeypatch: pytest.MonkeyPatch,
    app_compose: str,
    policies: dict[str, ImageProvenancePolicy],
    reason: str,
) -> None:
    fetch = AsyncMock()
    monkeypatch.setattr(provenance, 'fetch_image_provenance', fetch)

    with pytest.raises(VerificationError) as raised:
        await verify_deployment_image_provenance(app_compose, policies)

    assert raised.value.failure.code == 'provenance.deployment_images_invalid'
    assert raised.value.failure.details['reason'] == reason
    fetch.assert_not_awaited()


@pytest.mark.parametrize(
    'image',
    [IMAGE, IMAGE + ':latest', IMAGE + '@sha256:ab', IMAGE + ':bad!@' + DIGEST],
)
async def test_rejects_every_unpinned_match_even_when_another_service_is_pinned(
    monkeypatch: pytest.MonkeyPatch,
    image: str,
) -> None:
    fetch = AsyncMock()
    monkeypatch.setattr(provenance, 'fetch_image_provenance', fetch)
    app_compose = _compose(
        {'pinned': {'image': IMAGE + '@' + DIGEST}, 'unpinned': {'image': image}}
    )

    with pytest.raises(VerificationError) as raised:
        await verify_deployment_image_provenance(app_compose, POLICIES)

    assert raised.value.failure.details == {
        'reason': 'image_not_pinned',
        'imageRepository': IMAGE,
        'service': 'unpinned',
    }
    fetch.assert_not_awaited()


async def test_wraps_fetch_errors_and_preserves_retryability(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    failure = ApiError(ApiFailure(code='api.http_status', retryable=True))
    monkeypatch.setattr(
        provenance, 'fetch_image_provenance', AsyncMock(side_effect=failure)
    )

    with pytest.raises(VerificationError) as raised:
        await verify_deployment_image_provenance(
            _compose({'gateway': {'image': IMAGE + '@' + DIGEST}}), POLICIES
        )

    assert raised.value.failure.code == 'provenance.image_request_failed'
    assert raised.value.failure.details == {'imageRepository': IMAGE, 'digest': DIGEST}
    assert raised.value.retryable
    assert raised.value.cause is failure


async def test_preserves_image_verification_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    failure = VerificationError(
        VerificationFailure(code='provenance.image_verification_failed')
    )
    monkeypatch.setattr(
        provenance, 'fetch_image_provenance', AsyncMock(return_value=['bundle'])
    )
    monkeypatch.setattr(
        provenance, 'verify_image_provenance', AsyncMock(side_effect=failure)
    )

    with pytest.raises(VerificationError) as raised:
        await verify_deployment_image_provenance(
            _compose({'gateway': {'image': IMAGE + '@' + DIGEST}}), POLICIES
        )

    assert raised.value is failure
