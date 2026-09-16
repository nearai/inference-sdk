from __future__ import annotations

import base64
import json
from dataclasses import replace
from pathlib import Path

import pytest
from sigstore.models import TrustedRoot
from sigstore.verify import Verifier

import verifiable_ai_sdk.core.provenance as provenance
from verifiable_ai_sdk import (
    ApiError,
    ImageProvenancePolicy,
    VerificationError,
    fetch_image_provenance,
    verify_image_provenance,
)
from verifiable_ai_sdk.schemas import SlsaStatementSchema
from verifiable_ai_sdk.utils.fetch import FetchResponse


FIXTURE = (
    Path(__file__).resolve().parents[3]
    / 'test-fixtures/provenance/compose-manager-launcher.bundle.json'
)
BUNDLE = FIXTURE.read_text()
DIGEST = 'sha256:91fdff3cfa3543d72656b2368c7d8a0a83d95a0f1087378c897aa1537acdba56'
COMMIT = '8e07c3583909c9ab9da94d883e87add1ae90832d'
POLICY = ImageProvenancePolicy(
    repository='nearai/compose-manager',
    workflow='.github/workflows/build.yml',
    ref='refs/heads/master',
    commit=COMMIT,
)


@pytest.fixture(scope='module')
def sigstore_verifier() -> Verifier:
    # Use a snapshot of the authenticated production trust root without network I/O.
    # Certificate, signature and transparency-log verification remain real.
    root = TrustedRoot.from_file(str(FIXTURE.with_name('trusted-root.json')))
    return Verifier(trusted_root=root)


@pytest.fixture(autouse=True)
def use_local_trust_root(
    monkeypatch: pytest.MonkeyPatch, sigstore_verifier: Verifier
) -> None:
    monkeypatch.setattr(Verifier, 'production', lambda: sigstore_verifier)


async def test_verifies_real_image_provenance_and_skips_an_invalid_candidate() -> None:
    result = await verify_image_provenance(['{}', BUNDLE], DIGEST, POLICY)

    assert result.digest == DIGEST
    assert result.repository == 'nearai/compose-manager'
    assert result.workflow == '.github/workflows/build.yml'
    assert result.ref == 'refs/heads/master'
    assert result.commit == COMMIT
    assert result.certificate_identity == (
        'https://github.com/nearai/compose-manager/'
        '.github/workflows/build.yml@refs/heads/master'
    )
    assert result.issuer == POLICY.issuer
    assert result.predicate_type == 'https://slsa.dev/provenance/v1'


async def test_rejects_tampered_signed_payload() -> None:
    bundle = json.loads(BUNDLE)
    payload = json.loads(base64.b64decode(bundle['dsseEnvelope']['payload']))
    payload['subject'][0]['digest']['sha256'] = 'ab' * 32
    encoded = base64.b64encode(json.dumps(payload).encode()).decode()
    bundle['dsseEnvelope']['payload'] = encoded

    with pytest.raises(VerificationError) as raised:
        await verify_image_provenance([json.dumps(bundle)], DIGEST, POLICY)

    assert raised.value.failure.code == 'provenance.image_verification_failed'
    assert raised.value.failure.details['reasons'] == ['invalid_bundle']


@pytest.mark.parametrize(
    ('policy', 'reason'),
    [
        (replace(POLICY, repository='nearai/cloud-api'), 'untrusted_identity'),
        (replace(POLICY, workflow='.github/workflows/other.yml'), 'untrusted_identity'),
        (replace(POLICY, ref='refs/heads/main'), 'untrusted_identity'),
        (replace(POLICY, issuer='https://example.com'), 'untrusted_identity'),
        (replace(POLICY, commit='ab' * 20), 'commit_mismatch'),
    ],
)
async def test_rejects_a_build_outside_the_callers_policy(
    policy: ImageProvenancePolicy, reason: str
) -> None:
    with pytest.raises(VerificationError) as raised:
        await verify_image_provenance([BUNDLE], DIGEST, policy)

    assert raised.value.failure.details['reasons'] == [reason]


async def test_reports_each_failed_candidate_reason() -> None:
    with pytest.raises(VerificationError) as raised:
        await verify_image_provenance(['{}', BUNDLE], 'sha256:' + 'ab' * 32, POLICY)

    assert raised.value.failure.details['reasons'] == [
        'invalid_bundle',
        'digest_mismatch',
    ]


async def test_rejects_missing_attestations() -> None:
    with pytest.raises(VerificationError) as raised:
        await verify_image_provenance([], DIGEST, POLICY)

    assert raised.value.failure.details['reasons'] == ['no_attestations']


async def test_fetches_every_github_page_without_following_bundle_urls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entry = {'bundle': json.loads(BUNDLE), 'bundle_url': 'https://example.com/ignored'}
    requested: list[str] = []

    async def github_response(url: str, **_: object) -> FetchResponse:
        requested.append(url)
        entries = [entry] * 100 if len(requested) == 1 else [entry]
        return FetchResponse(
            status=200, body=json.dumps({'attestations': entries}).encode()
        )

    monkeypatch.setattr(provenance, 'fetch', github_response)
    bundles = await fetch_image_provenance(POLICY.repository, DIGEST)

    assert len(bundles) == 101
    assert requested == [
        f'https://api.github.com/repos/nearai/compose-manager/attestations/{DIGEST}'
        f'?per_page=100&page={page}'
        for page in (1, 2)
    ]
    result = await verify_image_provenance(bundles, DIGEST, POLICY)
    assert result.commit == COMMIT


async def test_invalid_github_response_is_an_api_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def malformed_response(_: str, **__: object) -> FetchResponse:
        return FetchResponse(status=200, body=b'{"attestations":[{"bundle_url":"x"}]}')

    monkeypatch.setattr(provenance, 'fetch', malformed_response)
    with pytest.raises(ApiError) as raised:
        await fetch_image_provenance(POLICY.repository, DIGEST)

    assert raised.value.failure.code == 'api.invalid_response'


def test_slsa_v02_checks_the_workflow_source_not_an_unrelated_material() -> None:
    # SLSA v0.2 source extraction is a separate statement-boundary check. This
    # synthetic statement is not presented as a cryptographically signed bundle.
    payload = {
        '_type': 'https://in-toto.io/Statement/v0.1',
        'subject': [{'name': 'image', 'digest': {'sha256': DIGEST[7:]}}],
        'predicateType': 'https://slsa.dev/provenance/v0.2',
        'predicate': {
            'invocation': {
                'configSource': {
                    'uri': 'git+https://github.com/nearai/compose-manager@refs/heads/master',
                    'entryPoint': '.github/workflows/build.yml',
                    'digest': {'sha1': COMMIT},
                }
            }
        },
    }
    statement = SlsaStatementSchema.model_validate(payload)
    commit = provenance._verify_statement(statement, DIGEST, POLICY, POLICY.ref)
    assert commit == COMMIT

    payload['predicate']['invocation']['configSource']['entryPoint'] = 'other.yml'
    statement = SlsaStatementSchema.model_validate(payload)
    with pytest.raises(provenance._StatementMismatch) as raised:
        provenance._verify_statement(statement, DIGEST, POLICY, POLICY.ref)
    assert raised.value.reason == 'source_mismatch'
