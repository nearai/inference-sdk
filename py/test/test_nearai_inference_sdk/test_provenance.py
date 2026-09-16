from __future__ import annotations

import base64
import json
from collections.abc import Mapping
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sigstore.models import TrustedRoot
from sigstore.verify import Verifier

import nearai_inference_sdk.core.provenance as provenance
from nearai_inference_sdk import (
    ApiError,
    ImageProvenancePolicy,
    VerificationError,
    fetch_image_provenance,
    verify_image_provenance,
)
from nearai_inference_sdk.schemas import SlsaStatementSchema
from nearai_inference_sdk.utils.fetch import FetchResponse


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


@pytest.mark.parametrize('commit_pin', [COMMIT, None])
async def test_verifies_real_image_provenance_and_skips_an_invalid_candidate(
    commit_pin: str | None,
) -> None:
    result = await verify_image_provenance(
        ['{}', BUNDLE], DIGEST, replace(POLICY, commit=commit_pin)
    )

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


def _certificate_with_extensions(extensions: dict[int, bytes]) -> x509.Certificate:
    # Generated certificates exercise only the source-policy boundary. The real
    # bundle tests above remain responsible for Sigstore cryptographic verification.
    key = Ed25519PrivateKey.generate()
    name = x509.Name(
        [x509.NameAttribute(x509.NameOID.COMMON_NAME, 'source-policy-test')]
    )
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(datetime(2026, 1, 1, tzinfo=timezone.utc))
        .not_valid_after(datetime(2027, 1, 1, tzinfo=timezone.utc))
    )
    for suffix, value in extensions.items():
        builder = builder.add_extension(
            x509.UnrecognizedExtension(
                x509.ObjectIdentifier(f'1.3.6.1.4.1.57264.1.{suffix}'), value
            ),
            critical=False,
        )
    return builder.sign(key, algorithm=None)


@pytest.mark.parametrize('commit_pin', [COMMIT, None])
def test_statement_commit_must_match_certificate_source_even_without_a_pin(
    commit_pin: str | None,
) -> None:
    statement = SlsaStatementSchema.model_validate_json(
        base64.b64decode(json.loads(BUNDLE)['dsseEnvelope']['payload'])
    )
    certificate = _certificate_with_extensions(
        {13: b'\x0c\x28' + b'ab' * 20, 3: COMMIT.encode()}
    )
    with pytest.raises(provenance._StatementMismatch) as raised:
        provenance._verify_statement(
            statement,
            DIGEST,
            replace(POLICY, commit=commit_pin),
            POLICY.ref,
            certificate,
        )

    assert raised.value.reason == 'source_mismatch'


def test_uses_legacy_certificate_sha_when_source_digest_is_absent() -> None:
    certificate = _certificate_with_extensions({3: COMMIT.upper().encode()})

    assert provenance._certificate_source_commit(certificate) == COMMIT


@pytest.mark.parametrize(
    'extensions',
    [
        {},
        {10: b'\x0c\x28' + COMMIT.encode(), 19: b'\x0c\x28' + COMMIT.encode()},
        {13: COMMIT.encode(), 3: COMMIT.encode()},
        {13: b'\x0c\x28' + b'z' * 40, 3: COMMIT.encode()},
        {3: b'not-a-commit'},
    ],
)
def test_rejects_missing_or_malformed_certificate_source(
    extensions: dict[int, bytes],
) -> None:
    certificate = _certificate_with_extensions(extensions)
    with pytest.raises(provenance._StatementMismatch) as raised:
        provenance._certificate_source_commit(certificate)

    assert raised.value.reason == 'source_mismatch'


@pytest.mark.parametrize('cursor', ['before', 'after'])
async def test_fetches_github_cursor_pages_without_following_returned_urls(
    monkeypatch: pytest.MonkeyPatch,
    cursor: str,
) -> None:
    entry = {'bundle': json.loads(BUNDLE), 'bundle_url': 'https://example.com/ignored'}
    requested: list[str] = []
    base_url = (
        f'https://api.github.com/repos/nearai/compose-manager/attestations/{DIGEST}'
        '?per_page=100'
    )

    async def github_response(url: str, *, headers: Mapping[str, str]) -> FetchResponse:
        requested.append(url)
        assert headers['Authorization'] == 'Bearer test-token'
        assert len(requested) <= 2
        entries = [entry] if len(requested) == 1 else [entry] * 100
        return FetchResponse(
            status=200,
            body=json.dumps({'attestations': entries}).encode(),
            headers={
                'lInK': '<https://example.com/ignored?after=ignored>; rel="prev", '
                f'<https://example.com/ignored?per_page=1&{cursor}=cursor%2B%2F%3D>'
                '; rel="next"',
            }
            if len(requested) == 1
            else {},
        )

    monkeypatch.setattr(provenance, 'fetch', github_response)
    bundles = await fetch_image_provenance(POLICY.repository, DIGEST, 'test-token')

    assert bundles == [json.dumps(entry['bundle'])] * 101
    assert requested == [base_url, f'{base_url}&{cursor}=cursor%2B%2F%3D']
    result = await verify_image_provenance(bundles, DIGEST, POLICY)
    assert result.commit == COMMIT


@pytest.mark.parametrize(
    ('query', 'request_count'),
    [('page=2', 1), ('after=', 1), ('after=repeated', 2)],
)
async def test_rejects_an_invalid_or_repeated_github_cursor(
    monkeypatch: pytest.MonkeyPatch,
    query: str,
    request_count: int,
) -> None:
    requested: list[str] = []

    async def github_response(url: str, **_: object) -> FetchResponse:
        requested.append(url)
        assert len(requested) <= 2
        return FetchResponse(
            status=200,
            body=b'{"attestations":[]}',
            headers={'Link': f'<https://api.github.com/?{query}>; rel="next"'},
        )

    monkeypatch.setattr(provenance, 'fetch', github_response)
    with pytest.raises(ApiError) as raised:
        await fetch_image_provenance(POLICY.repository, DIGEST)

    assert raised.value.failure.code == 'api.invalid_response'
    assert raised.value.failure.details['path'] == 'Link'
    assert len(requested) == request_count


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
    certificate = _certificate_with_extensions({13: b'\x0c\x28' + COMMIT.encode()})
    commit = provenance._verify_statement(
        statement, DIGEST, POLICY, POLICY.ref, certificate
    )
    assert commit == COMMIT

    payload['predicate']['invocation']['configSource']['entryPoint'] = 'other.yml'
    statement = SlsaStatementSchema.model_validate(payload)
    with pytest.raises(provenance._StatementMismatch) as raised:
        provenance._verify_statement(statement, DIGEST, POLICY, POLICY.ref, certificate)
    assert raised.value.reason == 'source_mismatch'
