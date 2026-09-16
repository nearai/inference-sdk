"""Verify GitHub image build attestations with Sigstore's production trust root.

The caller supplies the expected build identity. These helpers do not discover
trusted publishers, approve deployment versions, or inspect running containers.
"""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from urllib.parse import parse_qsl, quote, urlencode, urlsplit

from cryptography import x509
from pydantic import ValidationError
from sigstore.errors import Error as SigstoreError
from sigstore.errors import VerificationError as SigstoreVerificationError
from sigstore.models import Bundle
from sigstore.verify import Verifier
from sigstore.verify.policy import Identity

from ..schemas import GitHubImageAttestationsSchema, SlsaStatementSchema
from ..types.provenance import ImageProvenancePolicy, VerifiedImageProvenance
from ..utils.errors import VerificationError, api_failure, verification_failure
from ..utils.fetch import fetch


_DIGEST_PATTERN = re.compile(r'sha256:[0-9a-fA-F]{64}')
_REPOSITORY_PATTERN = re.compile(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+')
_COMMIT_PATTERN = re.compile(r'[0-9a-fA-F]{40}')
_SOURCE_REPOSITORY_DIGEST_OID = x509.ObjectIdentifier('1.3.6.1.4.1.57264.1.13')
_GITHUB_WORKFLOW_SHA_OID = x509.ObjectIdentifier('1.3.6.1.4.1.57264.1.3')


async def fetch_image_provenance(
    repository: str, digest: str, github_token: str | None = None
) -> list[str]:
    """Fetch inline Sigstore bundles for an image digest from a GitHub repository.

    ``github_token`` is an optional GitHub token, not a Gateway API key. Only
    api.github.com is requested; returned bundle URLs are never followed.
    """

    if not _REPOSITORY_PATTERN.fullmatch(repository) or any(
        part in ('.', '..') for part in repository.split('/')
    ):
        raise api_failure(
            'api.invalid_input',
            {
                'field': 'repository',
                'reason': 'unsupported_value',
                'expected': 'owner/repo',
            },
        )
    if not _DIGEST_PATTERN.fullmatch(digest):
        raise api_failure(
            'api.invalid_input',
            {
                'field': 'digest',
                'reason': 'unsupported_value',
                'expected': 'sha256:<64 hex characters>',
            },
        )
    headers = {
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
    }
    if github_token is not None:
        headers['Authorization'] = f'Bearer {github_token}'

    base_url = (
        f'https://api.github.com/repos/{repository}/attestations/'
        f'{quote(digest.lower(), safe=":")}?per_page=100'
    )
    url = base_url
    visited = {url}
    bundles: list[str] = []
    while True:
        try:
            response = await fetch(url, headers=headers)
        except Exception as error:
            raise api_failure(
                'api.transport_failed',
                {'resource': 'image_provenance', 'reason': 'request'},
                retryable=True,
                cause=error,
            ) from error
        if not response.ok:
            raise api_failure(
                'api.http_status',
                {'resource': 'image_provenance', 'status': response.status},
                retryable=response.status == 429 or response.status >= 500,
            )
        try:
            raw = json.loads(response.body)
        except (ValueError, UnicodeDecodeError) as error:
            raise api_failure(
                'api.invalid_json',
                {'resource': 'image_provenance'},
                cause=error,
            ) from error
        try:
            parsed = GitHubImageAttestationsSchema.model_validate(raw)
        except ValidationError as error:
            raise api_failure(
                'api.invalid_response',
                {
                    'resource': 'image_provenance',
                    'path': 'attestations',
                    'expected': 'GitHub attestations with inline bundles',
                    'actual': 'invalid response',
                },
                cause=error,
            ) from error
        bundles.extend(json.dumps(item.bundle) for item in parsed.attestations)
        link = ', '.join(
            value for name, value in response.headers.items() if name.lower() == 'link'
        )
        try:
            next_url = _next_attestation_url(link, base_url)
            if next_url is None:
                return bundles
            if next_url in visited:
                raise ValueError('repeated pagination cursor')
        except ValueError as error:
            raise api_failure(
                'api.invalid_response',
                {
                    'resource': 'image_provenance',
                    'path': 'Link',
                    'expected': 'a next link with a new before or after cursor',
                    'actual': 'invalid or repeated pagination cursor',
                },
                cause=error,
            ) from error
        visited.add(next_url)
        url = next_url


def _next_attestation_url(link: str, base_url: str) -> str | None:
    for entry in re.split(r',\s*(?=<)', link):
        relation = re.search(r';\s*rel\s*=\s*(?:"([^"]*)"|([^;\s]+))', entry)
        if relation is None or 'next' not in (relation[1] or relation[2] or '').split():
            continue
        target = re.match(r'\s*<([^>]*)>', entry)
        if target is None:
            raise ValueError('invalid pagination link')
        parsed_url = urlsplit(target[1])
        if not parsed_url.scheme or not parsed_url.netloc:
            raise ValueError('invalid pagination URL')
        cursors = [
            (name, value)
            for name, value in parse_qsl(
                parsed_url.query, keep_blank_values=True, errors='strict'
            )
            if name in ('before', 'after')
        ]
        if len(cursors) != 1 or not cursors[0][1]:
            raise ValueError('missing or ambiguous pagination cursor')
        # The link contributes only its cursor, never its origin or path.
        return f'{base_url}&{urlencode(cursors)}'
    return None


async def verify_image_provenance(
    bundles: Sequence[str], digest: str, policy: ImageProvenancePolicy
) -> VerifiedImageProvenance:
    """Accept any bundle that verifies the digest and caller's build policy.

    Sigstore authenticates the certificate, DSSE signature and transparency-log
    evidence. Only then do we interpret the in-toto statement and match its
    subject digest, source repository and certificate's source commit before
    applying the optional reviewed commit pin.
    """

    if not _DIGEST_PATTERN.fullmatch(digest):
        raise verification_failure(
            'input.invalid',
            {
                'field': 'digest',
                'reason': 'unsupported_value',
                'expected': 'sha256:<64 hex characters>',
            },
        )
    if not bundles:
        raise _provenance_failure(digest, ['no_attestations'])
    # Sigstore refreshes its TUF trust root synchronously. Keep this and the
    # subsequent certificate/signature checks off the caller's asyncio loop.
    return await asyncio.to_thread(_verify_bundles, bundles, digest.lower(), policy)


class _IdentityMismatch(SigstoreVerificationError):
    pass


class _StatementMismatch(Exception):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass
class _GitHubBuildIdentity:
    expected: ImageProvenancePolicy
    identity: str = ''
    ref: str = ''

    def verify(self, cert: x509.Certificate) -> None:
        prefix = (
            f'https://github.com/{self.expected.repository}/{self.expected.workflow}@'
        )
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            identities = san.value.get_values_for_type(x509.UniformResourceIdentifier)
            for identity in identities:
                if not identity.startswith(prefix):
                    continue
                ref = identity[len(prefix) :]
                if not ref.startswith('refs/'):
                    continue
                if self.expected.ref is not None and ref != self.expected.ref:
                    continue
                Identity(identity=identity, issuer=self.expected.issuer).verify(cert)
                self.identity = identity
                self.ref = ref
                return
        except (x509.ExtensionNotFound, SigstoreVerificationError) as error:
            raise _IdentityMismatch(
                'GitHub build identity does not match policy'
            ) from error
        raise _IdentityMismatch('GitHub build identity does not match policy')


def _verify_bundles(
    bundles: Sequence[str], digest: str, policy: ImageProvenancePolicy
) -> VerifiedImageProvenance:
    try:
        verifier = Verifier.production()
    except Exception as error:
        raise _provenance_failure(digest, ['trust_root_unavailable'], error) from error

    reasons: list[str] = []
    last_error: BaseException | None = None
    for raw in bundles:
        identity = _GitHubBuildIdentity(policy)
        try:
            bundle = Bundle.from_json(raw)
            content_type, payload = verifier.verify_dsse(bundle, identity)
            if content_type != 'application/vnd.in-toto+json':
                raise _StatementMismatch('invalid_statement')
            try:
                statement = SlsaStatementSchema.model_validate_json(payload)
            except ValidationError as error:
                raise _StatementMismatch('invalid_statement') from error
            commit = _verify_statement(
                statement, digest, policy, identity.ref, bundle.signing_certificate
            )
            return VerifiedImageProvenance(
                digest=digest,
                repository=policy.repository,
                workflow=policy.workflow,
                ref=identity.ref,
                commit=commit,
                certificate_identity=identity.identity,
                issuer=policy.issuer,
                predicate_type=statement.predicate_type,
            )
        except _IdentityMismatch as error:
            reason = 'untrusted_identity'
            last_error = error
        except _StatementMismatch as error:
            reason = error.reason
            last_error = error
        except (SigstoreError, ValueError, TypeError) as error:
            reason = 'invalid_bundle'
            last_error = error
        if reason not in reasons:
            reasons.append(reason)
    raise _provenance_failure(digest, reasons, last_error)


def _verify_statement(
    statement: SlsaStatementSchema,
    digest: str,
    policy: ImageProvenancePolicy,
    ref: str,
    certificate: x509.Certificate,
) -> str:
    expected_hash = digest.removeprefix('sha256:')
    if not any(
        subject.digest.get('sha256', '').lower() == expected_hash
        for subject in statement.subject
    ):
        raise _StatementMismatch('digest_mismatch')

    expected_repository = f'https://github.com/{policy.repository}'
    commit: str | None = None
    if statement.predicate_type == 'https://slsa.dev/provenance/v1':
        definition = statement.predicate.build_definition
        if definition is None:
            raise _StatementMismatch('invalid_statement')
        workflow = definition.external_parameters.workflow
        if (
            workflow.repository.removesuffix('.git') != expected_repository
            or workflow.path != policy.workflow
            or workflow.ref != ref
        ):
            raise _StatementMismatch('source_mismatch')
        for dependency in definition.resolved_dependencies:
            if _source_matches(dependency.uri, expected_repository, ref):
                commit = dependency.digest.get('gitCommit')
                break
    else:
        invocation = statement.predicate.invocation
        if invocation is None:
            raise _StatementMismatch('invalid_statement')
        source = invocation.config_source
        if (
            not _source_matches(source.uri, expected_repository, ref)
            or source.entry_point != policy.workflow
        ):
            raise _StatementMismatch('source_mismatch')
        commit = source.digest.get('sha1')
    if commit is None:
        raise _StatementMismatch('source_mismatch')
    if not _COMMIT_PATTERN.fullmatch(commit):
        raise _StatementMismatch('source_mismatch')
    if commit.lower() != _certificate_source_commit(certificate):
        raise _StatementMismatch('source_mismatch')
    if policy.commit is not None and commit.lower() != policy.commit.lower():
        raise _StatementMismatch('commit_mismatch')
    return commit.lower()


def _certificate_source_commit(certificate: x509.Certificate) -> str:
    for oid, prefix in (
        (_SOURCE_REPOSITORY_DIGEST_OID, b'\x0c\x28'),
        (_GITHUB_WORKFLOW_SHA_OID, b''),
    ):
        try:
            extension = certificate.extensions.get_extension_for_oid(oid).value
        except x509.ExtensionNotFound:
            continue
        if not isinstance(extension, x509.UnrecognizedExtension):
            raise _StatementMismatch('source_mismatch')
        # The modern field is a DER UTF8String with a 40-byte SHA; the legacy
        # field is raw text. A present but malformed modern field cannot fall back.
        value = extension.value
        if not value.startswith(prefix):
            raise _StatementMismatch('source_mismatch')
        commit = value[len(prefix) :]
        if re.fullmatch(rb'[0-9a-fA-F]{40}', commit) is None:
            raise _StatementMismatch('source_mismatch')
        return commit.decode('ascii').lower()
    raise _StatementMismatch('source_mismatch')


def _source_matches(uri: str, repository: str, ref: str) -> bool:
    source, separator, source_ref = uri.removeprefix('git+').partition('@')
    return (
        bool(separator)
        and source.removesuffix('.git') == repository
        and source_ref == ref
    )


def _provenance_failure(
    digest: str, reasons: list[str], cause: BaseException | None = None
) -> VerificationError:
    return verification_failure(
        'provenance.image_verification_failed',
        {'digest': digest, 'reasons': reasons},
        retryable=reasons == ['trust_root_unavailable'],
        cause=cause,
    )
