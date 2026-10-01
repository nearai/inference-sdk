"""Build provenance for images named by a verified Compose Manager action log."""

import re
from collections.abc import Mapping
from urllib.parse import quote

from ..types.provenance import ImageProvenancePolicy
from ..types.verification import MeasuredDeployment
from ..utils.common import sha256
from ..utils.errors import VerificationError, verification_failure
from ..utils.fetch import fetch
from .provenance import verify_compose_image_provenance


async def verify_compose_manager_deployment_image_provenance(
    deployment: MeasuredDeployment,
    image_policies: Mapping[str, ImageProvenancePolicy],
    *,
    compose_repository: str = 'nearai/cvm-compose-files',
    compose_file: str | None = None,
    github_token: str | None = None,
) -> None:
    """Check the recorded compose file's hash, then its required image builds.

    Select the latest compose_up, optionally restricted to compose_file. This
    authenticates recorded deployment intent, not successful/current execution.
    """
    manager = deployment.compose_manager
    if manager is None:
        raise _invalid_deployment('attestation_missing')
    action = next(
        (
            entry
            for entry in reversed(manager.actions)
            if entry['action'] == 'compose_up'
            and (compose_file is None or entry.get('file') == compose_file)
        ),
        None,
    )
    if action is None:
        raise _invalid_deployment('compose_up_missing')
    commit, file, digest = (
        action.get('commit'),
        action.get('file'),
        action.get('file_sha256'),
    )
    if (
        not isinstance(commit, str)
        or re.fullmatch(r'[\da-fA-F]{40}', commit) is None
        or not isinstance(file, str)
        or any(part in ('', '.', '..') for part in file.split('/'))
        or not isinstance(digest, str)
        or re.fullmatch(r'[\da-fA-F]{64}', digest) is None
        or re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', compose_repository) is None
        or any(part in ('.', '..') for part in compose_repository.split('/'))
    ):
        raise _invalid_deployment('invalid_file_reference')
    details: dict[str, object] = {
        'repository': compose_repository,
        'commit': commit,
        'file': file,
    }
    repository_path = '/'.join(
        quote(part, safe='') for part in compose_repository.split('/')
    )
    file_path = '/'.join(quote(part, safe='') for part in file.split('/'))
    url = f'https://api.github.com/repos/{repository_path}/contents/{file_path}?ref={commit}'
    headers = {
        'Accept': 'application/vnd.github.raw+json',
        'X-GitHub-Api-Version': '2022-11-28',
    }
    if github_token is not None:
        headers['Authorization'] = f'Bearer {github_token}'
    try:
        response = await fetch(url, headers=headers, allow_redirects=False)
    except Exception as error:
        raise verification_failure(
            'provenance.compose_file_request_failed',
            details,
            retryable=True,
            cause=error,
        ) from error
    if not response.ok:
        raise verification_failure(
            'provenance.compose_file_request_failed',
            {**details, 'status': response.status},
            retryable=response.status == 429 or response.status >= 500,
        )
    if sha256(response.body) != bytes.fromhex(digest):
        raise verification_failure('provenance.compose_file_hash_mismatch', details)
    try:
        docker_compose = response.body.decode('utf-8')
    except UnicodeDecodeError as error:
        raise verification_failure(
            'provenance.deployment_images_invalid',
            {'reason': 'invalid_docker_compose'},
            cause=error,
        ) from error
    started = next(
        (
            entry
            for entry in reversed(manager.actions)
            if entry['action'] == 'compose_manager_started'
        ),
        None,
    )
    image = None if started is None else started.get('image')
    additional_images = [('compose-manager', image)] if isinstance(image, str) else []
    await verify_compose_image_provenance(
        docker_compose, image_policies, github_token, additional_images
    )


def _invalid_deployment(reason: str) -> VerificationError:
    return verification_failure(
        'provenance.compose_manager_deployment_invalid', {'reason': reason}
    )
