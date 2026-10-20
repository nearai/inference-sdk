import { Buffer } from 'buffer';
import type {
  ComposeManagerDeploymentFailureReason,
  VerifyComposeManagerDeploymentImageProvenanceParams,
} from '../types/compose-manager';
import { sha256 } from '../utils/common';
import { VerificationError } from '../utils/errors';
import {
  requirePinnedImageDigest,
  verifyComposeImageProvenance,
} from './deployment-provenance';

type FetchComposeFileParams = {
  repository: string;
  commit: string;
  file: string;
  sha256: string;
  githubToken?: string;
  githubProxyUrl?: string;
};

/**
 * Check images named by a quote-authenticated Compose Manager deployment log.
 * The compose file is fetched at its recorded commit and checked byte-for-byte
 * before any image provenance requests. No current-runtime claim is inferred.
 */
export async function verifyComposeManagerDeploymentImageProvenance({
  deployment,
  imagePolicies,
  managerImagePolicy,
  composeRepository = 'nearai/cvm-compose-files',
  composeFile,
  githubToken,
  githubProxyUrl,
}: VerifyComposeManagerDeploymentImageProvenanceParams): Promise<void> {
  if (Object.keys(imagePolicies).length === 0) {
    throw new VerificationError({
      code: 'provenance.deployment_images_invalid',
      details: { reason: 'empty_policy' },
    });
  }
  const manager = deployment.composeManager;
  if (manager === undefined) throw invalidDeployment('attestation_missing');
  const newestActions = [...manager.actions].reverse();
  const action = newestActions.find(
    (entry) =>
      entry.action === 'compose_up' &&
      (composeFile === undefined || entry.file === composeFile),
  );
  if (action === undefined) throw invalidDeployment('compose_up_missing');
  const started = newestActions.find(
    (entry) => entry.action === 'compose_manager_started',
  );
  if (started?.image === undefined)
    throw invalidDeployment('manager_image_missing');
  const managerRepository = managerImagePolicy.imageRepository.replace(
    /^docker\.io\//,
    '',
  );
  const managerImage = started.image.replace(/^docker\.io\//, '');
  if (
    managerRepository === '' ||
    (!managerImage.startsWith(`${managerRepository}@`) &&
      !managerImage.startsWith(`${managerRepository}:`))
  )
    throw invalidDeployment('manager_image_mismatch');
  requirePinnedImageDigest(managerImage, managerRepository, 'compose-manager');
  const { commit, file, file_sha256: digest } = action;
  if (
    commit === undefined ||
    !/^[\da-f]{40}$/i.test(commit) ||
    file === undefined ||
    file
      .split('/')
      .some((part) => part === '' || part === '.' || part === '..') ||
    digest === undefined ||
    !/^[\da-f]{64}$/i.test(digest) ||
    !/^[\w.-]+\/[\w.-]+$/.test(composeRepository) ||
    composeRepository.split('/').some((part) => part === '.' || part === '..')
  ) {
    throw invalidDeployment('invalid_file_reference');
  }
  const dockerCompose = await fetchComposeFile({
    repository: composeRepository,
    commit,
    file,
    sha256: digest,
    githubToken,
    githubProxyUrl,
  });

  await verifyComposeImageProvenance({
    dockerCompose,
    imagePolicies,
    githubToken,
    githubProxyUrl,
    services: action.services,
  });
  // A stale compose reference cannot satisfy the current manager's policy.
  await verifyComposeImageProvenance({
    dockerCompose: 'services: {}',
    imagePolicies: { [managerRepository]: managerImagePolicy },
    githubToken,
    githubProxyUrl,
    additionalImages: [{ service: 'compose-manager', image: managerImage }],
  });
}

async function fetchComposeFile({
  repository,
  commit,
  file,
  sha256: expectedDigest,
  githubToken,
  githubProxyUrl,
}: FetchComposeFileParams): Promise<string> {
  const repositoryPath = repository
    .split('/')
    .map(encodeURIComponent)
    .join('/');
  const filePath = file.split('/').map(encodeURIComponent).join('/');
  const apiUrl = (githubProxyUrl ?? 'https://api.github.com').replace(
    /\/+$/,
    '',
  );
  const url = `${apiUrl}/repos/${repositoryPath}/contents/${filePath}?ref=${commit}`;
  const headers: Record<string, string> = {
    Accept: 'application/vnd.github.raw+json',
    'X-GitHub-Api-Version': '2022-11-28',
  };
  if (githubProxyUrl === undefined && githubToken !== undefined)
    headers.Authorization = `Bearer ${githubToken}`;
  let response: Response;
  try {
    response = await fetch(url, { headers, redirect: 'error' });
  } catch (cause) {
    throw new VerificationError(
      {
        code: 'provenance.compose_file_request_failed',
        details: { repository, commit, file },
        retryable: true,
      },
      { cause },
    );
  }
  if (!response.ok) {
    throw new VerificationError({
      code: 'provenance.compose_file_request_failed',
      details: { repository, commit, file, status: response.status },
      retryable: response.status === 429 || response.status >= 500,
    });
  }
  let bytes: Buffer;
  try {
    const reader = response.body?.getReader();
    const chunks: Uint8Array[] = [];
    let length = 0;
    if (reader !== undefined) {
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          if (value.byteLength > 8 * 1024 * 1024 - length) {
            void reader.cancel().catch(() => {});
            throw invalidDeployment('compose_file_too_large');
          }
          chunks.push(value);
          length += value.byteLength;
        }
      } finally {
        reader.releaseLock();
      }
    }
    bytes = Buffer.concat(chunks, length);
  } catch (cause) {
    if (cause instanceof VerificationError) throw cause;
    throw new VerificationError(
      {
        code: 'provenance.compose_file_request_failed',
        details: { repository, commit, file },
        retryable: true,
      },
      { cause },
    );
  }
  const digest = await sha256(bytes);
  if (!digest.equals(Buffer.from(expectedDigest, 'hex'))) {
    throw new VerificationError({
      code: 'provenance.compose_file_hash_mismatch',
      details: { repository, commit, file },
    });
  }
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch (cause) {
    throw new VerificationError(
      {
        code: 'provenance.deployment_images_invalid',
        details: { reason: 'invalid_docker_compose' },
      },
      { cause },
    );
  }
}

function invalidDeployment(
  reason: ComposeManagerDeploymentFailureReason,
): VerificationError {
  return new VerificationError({
    code: 'provenance.compose_manager_deployment_invalid',
    details: { reason },
  });
}
