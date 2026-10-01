import { Buffer } from 'buffer';
import type {
  ComposeManagerDeploymentFailureReason,
  VerifyComposeManagerDeploymentImageProvenanceParams,
} from '../types/compose-manager';
import { sha256 } from '../utils/common';
import { VerificationError } from '../utils/errors';
import { verifyComposeImageProvenance } from './deployment-provenance';

type ComposeFileReference = {
  repository: string;
  commit: string;
  file: string;
  sha256: string;
};

/**
 * Check images named by a quote-authenticated Compose Manager deployment log.
 * The compose file is fetched at its recorded commit and checked byte-for-byte
 * before any image provenance requests. No current-runtime claim is inferred.
 */
export async function verifyComposeManagerDeploymentImageProvenance({
  deployment,
  imagePolicies,
  composeRepository = 'nearai/cvm-compose-files',
  composeFile,
  githubToken,
}: VerifyComposeManagerDeploymentImageProvenanceParams): Promise<void> {
  const manager = deployment.composeManager;
  if (manager === undefined) throw invalidDeployment('attestation_missing');
  const newestActions = [...manager.actions].reverse();
  const action = newestActions.find(
    (entry) =>
      entry.action === 'compose_up' &&
      (composeFile === undefined || entry.file === composeFile),
  );
  if (action === undefined) throw invalidDeployment('compose_up_missing');
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
  const dockerCompose = await fetchComposeFile(
    {
      repository: composeRepository,
      commit,
      file,
      sha256: digest,
    },
    githubToken,
  );

  // A manager self-update is not reflected in the serving model compose.
  // Include the latest started image when the caller's policy requires it.
  const started = newestActions.find(
    (entry) => entry.action === 'compose_manager_started',
  );
  const additionalImages =
    started?.image === undefined
      ? []
      : [{ service: 'compose-manager', image: started.image }];
  await verifyComposeImageProvenance({
    dockerCompose,
    imagePolicies,
    githubToken,
    additionalImages,
  });
}

async function fetchComposeFile(
  reference: ComposeFileReference,
  githubToken: string | undefined,
): Promise<string> {
  const { repository, commit, file } = reference;
  const repositoryPath = repository
    .split('/')
    .map(encodeURIComponent)
    .join('/');
  const filePath = file.split('/').map(encodeURIComponent).join('/');
  const url = `https://api.github.com/repos/${repositoryPath}/contents/${filePath}?ref=${commit}`;
  const headers: Record<string, string> = {
    Accept: 'application/vnd.github.raw+json',
    'X-GitHub-Api-Version': '2022-11-28',
  };
  if (githubToken !== undefined)
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
    bytes = Buffer.from(await response.arrayBuffer());
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
  const digest = await sha256(bytes);
  if (!digest.equals(Buffer.from(reference.sha256, 'hex'))) {
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
