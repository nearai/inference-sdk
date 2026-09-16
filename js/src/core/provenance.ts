import { Buffer } from 'buffer';
import * as v from 'valibot';
import {
  AnyOf,
  Identity,
  OIDCIssuer,
  OIDCIssuerV2,
  PolicyError,
  SigstoreVerifier,
  TrustedRootProvider,
} from '@freedomofpress/sigstore-browser';
import {
  GitHubImageAttestationsSchema,
  ImageProvenanceBundleSchema,
  ImageProvenanceStatementSchema,
} from '../schemas';
import type {
  FetchImageProvenanceParams,
  ImageProvenanceFailureReason,
  ImageProvenancePolicy,
  ImageProvenanceStatement,
  VerifiedImageProvenance,
  VerifyImageProvenanceParams,
} from '../types/provenance';
import { ApiError, VerificationError, inputError } from '../utils/errors';

const GITHUB_ISSUER = 'https://token.actions.githubusercontent.com';
// TUF authenticates root updates. In-memory caching works in both Node and
// browsers, without requiring IndexedDB or sharing application credentials.
const trustedRootProvider = new TrustedRootProvider({ disableCache: true });

/** Fetch all inline Sigstore bundles published for a repository's image digest. */
export async function fetchImageProvenance({
  repository,
  digest,
  githubToken,
}: FetchImageProvenanceParams): Promise<readonly string[]> {
  if (
    !/^[\w.-]+\/[\w.-]+$/.test(repository) ||
    repository.split('/').some((part) => part === '.' || part === '..')
  ) {
    throw invalidApiInput('repository', 'Expected a GitHub owner/repository');
  }
  if (!isSha256Digest(digest)) {
    throw invalidApiInput(
      'digest',
      'Expected sha256 followed by 64 hex digits',
    );
  }
  const repositoryPath = repository
    .split('/')
    .map(encodeURIComponent)
    .join('/');
  const headers: Record<string, string> = {
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
  };
  if (githubToken !== undefined) {
    headers.Authorization = `Bearer ${githubToken}`;
  }

  const bundles: string[] = [];
  for (let page = 1; ; page++) {
    const url = `https://api.github.com/repos/${repositoryPath}/attestations/${encodeURIComponent(digest.toLowerCase())}?per_page=100&page=${page}`;
    let response: Response;
    try {
      response = await fetch(url, { headers });
    } catch (cause) {
      throw new ApiError(
        {
          code: 'api.transport_failed',
          details: { resource: 'image_provenance', reason: 'request' },
          retryable: true,
        },
        { cause },
      );
    }
    if (!response.ok) {
      throw new ApiError({
        code: 'api.http_status',
        details: { resource: 'image_provenance', status: response.status },
        retryable: response.status === 429 || response.status >= 500,
      });
    }

    let raw: unknown;
    try {
      raw = await response.json();
    } catch (cause) {
      throw new ApiError(
        {
          code: 'api.invalid_json',
          details: { resource: 'image_provenance' },
        },
        { cause },
      );
    }
    const parsed = v.safeParse(GitHubImageAttestationsSchema, raw);
    if (!parsed.success) {
      throw new ApiError({
        code: 'api.invalid_response',
        details: {
          path: 'attestations',
          expected: 'An array of inline Sigstore bundles',
          actual: 'Invalid GitHub attestation response',
        },
      });
    }
    bundles.push(
      ...parsed.output.attestations.map(({ bundle }) => JSON.stringify(bundle)),
    );
    if (parsed.output.attestations.length < 100) {
      return bundles;
    }
  }
}

/**
 * Verify a GitHub Actions SLSA build proof for an image manifest digest.
 * One complete matching proof is sufficient. This checks the caller's build
 * policy; it does not prove which containers are running now.
 */
export async function verifyImageProvenance({
  bundles,
  digest,
  policy,
}: VerifyImageProvenanceParams): Promise<VerifiedImageProvenance> {
  if (!isSha256Digest(digest)) {
    throw inputError({ field: 'digest', reason: 'invalid_hex' });
  }
  const normalizedDigest = digest.toLowerCase();
  if (bundles.length === 0) {
    throw imageFailure({
      digest: normalizedDigest,
      reasons: ['no_attestations'],
    });
  }

  const verifier = new SigstoreVerifier();
  try {
    await verifier.loadSigstoreRootWithTUF(trustedRootProvider);
  } catch (cause) {
    throw imageFailure({
      digest: normalizedDigest,
      reasons: ['trust_root_unavailable'],
      cause,
    });
  }

  const reasons = new Set<ImageProvenanceFailureReason>();
  let lastCause: unknown;
  for (const bundleJson of bundles) {
    try {
      return await verifyBundle({
        verifier,
        bundleJson,
        digest: normalizedDigest,
        policy,
      });
    } catch (cause) {
      lastCause = cause;
      if (
        cause instanceof VerificationError &&
        cause.failure.code === 'provenance.image_verification_failed'
      ) {
        for (const reason of cause.failure.details.reasons) reasons.add(reason);
      } else {
        reasons.add(
          cause instanceof PolicyError
            ? 'untrusted_identity'
            : 'invalid_bundle',
        );
      }
    }
  }
  throw imageFailure({
    digest: normalizedDigest,
    reasons: [...reasons],
    cause: lastCause,
  });
}

type VerifyBundleParams = {
  verifier: SigstoreVerifier;
  bundleJson: string;
  digest: string;
  policy: ImageProvenancePolicy;
};

async function verifyBundle({
  verifier,
  bundleJson,
  digest,
  policy,
}: VerifyBundleParams): Promise<VerifiedImageProvenance> {
  const raw: unknown = JSON.parse(bundleJson);
  const parsed = v.safeParse(ImageProvenanceBundleSchema, raw);
  if (!parsed.success)
    throw imageFailure({ digest, reasons: ['invalid_bundle'] });

  const issuer = policy.issuer ?? GITHUB_ISSUER;
  const identityPrefix = `https://github.com/${policy.repository}/${policy.workflow}@`;
  let certificateIdentity = '';
  let ref = '';
  const verified = await verifier.verifyDsse(parsed.output, {
    verify(cert) {
      const identity = cert.extSubjectAltName?.uri ?? '';
      const candidateRef = identity.slice(identityPrefix.length);
      if (
        !identity.startsWith(identityPrefix) ||
        !candidateRef.startsWith('refs/') ||
        (policy.ref !== undefined && policy.ref !== candidateRef)
      ) {
        throw new PolicyError(
          'The certificate does not match the required repository, workflow and ref',
        );
      }
      new Identity({ identity }).verify(cert);
      new AnyOf([new OIDCIssuer(issuer), new OIDCIssuerV2(issuer)]).verify(
        cert,
      );
      certificateIdentity = identity;
      ref = candidateRef;
    },
  });

  let statementRaw: unknown;
  try {
    statementRaw = JSON.parse(new TextDecoder().decode(verified.payload));
  } catch (cause) {
    throw imageFailure({ digest, reasons: ['invalid_statement'], cause });
  }
  const statement = v.safeParse(ImageProvenanceStatementSchema, statementRaw);
  if (
    !statement.success ||
    verified.payloadType !== 'application/vnd.in-toto+json'
  ) {
    throw imageFailure({ digest, reasons: ['invalid_statement'] });
  }
  const expectedDigest = Buffer.from(digest.slice('sha256:'.length), 'hex');
  const subjectMatches = statement.output.subject.some(
    ({ digest: subjectDigest }) => {
      const sha256 = subjectDigest.sha256;
      return (
        sha256 !== undefined &&
        /^[a-f\d]{64}$/i.test(sha256) &&
        Buffer.from(sha256, 'hex').equals(expectedDigest)
      );
    },
  );
  if (!subjectMatches)
    throw imageFailure({ digest, reasons: ['digest_mismatch'] });

  const commit = verifyImageProvenanceSource({
    statement: statement.output,
    policy,
    ref,
    digest,
  });
  return {
    digest,
    repository: policy.repository,
    workflow: policy.workflow,
    ref,
    commit,
    certificateIdentity,
    issuer,
    predicateType: statement.output.predicateType,
  };
}

type VerifyImageProvenanceSourceParams = {
  statement: ImageProvenanceStatement;
  policy: ImageProvenancePolicy;
  ref: string;
  digest: string;
};

/** Match source fields after the enclosing DSSE statement has been verified. */
export function verifyImageProvenanceSource({
  statement,
  policy,
  ref,
  digest,
}: VerifyImageProvenanceSourceParams): string {
  const repositoryUrl = `https://github.com/${policy.repository}`;
  let commit: string | undefined;
  if (statement.predicateType === 'https://slsa.dev/provenance/v1') {
    const { externalParameters, resolvedDependencies } =
      statement.predicate.buildDefinition;
    const workflow = externalParameters.workflow;
    if (
      workflow.repository.replace(/\.git$/, '') !== repositoryUrl ||
      workflow.path !== policy.workflow ||
      workflow.ref !== ref
    ) {
      throw imageFailure({ digest, reasons: ['source_mismatch'] });
    }
    commit = resolvedDependencies.find(({ uri }) =>
      matchesSourceUri({ uri, repositoryUrl, ref }),
    )?.digest.gitCommit;
  } else {
    const source = statement.predicate.invocation.configSource;
    if (
      !matchesSourceUri({ uri: source.uri, repositoryUrl, ref }) ||
      source.entryPoint !== policy.workflow
    ) {
      throw imageFailure({ digest, reasons: ['source_mismatch'] });
    }
    commit = source.digest.sha1;
  }
  if (commit === undefined || !/^[a-f\d]{40}$/i.test(commit)) {
    throw imageFailure({ digest, reasons: ['source_mismatch'] });
  }
  const normalizedCommit = commit.toLowerCase();
  if (
    policy.commit !== undefined &&
    (!/^[a-f\d]{40}$/i.test(policy.commit) ||
      !Buffer.from(normalizedCommit, 'hex').equals(
        Buffer.from(policy.commit, 'hex'),
      ))
  ) {
    throw imageFailure({ digest, reasons: ['commit_mismatch'] });
  }
  return normalizedCommit;
}

function isSha256Digest(digest: string): boolean {
  return /^sha256:[a-fA-F\d]{64}$/.test(digest);
}

type MatchesSourceUriParams = {
  uri: string;
  repositoryUrl: string;
  ref: string;
};

function matchesSourceUri({
  uri,
  repositoryUrl,
  ref,
}: MatchesSourceUriParams): boolean {
  const source = uri.replace(/^git\+/, '');
  return (
    source === `${repositoryUrl}@${ref}` ||
    source === `${repositoryUrl}.git@${ref}`
  );
}

function invalidApiInput(field: string, expected: string): ApiError {
  return new ApiError({
    code: 'api.invalid_input',
    details: { field, reason: 'unsupported_value', expected },
  });
}

type ImageFailureParams = {
  digest: string;
  reasons: readonly ImageProvenanceFailureReason[];
  cause?: unknown;
};

function imageFailure({
  digest,
  reasons,
  cause,
}: ImageFailureParams): VerificationError {
  return new VerificationError(
    {
      code: 'provenance.image_verification_failed',
      details: { digest, reasons },
      retryable: reasons.includes('trust_root_unavailable'),
    },
    cause === undefined ? undefined : { cause },
  );
}
