import { readFileSync } from 'node:fs';
import { Buffer } from 'node:buffer';
import { resolve } from 'node:path';
import {
  TrustedRootProvider,
  X509Certificate,
  X509SourceRepositoryDigestExtension,
} from '@freedomofpress/sigstore-browser';
import type { TrustedRoot } from '@freedomofpress/sigstore-browser';
import * as v from 'valibot';
import {
  fetchImageProvenance,
  verifyDeploymentImageProvenance,
  verifyImageProvenance,
} from '../src';
import { verifyImageProvenanceSource } from '../src/core/provenance';
import { ImageProvenanceStatementSchema } from '../src/schemas';
import { createDeferred } from './fixtures';

const FIXTURES = resolve(__dirname, '../../test-fixtures/provenance');
const BUNDLE = readFileSync(
  resolve(FIXTURES, 'compose-manager-launcher.bundle.json'),
  'utf8',
);
const TRUSTED_ROOT = JSON.parse(
  readFileSync(resolve(FIXTURES, 'trusted-root.json'), 'utf8'),
);
const DIGEST =
  'sha256:91fdff3cfa3543d72656b2368c7d8a0a83d95a0f1087378c897aa1537acdba56';
const POLICY = {
  repository: 'nearai/compose-manager',
  workflow: '.github/workflows/build.yml',
  ref: 'refs/heads/master',
  commit: '8e07c3583909c9ab9da94d883e87add1ae90832d',
};

describe('image provenance verification', () => {
  beforeEach(() => {
    // Pin only the network root input. Certificate, signature, SCT and Rekor
    // checks run against the real published bundle in every verification test.
    jest
      .spyOn(TrustedRootProvider.prototype, 'getTrustedRoot')
      .mockResolvedValue(TRUSTED_ROOT);
  });

  afterEach(() => jest.restoreAllMocks());

  test('fetches bundles and verifies an approved GitHub build', async () => {
    const body = { attestations: [{ bundle: JSON.parse(BUNDLE) }] };
    jest.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(body));

    const bundles = await fetchImageProvenance({
      repository: POLICY.repository,
      digest: DIGEST,
    });
    const verified = await verifyImageProvenance({
      bundles,
      digest: DIGEST,
      policy: POLICY,
    });

    expect(verified).toEqual({
      digest: DIGEST,
      ...POLICY,
      certificateIdentity:
        'https://github.com/nearai/compose-manager/.github/workflows/build.yml@refs/heads/master',
      issuer: 'https://token.actions.githubusercontent.com',
      predicateType: 'https://slsa.dev/provenance/v1',
    });
  });

  test('verifies every required image from compose, including YAML merges and tagged digests', async () => {
    const firstRequest = createDeferred<Response>();
    const secondRequest = createDeferred<Response>();
    const fetch = jest
      .spyOn(globalThis, 'fetch')
      .mockReturnValueOnce(firstRequest.promise)
      .mockReturnValueOnce(secondRequest.promise);
    const appCompose = JSON.stringify({
      docker_compose_file: `
x-image: &manager
  image: docker.io/nearaidev/compose-manager@${DIGEST}
services:
  manager:
    <<: *manager
  worker:
    image: nearaidev/compose-manager:release@${DIGEST}
  other:
    image: unrelated/image:latest
  built:
    build: .
  absent:
    image: null
`,
    });

    const verification = verifyDeploymentImageProvenance({
      appCompose,
      imagePolicies: { 'docker.io/nearaidev/compose-manager': POLICY },
      githubToken: 'test-github-token',
    });
    const startedRequests = fetch.mock.calls.length;
    firstRequest.resolve(
      Response.json({ attestations: [{ bundle: JSON.parse(BUNDLE) }] }),
    );
    secondRequest.resolve(
      Response.json({ attestations: [{ bundle: JSON.parse(BUNDLE) }] }),
    );
    await verification;

    expect(startedRequests).toBe(2);
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining(encodeURIComponent(DIGEST)),
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: 'Bearer test-github-token',
        }),
      }),
    );
  });

  test('shares an in-flight root refresh without retaining the completed request', async () => {
    const root = createDeferred<TrustedRoot>();
    const getRoot = jest
      .spyOn(TrustedRootProvider.prototype, 'getTrustedRoot')
      .mockReturnValueOnce(root.promise);
    const input = { bundles: [BUNDLE], digest: DIGEST, policy: POLICY };
    const verifications = [
      verifyImageProvenance(input),
      verifyImageProvenance(input),
    ];
    const startedRequests = getRoot.mock.calls.length;
    root.resolve(TRUSTED_ROOT);

    await expect(Promise.all(verifications)).resolves.toHaveLength(2);
    expect(startedRequests).toBe(1);

    await verifyImageProvenance(input);
    expect(getRoot).toHaveBeenCalledTimes(2);
  });

  test('shares a failed root refresh and allows a later retry', async () => {
    const root = createDeferred<TrustedRoot>();
    const getRoot = jest
      .spyOn(TrustedRootProvider.prototype, 'getTrustedRoot')
      .mockReturnValueOnce(root.promise);
    const input = { bundles: [BUNDLE], digest: DIGEST, policy: POLICY };
    const verifications = Promise.allSettled([
      verifyImageProvenance(input),
      verifyImageProvenance(input),
    ]);
    const startedRequests = getRoot.mock.calls.length;
    const cause = new Error('root request failed');
    root.reject(cause);

    for (const result of await verifications) {
      expect(result).toMatchObject({
        status: 'rejected',
        reason: {
          failure: {
            code: 'provenance.image_verification_failed',
            details: { digest: DIGEST, reasons: ['trust_root_unavailable'] },
          },
          retryable: true,
          cause,
        },
      });
    }
    expect(startedRequests).toBe(1);

    await verifyImageProvenance(input);
    expect(getRoot).toHaveBeenCalledTimes(2);
  });

  test.each(['', ':latest', '@sha256:bad', `@${DIGEST}@${DIGEST}`])(
    'rejects an unpinned reference even alongside a valid digest: %s',
    async (suffix) => {
      const fetch = jest.spyOn(globalThis, 'fetch');
      const appCompose = JSON.stringify({
        docker_compose_file: `services:
  pinned:
    image: nearaidev/compose-manager@${DIGEST}
  unpinned:
    image: nearaidev/compose-manager${suffix}
`,
      });

      await expect(
        verifyDeploymentImageProvenance({
          appCompose,
          imagePolicies: { 'nearaidev/compose-manager': POLICY },
        }),
      ).rejects.toMatchObject({
        name: 'VerificationError',
        failure: {
          code: 'provenance.deployment_images_invalid',
          details: {
            reason: 'image_not_pinned',
            imageRepository: 'nearaidev/compose-manager',
            service: 'unpinned',
          },
        },
      });
      expect(fetch).not.toHaveBeenCalled();
    },
  );

  test.each([
    ['not-json', 'invalid_app_compose'],
    ['{}', 'invalid_app_compose'],
    [
      JSON.stringify({ docker_compose_file: 'services: [' }),
      'invalid_docker_compose',
    ],
    [
      JSON.stringify({
        docker_compose_file: 'services: { manager: { image: 42 } }',
      }),
      'invalid_docker_compose',
    ],
    [JSON.stringify({ docker_compose_file: 'services: {}' }), 'image_missing'],
    [
      JSON.stringify({
        docker_compose_file: `services:\n  manager:\n    image: \${IMAGE:-nearaidev/compose-manager@${DIGEST}}`,
      }),
      'unresolved_image',
    ],
  ])(
    'reports invalid deployment configuration: %s',
    async (appCompose, reason) => {
      const fetch = jest.spyOn(globalThis, 'fetch');

      await expect(
        verifyDeploymentImageProvenance({
          appCompose,
          imagePolicies: { 'nearaidev/compose-manager': POLICY },
        }),
      ).rejects.toMatchObject({
        name: 'VerificationError',
        failure: {
          code: 'provenance.deployment_images_invalid',
          details: { reason },
        },
      });
      expect(fetch).not.toHaveBeenCalled();
    },
  );

  test('requires a nonempty image policy instead of succeeding without checks', async () => {
    await expect(
      verifyDeploymentImageProvenance({ appCompose: '{}', imagePolicies: {} }),
    ).rejects.toMatchObject({
      failure: {
        code: 'provenance.deployment_images_invalid',
        details: { reason: 'empty_policy' },
      },
    });
  });

  test('checks provenance of every matching digest, not only the first service', async () => {
    jest
      .spyOn(globalThis, 'fetch')
      .mockImplementation(async () =>
        Response.json({ attestations: [{ bundle: JSON.parse(BUNDLE) }] }),
      );
    const otherDigest = `sha256:${'ab'.repeat(32)}`;
    const appCompose = JSON.stringify({
      docker_compose_file: `services:
  first:
    image: nearaidev/compose-manager@${DIGEST}
  second:
    image: nearaidev/compose-manager@${otherDigest}
`,
    });

    await expect(
      verifyDeploymentImageProvenance({
        appCompose,
        imagePolicies: { 'nearaidev/compose-manager': POLICY },
      }),
    ).rejects.toMatchObject({
      failure: {
        code: 'provenance.image_verification_failed',
        details: { digest: otherDigest, reasons: ['digest_mismatch'] },
      },
    });
  });

  test('reports an image fetch failure as a retryable verification failure with its cause', async () => {
    jest
      .spyOn(globalThis, 'fetch')
      .mockResolvedValue(new Response(null, { status: 429 }));
    const appCompose = JSON.stringify({
      docker_compose_file: `services:\n  manager:\n    image: nearaidev/compose-manager@${DIGEST}`,
    });

    await expect(
      verifyDeploymentImageProvenance({
        appCompose,
        imagePolicies: { 'nearaidev/compose-manager': POLICY },
      }),
    ).rejects.toMatchObject({
      name: 'VerificationError',
      failure: {
        code: 'provenance.image_request_failed',
        details: {
          imageRepository: 'nearaidev/compose-manager',
          digest: DIGEST,
        },
      },
      retryable: true,
      cause: {
        name: 'ApiError',
        failure: { code: 'api.http_status', details: { status: 429 } },
      },
    });
  });

  test.each(['before', 'after'])(
    'fetches every page using the %s cursor from Link',
    async (cursorName) => {
      const url = `https://api.github.com/repos/${POLICY.repository}/attestations/${encodeURIComponent(DIGEST)}?per_page=100`;
      const cursor = 'opaque+cursor/=';
      const nextUrl = `${url}&${cursorName}=${encodeURIComponent(cursor)}`;
      const firstBundle = { page: 'first' };
      const lastBundle = { page: 'last' };
      const fetch = jest
        .spyOn(globalThis, 'fetch')
        .mockResolvedValueOnce(
          Response.json(
            { attestations: [{ bundle: firstBundle }] },
            {
              headers: {
                // Only the cursor is used, not the returned host or path.
                Link: `<${url}>; rel="prev", <https://other.example/ignored?${cursorName}=${encodeURIComponent(cursor)}>; rel="next"`,
              },
            },
          ),
        )
        .mockResolvedValueOnce(
          Response.json({
            attestations: Array.from({ length: 100 }, () => ({
              bundle: lastBundle,
            })),
          }),
        );

      const bundles = await fetchImageProvenance({
        repository: POLICY.repository,
        digest: DIGEST,
        githubToken: 'test-token',
      });

      expect(fetch.mock.calls.map(([requestedUrl]) => requestedUrl)).toEqual([
        url,
        nextUrl,
      ]);
      expect(bundles).toEqual([
        JSON.stringify(firstBundle),
        ...Array(100).fill(JSON.stringify(lastBundle)),
      ]);
    },
  );

  test('reports a repeated pagination cursor as an API error', async () => {
    const url = `https://api.github.com/repos/${POLICY.repository}/attestations/${encodeURIComponent(DIGEST)}?per_page=100`;
    const fetch = jest
      .spyOn(globalThis, 'fetch')
      .mockImplementation(async () =>
        Response.json(
          { attestations: [{ bundle: {} }] },
          { headers: { Link: `<${url}&after=same>; rel="next"` } },
        ),
      );

    await expect(
      fetchImageProvenance({ repository: POLICY.repository, digest: DIGEST }),
    ).rejects.toMatchObject({
      name: 'ApiError',
      failure: { code: 'api.invalid_response', details: { path: 'Link' } },
    });
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  test.each(['not a URL', 'https://api.github.com/attestations?per_page=100'])(
    'rejects a next-page link without a usable cursor: %s',
    async (nextUrl) => {
      jest
        .spyOn(globalThis, 'fetch')
        .mockResolvedValue(
          Response.json(
            { attestations: [{ bundle: {} }] },
            { headers: { Link: `<${nextUrl}>; rel="next"` } },
          ),
        );

      await expect(
        fetchImageProvenance({ repository: POLICY.repository, digest: DIGEST }),
      ).rejects.toMatchObject({
        name: 'ApiError',
        failure: { code: 'api.invalid_response', details: { path: 'Link' } },
      });
    },
  );

  test('accepts a later valid proof when another proof does not verify', async () => {
    const verified = await verifyImageProvenance({
      bundles: ['{}', BUNDLE],
      digest: DIGEST,
      policy: { repository: POLICY.repository, workflow: POLICY.workflow },
    });

    expect(verified.commit).toBe(POLICY.commit);
  });

  test.each([POLICY.commit, undefined])(
    'rejects a statement from another certificate source commit with pin %s',
    async (commit) => {
      // Simulate another authenticated source claim at the policy boundary.
      // DSSE, certificate-chain and transparency-log verification still run.
      jest
        .spyOn(
          X509SourceRepositoryDigestExtension.prototype,
          'sourceRepositoryDigest',
          'get',
        )
        .mockReturnValue('ab'.repeat(20));

      await expect(
        verifyImageProvenance({
          bundles: [BUNDLE],
          digest: DIGEST,
          policy: { ...POLICY, commit },
        }),
      ).rejects.toMatchObject({
        failure: { details: { reasons: ['source_mismatch'] } },
      });
    },
  );

  test('uses the legacy source SHA only when the modern extension is absent', async () => {
    jest
      .spyOn(X509Certificate.prototype, 'extSourceRepositoryDigest', 'get')
      .mockReturnValue(undefined);

    const verified = await verifyImageProvenance({
      bundles: [BUNDLE],
      digest: DIGEST,
      policy: POLICY,
    });

    expect(verified.commit).toBe(POLICY.commit);
  });

  test('rejects a missing certificate source SHA', async () => {
    jest
      .spyOn(X509Certificate.prototype, 'extSourceRepositoryDigest', 'get')
      .mockReturnValue(undefined);
    jest
      .spyOn(X509Certificate.prototype, 'extGitHubWorkflowSHA', 'get')
      .mockReturnValue(undefined);

    await expect(
      verifyImageProvenance({
        bundles: [BUNDLE],
        digest: DIGEST,
        policy: POLICY,
      }),
    ).rejects.toMatchObject({
      failure: { details: { reasons: ['source_mismatch'] } },
    });
  });

  test('does not fall back to a legacy SHA when the modern claim is malformed', async () => {
    jest
      .spyOn(
        X509SourceRepositoryDigestExtension.prototype,
        'sourceRepositoryDigest',
        'get',
      )
      .mockReturnValue('not-a-commit');

    await expect(
      verifyImageProvenance({
        bundles: [BUNDLE],
        digest: DIGEST,
        policy: POLICY,
      }),
    ).rejects.toMatchObject({
      failure: { details: { reasons: ['source_mismatch'] } },
    });
  });

  test.each([
    ['repository', { repository: 'someone/compose-manager' }],
    ['workflow', { workflow: '.github/workflows/unapproved.yml' }],
    ['ref', { ref: 'refs/heads/main' }],
    ['issuer', { issuer: 'https://unapproved.example' }],
  ])('rejects an unapproved %s', async (_label, override) => {
    await expect(
      verifyImageProvenance({
        bundles: [BUNDLE],
        digest: DIGEST,
        policy: { ...POLICY, ...override },
      }),
    ).rejects.toMatchObject({
      failure: {
        code: 'provenance.image_verification_failed',
        details: { reasons: ['untrusted_identity'] },
      },
    });
  });

  test('rejects a valid proof for a different image digest', async () => {
    await expect(
      verifyImageProvenance({
        bundles: [BUNDLE],
        digest: `sha256:${'00'.repeat(32)}`,
        policy: POLICY,
      }),
    ).rejects.toMatchObject({
      failure: { details: { reasons: ['digest_mismatch'] } },
    });
  });

  test('rejects a valid build outside the approved commit', async () => {
    await expect(
      verifyImageProvenance({
        bundles: [BUNDLE],
        digest: DIGEST,
        policy: { ...POLICY, commit: '00'.repeat(20) },
      }),
    ).rejects.toMatchObject({
      failure: { details: { reasons: ['commit_mismatch'] } },
    });
  });

  test('rejects a modified signed payload', async () => {
    const bundle = JSON.parse(BUNDLE);
    const statement = JSON.parse(
      Buffer.from(bundle.dsseEnvelope.payload, 'base64').toString('utf8'),
    );
    statement.subject[0].digest.sha256 = '00'.repeat(32);
    bundle.dsseEnvelope.payload = Buffer.from(
      JSON.stringify(statement),
    ).toString('base64');

    await expect(
      verifyImageProvenance({
        bundles: [JSON.stringify(bundle)],
        digest: `sha256:${'00'.repeat(32)}`,
        policy: POLICY,
      }),
    ).rejects.toMatchObject({
      failure: { details: { reasons: ['invalid_bundle'] } },
    });
  });

  test('rejects a bundle without transparency-log evidence', async () => {
    const bundle = JSON.parse(BUNDLE);
    bundle.verificationMaterial.tlogEntries = [];

    await expect(
      verifyImageProvenance({
        bundles: [JSON.stringify(bundle)],
        digest: DIGEST,
        policy: POLICY,
      }),
    ).rejects.toMatchObject({
      failure: { details: { reasons: ['invalid_bundle'] } },
    });
  });

  test('rejects an empty proof set', async () => {
    await expect(
      verifyImageProvenance({ bundles: [], digest: DIGEST, policy: POLICY }),
    ).rejects.toMatchObject({
      failure: { details: { reasons: ['no_attestations'] } },
    });
  });

  test('reports GitHub failures as API errors, not verification errors', async () => {
    jest
      .spyOn(globalThis, 'fetch')
      .mockResolvedValue(new Response(null, { status: 404 }));

    await expect(
      fetchImageProvenance({ repository: POLICY.repository, digest: DIGEST }),
    ).rejects.toMatchObject({
      name: 'ApiError',
      failure: { code: 'api.http_status', details: { status: 404 } },
    });
  });
});

describe('verified SLSA source interpretation', () => {
  test('selects the source dependency matching the workflow repository and ref', () => {
    const bundle = JSON.parse(BUNDLE);
    const raw = JSON.parse(
      Buffer.from(bundle.dsseEnvelope.payload, 'base64').toString('utf8'),
    );
    raw.predicate.buildDefinition.resolvedDependencies.unshift({
      uri: 'git+https://github.com/other/dependency@refs/heads/main',
    });
    const statement = v.parse(ImageProvenanceStatementSchema, raw);

    const commit = verifyImageProvenanceSource({
      statement,
      digest: DIGEST,
      policy: POLICY,
      ref: POLICY.ref,
      certificateSourceCommit: POLICY.commit,
    });

    expect(commit).toBe(POLICY.commit);
  });

  test('reads SLSA v0.2 configSource and rejects a different source repository', () => {
    const raw = {
      _type: 'https://in-toto.io/Statement/v0.1',
      subject: [{ digest: { sha256: DIGEST.slice('sha256:'.length) } }],
      predicateType: 'https://slsa.dev/provenance/v0.2',
      predicate: {
        invocation: {
          configSource: {
            uri: `git+https://github.com/${POLICY.repository}@${POLICY.ref}`,
            entryPoint: POLICY.workflow,
            digest: { sha1: POLICY.commit },
          },
        },
      },
    };
    const statement = v.parse(ImageProvenanceStatementSchema, raw);
    const commit = verifyImageProvenanceSource({
      statement,
      digest: DIGEST,
      policy: POLICY,
      ref: POLICY.ref,
      certificateSourceCommit: POLICY.commit,
    });
    expect(commit).toBe(POLICY.commit);

    expect(() =>
      verifyImageProvenanceSource({
        statement,
        digest: DIGEST,
        policy: { ...POLICY, repository: 'other/source' },
        ref: POLICY.ref,
        certificateSourceCommit: POLICY.commit,
      }),
    ).toThrow(
      expect.objectContaining({
        failure: expect.objectContaining({
          code: 'provenance.image_verification_failed',
          details: { digest: DIGEST, reasons: ['source_mismatch'] },
        }),
      }),
    );
  });
});
