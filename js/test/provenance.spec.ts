import { readFileSync } from 'node:fs';
import { Buffer } from 'node:buffer';
import { resolve } from 'node:path';
import { SigstoreVerifier } from '@freedomofpress/sigstore-browser';
import { fetchImageProvenance, verifyImageProvenance } from '../src';

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
      .spyOn(SigstoreVerifier.prototype, 'loadSigstoreRootWithTUF')
      .mockImplementation(function (this: SigstoreVerifier) {
        return this.loadSigstoreRoot(TRUSTED_ROOT);
      });
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

  test('accepts a later valid proof when another proof does not verify', async () => {
    const verified = await verifyImageProvenance({
      bundles: ['{}', BUNDLE],
      digest: DIGEST,
      policy: { repository: POLICY.repository, workflow: POLICY.workflow },
    });

    expect(verified.commit).toBe(POLICY.commit);
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
