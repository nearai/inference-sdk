import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { TrustedRootProvider } from '@freedomofpress/sigstore-browser';
import { verifyComposeManagerDeploymentImageProvenance } from '../src/core/compose-manager-provenance';
import { decodeDirectModelAttestations } from '../src/boundaries/direct-api';
import type { MeasuredDeployment } from '../src/types/verification';
import { sha256 } from './fixtures';

const fixtureDir = resolve(__dirname, '../../test-fixtures');
const fixture = JSON.parse(
  readFileSync(resolve(fixtureDir, 'compose-manager/deployment.json'), 'utf8'),
);
const bundle = JSON.parse(
  readFileSync(
    resolve(fixtureDir, 'provenance/compose-manager-launcher.bundle.json'),
    'utf8',
  ),
);
const root = JSON.parse(
  readFileSync(resolve(fixtureDir, 'provenance/trusted-root.json'), 'utf8'),
);
const compose = fixture.compose.replaceAll(
  'nearaidev/compose-manager-launcher',
  'nearaidev/compose-manager',
);
const policies = {
  'nearaidev/compose-manager': {
    repository: 'nearai/compose-manager',
    workflow: '.github/workflows/build.yml',
  },
};

function deployment(image?: string): MeasuredDeployment {
  return {
    appCompose: '{}',
    runtimeMeasurements: {},
    composeManager: {
      actions: [
        { ...fixture.actions[0], file_sha256: sha256(compose).toString('hex') },
        {
          action: 'compose_manager_started',
          timestamp: '2026-10-02T00:00:00Z',
          ...(image === undefined ? {} : { image }),
        },
      ],
      tcbStatus: 'UpToDate',
      advisoryIds: [],
      runtimeMeasurements: {},
    },
  };
}

afterEach(() => jest.restoreAllMocks());

test.each([undefined, 'unlisted/manager@sha256:' + 'bb'.repeat(32)])(
  'rejects a stale compose manager when the latest startup image is %s',
  async (image) => {
    const fetch = jest
      .spyOn(globalThis, 'fetch')
      .mockRejectedValue(new Error('Unexpected network request'));
    await expect(
      verifyComposeManagerDeploymentImageProvenance({
        deployment: deployment(image),
        imagePolicies: policies,
        managerImagePolicy: {
          ...policies['nearaidev/compose-manager'],
          imageRepository: 'nearaidev/compose-manager',
        },
      }),
    ).rejects.toMatchObject({
      failure: {
        code: 'provenance.compose_manager_deployment_invalid',
        details: {
          reason:
            image === undefined
              ? 'manager_image_missing'
              : 'manager_image_mismatch',
        },
      },
    });
    expect(fetch).not.toHaveBeenCalled();
  },
);

test('rejects empty policy before fetching compose', async () => {
  const fetch = jest
    .spyOn(globalThis, 'fetch')
    .mockResolvedValue(new Response('', { status: 503 }));
  await expect(
    verifyComposeManagerDeploymentImageProvenance({
      deployment: deployment(),
      imagePolicies: {},
      managerImagePolicy: {
        ...policies['nearaidev/compose-manager'],
        imageRepository: 'nearaidev/compose-manager',
      },
    }),
  ).rejects.toMatchObject({
    failure: {
      code: 'provenance.deployment_images_invalid',
      details: { reason: 'empty_policy' },
    },
  });
  expect(fetch).not.toHaveBeenCalled();
});

test('discards nested-only manager evidence before selecting the serving report', () => {
  const report = {
    model_name: 'test',
    request_nonce: '11'.repeat(32),
    signing_algo: 'ed25519',
    signing_address: '22'.repeat(32),
    signing_public_key: '44'.repeat(32),
    intel_quote: 'aa',
    event_log: [],
    info: { tcb_info: { app_compose: '{}' } },
  };
  const manager = {
    actions: [],
    actions_hash: '00'.repeat(32),
    nonce: report.request_nonce,
    quote: 'bb',
    event_log: [],
  };
  const result = decodeDirectModelAttestations({
    ...report,
    all_attestations: [{ ...report, compose_manager_attestation: manager }],
  });
  expect(result.servingAttestation.composeManagerAttestation).toBeUndefined();
});

test('a valid stale compose image cannot vouch for a different current manager digest', async () => {
  jest
    .spyOn(TrustedRootProvider.prototype, 'getTrustedRoot')
    .mockResolvedValue(root);
  const fetch = jest
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(new Response(compose))
    .mockImplementation(async () =>
      Response.json({ attestations: [{ bundle }] }),
    );
  const digest = `sha256:${'bb'.repeat(32)}`;
  await expect(
    verifyComposeManagerDeploymentImageProvenance({
      deployment: deployment(`nearaidev/compose-manager@${digest}`),
      imagePolicies: policies,
      managerImagePolicy: {
        ...policies['nearaidev/compose-manager'],
        imageRepository: 'nearaidev/compose-manager',
      },
    }),
  ).rejects.toMatchObject({
    failure: {
      code: 'provenance.image_verification_failed',
      details: { digest, reasons: ['digest_mismatch'] },
    },
  });
  expect(fetch).toHaveBeenCalledTimes(3);
});
