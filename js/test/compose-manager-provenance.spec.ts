import { Buffer } from 'node:buffer';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { TrustedRootProvider } from '@freedomofpress/sigstore-browser';
import {
  verifyComposeManagerDeploymentImageProvenance,
  verifyModelAttestation,
  verifyDirectModelAttestations,
  type ComposeManagerAttestation,
} from '../src';
import type { VerifiedTdxQuote } from '../src/types/verification';
import { decodeModelAttestationReport } from '../src/boundaries/cloud-api';
import {
  appCompose,
  createModelAttestation,
  createModelQuote,
  nonce,
  sha256,
} from './fixtures';

const FIXTURES = resolve(__dirname, '../../test-fixtures/provenance');
const BUNDLE = JSON.parse(
  readFileSync(
    resolve(FIXTURES, 'compose-manager-launcher.bundle.json'),
    'utf8',
  ),
);
const TRUSTED_ROOT = JSON.parse(
  readFileSync(resolve(FIXTURES, 'trusted-root.json'), 'utf8'),
);
const FIXTURE = JSON.parse(
  readFileSync(resolve(FIXTURES, '../compose-manager/deployment.json'), 'utf8'),
);
const COMMIT = '12'.repeat(20);
const POLICY = {
  repository: 'nearai/compose-manager',
  workflow: '.github/workflows/build.yml',
};
const IMAGE_POLICIES = { 'nearaidev/compose-manager-launcher': POLICY };
const COMPOSE = FIXTURE.compose;

function managerReport(): ComposeManagerAttestation {
  return {
    actions: FIXTURE.actions,
    actionsHash: FIXTURE.actions_hash,
    nonce,
    intelQuote: 'bb',
    eventLog: createModelAttestation().eventLog,
  };
}

function managerQuote(report: ComposeManagerAttestation): VerifiedTdxQuote {
  return createModelQuote({
    reportData: Buffer.concat([
      Buffer.from(report.actionsHash, 'hex'),
      Buffer.from(nonce, 'hex'),
    ]),
  });
}

describe('Compose Manager deployment image provenance', () => {
  afterEach(() => jest.restoreAllMocks());

  test('verifies the signed log, recorded compose bytes and image build through the model callback', async () => {
    const report = managerReport();
    // Wire key order is not part of the canonical action hash.
    const [action] = report.actions;
    const [attestation] = decodeModelAttestationReport({
      model_attestations: [
        {
          signing_algo: 'ecdsa',
          signing_address: createModelAttestation().signer.signingAddress,
          request_nonce: nonce,
          intel_quote: 'aa',
          event_log: createModelAttestation().eventLog,
          info: { tcb_info: { app_compose: appCompose } },
          compose_manager_attestation: {
            actions: [{ ...action, timestamp: action.timestamp }].map((entry) =>
              Object.fromEntries(Object.entries(entry).reverse()),
            ),
            actions_hash: report.actionsHash,
            nonce,
            quote: report.intelQuote,
            event_log: report.eventLog,
          },
        },
      ],
    });
    jest
      .spyOn(TrustedRootProvider.prototype, 'getTrustedRoot')
      .mockResolvedValue(TRUSTED_ROOT);
    const fetch = jest
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(COMPOSE))
      .mockResolvedValueOnce(
        Response.json({ attestations: [{ bundle: BUNDLE }] }),
      );

    const verified = await verifyModelAttestation({
      attestation,
      clientBinding: { nonce },
      verifiers: {
        tdxQuote: async (quote) =>
          quote === 'bb' ? managerQuote(report) : createModelQuote(),
        deployment: (deployment) =>
          verifyComposeManagerDeploymentImageProvenance({
            deployment,
            imagePolicies: IMAGE_POLICIES,
          }),
      },
    });

    expect(verified.deploymentProvenance).toBe('verified');
    expect(verified.deployment.composeManager?.actions).toEqual(report.actions);
    expect(fetch).toHaveBeenNthCalledWith(
      1,
      `https://api.github.com/repos/nearai/cvm-compose-files/contents/prod/model.yaml?ref=${COMMIT}`,
      expect.any(Object),
    );
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  test.each([
    [
      'changed action',
      { actions: [{ ...managerReport().actions[0], file: 'other.yaml' }] },
      {},
      'binding.compose_manager_actions_mismatch',
    ],
    [
      'replayed nonce',
      { nonce: 'ff'.repeat(32) },
      {},
      'binding.nonce_mismatch',
    ],
    [
      'unbound action hash',
      {},
      { reportData: Buffer.from('00'.repeat(32) + nonce, 'hex') },
      'binding.compose_manager_actions_mismatch',
    ],
    [
      'different measured configuration',
      {},
      { mrConfigId: Buffer.from(`01${'00'.repeat(47)}`, 'hex') },
      'measurement.app_compose_mrconfigid_mismatch',
    ],
    ['debug manager', {}, { debugEnabled: true }, 'policy.debug_enabled'],
  ] satisfies [
    string,
    Partial<ComposeManagerAttestation>,
    Partial<VerifiedTdxQuote>,
    string,
  ][])(
    'rejects a %s before invoking deployment policy',
    async (_label, reportOverride, quoteOverride, code) => {
      const original = managerReport();
      const attestation = createModelAttestation({
        composeManagerAttestation: { ...original, ...reportOverride },
      });
      const deployment = jest.fn();
      await expect(
        verifyModelAttestation({
          attestation,
          clientBinding: { nonce },
          verifiers: {
            tdxQuote: async (quote) =>
              quote === 'bb'
                ? { ...managerQuote(original), ...quoteOverride }
                : createModelQuote(),
            deployment,
          },
        }),
      ).rejects.toMatchObject({ failure: { code } });
      expect(deployment).not.toHaveBeenCalled();
    },
  );

  test('rejects downloaded compose bytes with the wrong hash before fetching image proofs', async () => {
    const report = managerReport();
    const verified = await verifyModelAttestation({
      attestation: createModelAttestation({
        composeManagerAttestation: report,
      }),
      clientBinding: { nonce },
      verifiers: {
        tdxQuote: async (quote) =>
          quote === 'bb' ? managerQuote(report) : createModelQuote(),
      },
    });
    const fetch = jest
      .spyOn(globalThis, 'fetch')
      .mockResolvedValue(new Response(`${COMPOSE}\n# changed`));
    await expect(
      verifyComposeManagerDeploymentImageProvenance({
        deployment: verified.deployment,
        imagePolicies: IMAGE_POLICIES,
      }),
    ).rejects.toMatchObject({
      failure: { code: 'provenance.compose_file_hash_mismatch' },
    });
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  test('requires Compose Manager evidence when this policy is selected', async () => {
    await expect(
      verifyModelAttestation({
        attestation: createModelAttestation(),
        clientBinding: { nonce },
        verifiers: {
          tdxQuote: async () => createModelQuote(),
          deployment: (deployment) =>
            verifyComposeManagerDeploymentImageProvenance({
              deployment,
              imagePolicies: IMAGE_POLICIES,
            }),
        },
      }),
    ).rejects.toMatchObject({
      failure: {
        code: 'provenance.compose_manager_deployment_invalid',
        details: { reason: 'attestation_missing' },
      },
    });
  });

  test('hashes numeric-looking action keys in lexical order', async () => {
    const actionsJson =
      '[{"10":"ten","2":"two","action":"compose_up","timestamp":"1"}]';
    const report = {
      ...managerReport(),
      actions: [
        { '2': 'two', '10': 'ten', action: 'compose_up', timestamp: '1' },
      ],
      actionsHash: sha256(actionsJson).toString('hex'),
    };
    const verified = await verifyModelAttestation({
      attestation: createModelAttestation({
        composeManagerAttestation: report,
      }),
      clientBinding: { nonce },
      verifiers: {
        tdxQuote: (quote) =>
          quote === 'bb' ? managerQuote(report) : createModelQuote(),
      },
    });
    expect(verified.deployment.composeManager?.actions).toEqual(report.actions);
  });

  test.each([
    [['other'], 'image_missing'],
    [['model', 'missing'], 'service_missing'],
  ])(
    'rejects a service selection that cannot satisfy the image policy: %p',
    async (services, reason) => {
      const report = managerReport();
      const verified = await verifyModelAttestation({
        attestation: createModelAttestation({
          composeManagerAttestation: report,
        }),
        clientBinding: { nonce },
        verifiers: {
          tdxQuote: (quote) =>
            quote === 'bb' ? managerQuote(report) : createModelQuote(),
        },
      });
      const compose = `${COMPOSE}  other:\n    image: other/model:latest\n`;
      const manager = verified.deployment.composeManager;
      if (manager === undefined)
        throw new Error('Expected verified manager evidence');
      const deployment = {
        ...verified.deployment,
        composeManager: {
          ...manager,
          actions: [
            {
              ...manager.actions[0],
              services,
              file_sha256: sha256(compose).toString('hex'),
            },
          ],
        },
      };
      const fetch = jest
        .spyOn(globalThis, 'fetch')
        .mockResolvedValue(new Response(compose));
      await expect(
        verifyComposeManagerDeploymentImageProvenance({
          deployment,
          imagePolicies: IMAGE_POLICIES,
        }),
      ).rejects.toMatchObject({
        failure: {
          code: 'provenance.deployment_images_invalid',
          details: { reason },
        },
      });
      expect(fetch).toHaveBeenCalledTimes(1);
    },
  );

  test('applies manager provenance only to the serving report while verifying the whole set', async () => {
    const report = managerReport();
    const serving = {
      ...createModelAttestation({ composeManagerAttestation: report }),
      modelName: 'glm-5.2',
    };
    const sibling = {
      ...createModelAttestation({ intelQuote: 'cc' }),
      modelName: 'glm-5.2',
    };
    const checked: string[] = [];
    jest
      .spyOn(TrustedRootProvider.prototype, 'getTrustedRoot')
      .mockResolvedValue(TRUSTED_ROOT);
    jest
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(COMPOSE))
      .mockResolvedValueOnce(
        Response.json({ attestations: [{ bundle: BUNDLE }] }),
      );

    const verified = await verifyDirectModelAttestations({
      servingAttestation: serving,
      attestations: [sibling, serving],
      clientBinding: { nonce },
      verifiers: {
        tdxQuote: (quote) => {
          checked.push(quote);
          return quote === 'bb' ? managerQuote(report) : createModelQuote();
        },
      },
      servingDeployment: (deployment) =>
        verifyComposeManagerDeploymentImageProvenance({
          deployment,
          imagePolicies: IMAGE_POLICIES,
        }),
    });

    expect(checked.sort()).toEqual(['aa', 'bb', 'cc']);
    expect(verified.servingAttestation).toBe(verified.attestations[1]);
    expect(verified.attestations[0].deploymentProvenance).toBe('not_checked');
    expect(verified.servingAttestation.deploymentProvenance).toBe('verified');
  });

  test('selects the requested compose project and the latest manager-start image', async () => {
    const report = managerReport();
    const verified = await verifyModelAttestation({
      attestation: createModelAttestation({
        composeManagerAttestation: report,
      }),
      clientBinding: { nonce },
      verifiers: {
        tdxQuote: async (quote) =>
          quote === 'bb' ? managerQuote(report) : createModelQuote(),
      },
    });
    const manager = verified.deployment.composeManager;
    if (manager === undefined)
      throw new Error('Expected verified manager evidence');
    // Exercise selection with an already authenticated deployment, independently
    // of the quote/hash checks covered above.
    const deployment = {
      ...verified.deployment,
      composeManager: {
        ...manager,
        actions: [
          {
            action: 'compose_manager_started',
            timestamp: '1',
            image: 'nearaidev/compose-manager:old',
          },
          ...manager.actions,
          { ...manager.actions[0], file: 'prod/other.yaml' },
          {
            action: 'compose_manager_started',
            timestamp: '2',
            image:
              'nearaidev/compose-manager@sha256:91fdff3cfa3543d72656b2368c7d8a0a83d95a0f1087378c897aa1537acdba56',
          },
        ],
      },
    };
    jest
      .spyOn(TrustedRootProvider.prototype, 'getTrustedRoot')
      .mockResolvedValue(TRUSTED_ROOT);
    const fetch = jest
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(COMPOSE))
      .mockImplementation(async () =>
        Response.json({ attestations: [{ bundle: BUNDLE }] }),
      );
    await verifyComposeManagerDeploymentImageProvenance({
      deployment,
      composeFile: 'prod/model.yaml',
      imagePolicies: { ...IMAGE_POLICIES, 'nearaidev/compose-manager': POLICY },
    });
    expect(fetch.mock.calls[0][0]).toContain('/contents/prod/model.yaml?');
    expect(fetch).toHaveBeenCalledTimes(3);
  });

  test('rejects malformed manager evidence at the API boundary', () => {
    const decode = () =>
      decodeModelAttestationReport({
        model_attestations: [
          {
            request_nonce: nonce,
            signing_algo: 'ecdsa',
            signing_address: createModelAttestation().signer.signingAddress,
            intel_quote: 'aa',
            event_log: [],
            info: { tcb_info: { app_compose: appCompose } },
            compose_manager_attestation: { actions: 'not an array' },
          },
        ],
      });
    expect(decode).toThrow(
      expect.objectContaining({
        name: 'ApiError',
        failure: expect.objectContaining({ code: 'api.invalid_response' }),
      }),
    );
  });
});
