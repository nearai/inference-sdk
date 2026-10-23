import { Buffer } from 'node:buffer';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { TrustedRootProvider } from '@freedomofpress/sigstore-browser';
import {
  type ComposeManagerAttestation,
  fetchImageProvenance,
  verifyComposeManagerDeploymentImageProvenance,
  verifyDirectModelAttestations,
  verifyModelAttestation,
} from '../src';
import { decodeModelAttestationReport } from '../src/boundaries/cloud-api';
import type { VerifiedTdxQuote } from '../src/types/verification';
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
const MANAGER_POLICY = {
  ...POLICY,
  imageRepository: 'nearaidev/compose-manager-launcher',
};

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

async function verifyManagerFixture() {
  const report = managerReport();
  return verifyModelAttestation({
    attestation: createModelAttestation({ composeManagerAttestation: report }),
    clientBinding: { nonce },
    verifiers: {
      tdxQuote: (quote) =>
        quote === 'bb' ? managerQuote(report) : createModelQuote(),
    },
  });
}

describe('Compose Manager deployment image provenance', () => {
  afterEach(() => jest.restoreAllMocks());

  test.each([
    '',
    '/github',
    'ftp://proxy.example/github',
    'https://user:password@proxy.example/github',
    'https://proxy.example/github?token=test',
    'https://proxy.example/github?',
    'https://proxy.example/github#fragment',
    'https://proxy.example/github#',
    'https://proxy.example:99999/github',
  ])(
    'rejects an invalid proxy before requesting compose files or proofs: %s',
    async (githubProxyUrl) => {
      const verified = await verifyManagerFixture();
      const fetch = jest
        .spyOn(globalThis, 'fetch')
        .mockRejectedValue(new Error('Unexpected network request'));
      for (const operation of [
        () =>
          fetchImageProvenance({
            repository: POLICY.repository,
            digest: `sha256:${'aa'.repeat(32)}`,
            githubProxyUrl,
          }),
        () =>
          verifyComposeManagerDeploymentImageProvenance({
            deployment: verified.deployment,
            imagePolicies: IMAGE_POLICIES,
            composeManagerImagePolicy: MANAGER_POLICY,
            githubProxyUrl,
          }),
      ]) {
        await expect(operation()).rejects.toMatchObject({
          failure: {
            code: 'api.invalid_input',
            details: { field: 'githubProxyUrl' },
          },
        });
      }
      expect(fetch).not.toHaveBeenCalled();
    },
  );

  test.each([':latest', '@sha256:abcd', `:bad tag@sha256:${'aa'.repeat(32)}`])(
    'rejects an unpinned manager image before any request: %s',
    async (suffix) => {
      const verified = await verifyManagerFixture();
      const manager = verified.deployment.composeManager;
      if (manager === undefined) throw new Error('Missing manager evidence');
      const fetch = jest
        .spyOn(globalThis, 'fetch')
        .mockRejectedValue(new Error('Unexpected network request'));
      await expect(
        verifyComposeManagerDeploymentImageProvenance({
          deployment: {
            ...verified.deployment,
            composeManager: {
              ...manager,
              actions: manager.actions.map((action) =>
                action.action === 'compose_manager_started'
                  ? {
                      ...action,
                      image: MANAGER_POLICY.imageRepository + suffix,
                    }
                  : action,
              ),
            },
          },
          imagePolicies: IMAGE_POLICIES,
          composeManagerImagePolicy: MANAGER_POLICY,
          githubToken: 'test-github-token',
        }),
      ).rejects.toMatchObject({
        failure: {
          code: 'provenance.deployment_images_invalid',
          details: { reason: 'image_not_pinned' },
        },
      });
      expect(fetch).not.toHaveBeenCalled();
    },
  );

  test.each([
    undefined,
    'https://app.example/verification/github',
    'http://127.0.0.1:8080/github',
  ])(
    'verifies the signed log, compose bytes and image build with proxy %s',
    async (githubProxyUrl) => {
      const report = managerReport();
      // Wire key order is not part of the canonical action hash.
      const actions = report.actions;
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
              actions: actions.map((entry) =>
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
        .mockImplementation(async () =>
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
              composeManagerImagePolicy: MANAGER_POLICY,
              githubToken: 'test-github-token',
              githubProxyUrl,
            }),
        },
      });

      expect(verified.deploymentProvenance).toBe('verified');
      expect(verified.deployment.composeManager?.actions).toEqual(
        report.actions,
      );
      expect(fetch).toHaveBeenNthCalledWith(
        1,
        `${githubProxyUrl ?? 'https://api.github.com'}/repos/nearai/cvm-compose-files/contents/prod/model.yaml?ref=${COMMIT}`,
        expect.any(Object),
      );
      expect(fetch).toHaveBeenNthCalledWith(
        2,
        expect.stringContaining(
          `${githubProxyUrl ?? 'https://api.github.com'}/repos/${POLICY.repository}/attestations/`,
        ),
        expect.any(Object),
      );
      for (const [, options] of fetch.mock.calls) {
        const headers = new Headers(options?.headers);
        expect(headers.get('Authorization')).toBe(
          githubProxyUrl === undefined ? 'Bearer test-github-token' : null,
        );
      }
      expect(fetch).toHaveBeenCalledTimes(3);
    },
  );

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
    const verified = await verifyManagerFixture();
    const fetch = jest
      .spyOn(globalThis, 'fetch')
      .mockResolvedValue(new Response(`${COMPOSE}\n# changed`));
    await expect(
      verifyComposeManagerDeploymentImageProvenance({
        deployment: verified.deployment,
        imagePolicies: IMAGE_POLICIES,
        composeManagerImagePolicy: MANAGER_POLICY,
      }),
    ).rejects.toMatchObject({
      failure: { code: 'provenance.compose_file_hash_mismatch' },
    });
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  test('cancels an oversized streamed compose file before image proof retrieval', async () => {
    const verified = await verifyManagerFixture();
    let chunks = 0;
    let cancelled = false;
    const fetch = jest.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(
        new ReadableStream({
          pull(controller) {
            chunks++;
            controller.enqueue(new Uint8Array(1024 * 1024));
          },
          cancel() {
            cancelled = true;
          },
        }),
      ),
    );
    await expect(
      verifyComposeManagerDeploymentImageProvenance({
        deployment: verified.deployment,
        imagePolicies: IMAGE_POLICIES,
        composeManagerImagePolicy: MANAGER_POLICY,
      }),
    ).rejects.toMatchObject({
      failure: {
        code: 'provenance.compose_manager_deployment_invalid',
        details: { reason: 'compose_file_too_large' },
      },
    });
    expect(cancelled).toBe(true);
    expect(chunks).toBeLessThanOrEqual(10);
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
              composeManagerImagePolicy: MANAGER_POLICY,
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

  test.each([
    [
      'numeric-looking',
      '[{"10":"ten","2":"two","action":"compose_up","timestamp":"1"}]',
    ],
    [
      'reserved JavaScript',
      '[{"__proto__":["value"],"action":"compose_up","constructor":"value","prototype":"value","timestamp":"1"}]',
    ],
  ])(
    'retains and hashes %s action keys in lexical order',
    async (_label, actionsJson) => {
      const report = {
        ...managerReport(),
        actions: JSON.parse(actionsJson),
        actionsHash: sha256(actionsJson).toString('hex'),
      };
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
              actions: report.actions,
              actions_hash: report.actionsHash,
              nonce,
              quote: report.intelQuote,
              event_log: report.eventLog,
            },
          },
        ],
      });
      const verified = await verifyModelAttestation({
        attestation,
        clientBinding: { nonce },
        verifiers: {
          tdxQuote: (quote) =>
            quote === 'bb' ? managerQuote(report) : createModelQuote(),
        },
      });
      expect(verified.deployment.composeManager?.actions).toEqual(
        report.actions,
      );
    },
  );

  test.each([
    [['other'], 'image_missing'],
    [['model', 'missing'], 'service_missing'],
  ])(
    'rejects a service selection that cannot satisfy the image policy: %p',
    async (services, reason) => {
      const verified = await verifyManagerFixture();
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
            ...manager.actions.slice(1),
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
          composeManagerImagePolicy: MANAGER_POLICY,
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

  test.each(['missing', 'different'])(
    'rejects %s manager evidence in the serving entry',
    async (kind) => {
      const report = managerReport();
      const serving = {
        ...createModelAttestation({
          composeManagerAttestation: { ...report, intelQuote: 'invalid' },
        }),
        modelName: 'glm-5.2',
      };

      await expect(
        verifyDirectModelAttestations({
          servingAttestation: serving,
          attestations: [
            {
              ...serving,
              composeManagerAttestation:
                kind === 'missing' ? undefined : report,
            },
          ],
          clientBinding: { nonce },
          verifiers: {
            tdxQuote: (quote) =>
              quote === 'bb' ? managerQuote(report) : createModelQuote(),
          },
        }),
      ).rejects.toMatchObject({
        failure: {
          code: 'input.invalid',
          details: {
            field: 'servingAttestation',
            reason: 'not_in_attestation_set',
          },
        },
      });
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
      .mockImplementation(async () =>
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
          composeManagerImagePolicy: MANAGER_POLICY,
        }),
    });

    expect(checked.sort()).toEqual(['aa', 'bb', 'cc']);
    expect(verified.servingAttestation).toBe(verified.attestations[1]);
    expect(verified.attestations[0].deploymentProvenance).toBe('not_checked');
    expect(verified.servingAttestation.deploymentProvenance).toBe('verified');
  });

  test('selects the requested compose project and the latest manager-start image', async () => {
    const verified = await verifyManagerFixture();
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
      imagePolicies: IMAGE_POLICIES,
      composeManagerImagePolicy: {
        ...POLICY,
        imageRepository: 'nearaidev/compose-manager',
      },
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
