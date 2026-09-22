import { Buffer } from 'node:buffer';
import {
  verifyDirectModelAttestation,
  verifyDirectModelAttestations,
} from '../src/core/attestation-direct';
import type { DirectModelAttestation } from '../src/types/direct-api';
import type {
  MeasuredDeployment,
  VerifiedTdxQuote,
} from '../src/types/verification';
import {
  createDeferred,
  createModelAttestation,
  createModelQuote,
  nonce,
  sha256,
  tlsFingerprint,
} from './fixtures';

function createDirectAttestation(
  overrides: Partial<DirectModelAttestation> = {},
): DirectModelAttestation {
  return {
    ...createModelAttestation(),
    modelName: 'glm-5.2',
    instanceId: 'instance-a',
    ...overrides,
  };
}

function quoteFor(attestation: DirectModelAttestation): VerifiedTdxQuote {
  const signingAddress = Buffer.from(
    attestation.signer.signingAddress.replace(/^0x/i, ''),
    'hex',
  );
  let signerBinding: Buffer;
  if (attestation.spkiFingerprint === undefined) {
    signerBinding = Buffer.alloc(32);
    signingAddress.copy(signerBinding);
  } else {
    signerBinding = sha256(
      Buffer.concat([
        signingAddress,
        Buffer.from(attestation.spkiFingerprint, 'hex'),
      ]),
    );
  }
  return createModelQuote({
    reportData: Buffer.concat([signerBinding, Buffer.from(nonce, 'hex')]),
    mrConfigId: Buffer.concat([
      Buffer.from([0x01]),
      sha256(attestation.appCompose),
      Buffer.alloc(15),
    ]),
  });
}

describe('direct model attestation verification', () => {
  test('authenticates a model fingerprint without claiming a live TLS connection', async () => {
    const signingPublicKey = '66'.repeat(32);
    const attestation = createDirectAttestation({
      signer: { signingAlgo: 'ed25519', signingAddress: signingPublicKey },
      signingPublicKey,
      spkiFingerprint: tlsFingerprint,
      nvidiaPayload: JSON.stringify({ nonce }),
    });
    const gpuPayloads: string[] = [];

    const verified = await verifyDirectModelAttestation({
      attestation,
      clientBinding: { nonce },
      policy: { gpuEvidence: 'required' },
      verifiers: {
        tdxQuote: () => quoteFor(attestation),
        gpuEvidence: (payload) => {
          gpuPayloads.push(payload);
        },
      },
    });

    expect(verified).toMatchObject({
      modelName: 'glm-5.2',
      instanceId: 'instance-a',
      spkiFingerprint: tlsFingerprint,
      signingPublicKey,
      gpuEvidence: 'verified',
    });
    expect(gpuPayloads).toEqual([attestation.nvidiaPayload]);
  });

  test.each([
    [
      { nvidiaPayload: JSON.stringify({ nonce: '44'.repeat(32) }) },
      'binding.nonce_mismatch',
    ],
    [
      { signingPublicKey: '77'.repeat(32) },
      'binding.model_public_key_mismatch',
    ],
  ])('retains model evidence checks for %p', async (overrides, code) => {
    const attestation = createDirectAttestation({
      signer: { signingAlgo: 'ed25519', signingAddress: '66'.repeat(32) },
      ...overrides,
    });

    await expect(
      verifyDirectModelAttestation({
        attestation,
        clientBinding: { nonce },
        verifiers: { tdxQuote: () => quoteFor(attestation) },
      }),
    ).rejects.toMatchObject({ failure: { code } });
  });

  test('rejects a fingerprint not authenticated by the quote', async () => {
    const original = createDirectAttestation({
      spkiFingerprint: tlsFingerprint,
    });
    const attestation = { ...original, spkiFingerprint: '44'.repeat(32) };

    await expect(
      verifyDirectModelAttestation({
        attestation,
        clientBinding: { nonce },
        verifiers: { tdxQuote: () => quoteFor(original) },
      }),
    ).rejects.toMatchObject({
      failure: {
        code: 'binding.report_data_mismatch',
        details: { source: 'signerTlsBinding' },
      },
    });
  });

  test.each([false, true])(
    'requires the quote layout to match fingerprint presence: %s',
    async (includeFingerprint) => {
      const plain = createDirectAttestation();
      const withTls = { ...plain, spkiFingerprint: tlsFingerprint };

      await expect(
        verifyDirectModelAttestation({
          attestation: includeFingerprint ? withTls : plain,
          clientBinding: { nonce },
          verifiers: {
            tdxQuote: () => quoteFor(includeFingerprint ? plain : withTls),
          },
        }),
      ).rejects.toMatchObject({
        failure: { code: 'binding.report_data_mismatch' },
      });
    },
  );
});

describe('direct model attestations verification', () => {
  test('verifies reports concurrently while preserving their order and serving identity', async () => {
    const first = createDirectAttestation({ spkiFingerprint: tlsFingerprint });
    const second = createDirectAttestation({
      instanceId: 'instance-b',
      intelQuote: 'bb',
      appCompose: '{"services":{"model":"different-image"}}',
      spkiFingerprint: '44'.repeat(32),
    });
    const checkedDeployments: MeasuredDeployment[] = [];
    const firstQuote = createDeferred<VerifiedTdxQuote>();
    const secondQuote = createDeferred<VerifiedTdxQuote>();
    const secondDeploymentChecked = createDeferred<void>();
    const startedQuotes: string[] = [];

    const verification = verifyDirectModelAttestations({
      servingAttestation: first,
      attestations: [first, second],
      clientBinding: { nonce, spkiFingerprint: tlsFingerprint },
      verifiers: {
        tdxQuote: (quote) => {
          startedQuotes.push(quote);
          return quote === first.intelQuote
            ? firstQuote.promise
            : secondQuote.promise;
        },
        deployment: (deployment) => {
          if (deployment.provider !== 'near')
            throw new Error('Expected NEAR deployment');
          checkedDeployments.push(deployment);
          if (deployment.appCompose === second.appCompose) {
            secondDeploymentChecked.resolve();
          }
        },
      },
    });

    expect(startedQuotes).toEqual([first.intelQuote, second.intelQuote]);
    secondQuote.resolve(quoteFor(second));
    await secondDeploymentChecked.promise;
    expect(checkedDeployments.map(({ appCompose }) => appCompose)).toEqual([
      second.appCompose,
    ]);
    firstQuote.resolve(quoteFor(first));
    const verified = await verification;

    expect(verified.attestations.map(({ instanceId }) => instanceId)).toEqual([
      'instance-a',
      'instance-b',
    ]);
    expect(checkedDeployments).toHaveLength(2);
    expect(checkedDeployments.map(({ appCompose }) => appCompose)).toEqual(
      expect.arrayContaining([first.appCompose, second.appCompose]),
    );
    expect(verified.servingAttestation).toBe(verified.attestations[0]);
    expect(verified.tlsBinding).toEqual({
      kind: 'attested',
      spkiFingerprint: tlsFingerprint,
    });
    expect(verified.spkiFingerprints).toEqual([
      tlsFingerprint,
      '44'.repeat(32),
    ]);
  });

  test('rejects every supplied attestation when another instance fails deployment verification', async () => {
    const first = createDirectAttestation();
    const second = createDirectAttestation({
      instanceId: 'instance-b',
      intelQuote: 'bb',
    });
    const tampered = { ...second, appCompose: '{"tampered":true}' };

    await expect(
      verifyDirectModelAttestations({
        servingAttestation: first,
        attestations: [first, tampered],
        clientBinding: { nonce },
        verifiers: {
          tdxQuote: (quote) =>
            quoteFor(quote === first.intelQuote ? first : second),
        },
      }),
    ).rejects.toMatchObject({
      failure: { code: 'measurement.app_compose_mrconfigid_mismatch' },
    });
  });

  test.each([
    [undefined, 'binding.spki_fingerprint_required'],
    ['44'.repeat(32), 'binding.spki_fingerprint_mismatch'],
  ])(
    'rejects a serving attestation without a matching peer observation: %s',
    async (spkiFingerprint, code) => {
      const attestation = createDirectAttestation({
        spkiFingerprint: tlsFingerprint,
      });

      await expect(
        verifyDirectModelAttestations({
          servingAttestation: attestation,
          attestations: [attestation],
          clientBinding: { nonce, spkiFingerprint },
          verifiers: { tdxQuote: () => quoteFor(attestation) },
        }),
      ).rejects.toMatchObject({ failure: { code } });
    },
  );

  test('verifies signer-and-nonce evidence without a TLS binding', async () => {
    const attestation = createDirectAttestation();
    const verified = await verifyDirectModelAttestations({
      servingAttestation: attestation,
      attestations: [attestation],
      clientBinding: { nonce },
      verifiers: { tdxQuote: () => quoteFor(attestation) },
    });

    expect(verified.tlsBinding).toEqual({ kind: 'none' });
    expect(verified.spkiFingerprints).toEqual([]);
  });

  test('requires the serving attestation to be an array entry', async () => {
    const instance = createDirectAttestation();
    const root = { ...instance, appCompose: '{"unverified-root":true}' };

    await expect(
      verifyDirectModelAttestations({
        servingAttestation: root,
        attestations: [instance],
        clientBinding: { nonce },
        verifiers: { tdxQuote: () => quoteFor(instance) },
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
  });

  test('requires at least one model attestation', async () => {
    await expect(
      verifyDirectModelAttestations({
        servingAttestation: createDirectAttestation(),
        attestations: [],
        clientBinding: { nonce },
      }),
    ).rejects.toMatchObject({
      failure: { code: 'policy.model_attestation_required' },
    });
  });
});
