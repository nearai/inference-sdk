import { Buffer } from 'node:buffer';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { verifyChutesModelAttestation as verifyChutesEvidence } from '../src/core/attestation-chutes';
import type { VerifyChutesModelAttestationParams } from '../src/types/attestation-chutes';
import type { TdxQuoteVerificationResult } from '../src/types/verification';
import { CHUTES_MEASUREMENT_BASELINES } from '../src/utils/chutes-measurements';
import { createDeferred } from './fixtures';
import {
  CHUTES_TEST_CERTIFICATE as CERTIFICATE,
  CHUTES_TEST_SPKI_FINGERPRINT as SPKI_FINGERPRINT,
  CHUTES_TEST_NONCE as NONCE,
  CHUTES_TEST_PUBLIC_KEY as PUBLIC_KEY,
  CHUTES_TEST_BASELINE as BASELINE,
  createChutesAttestation as createAttestation,
  createChutesQuote as createQuote,
} from './chutes-fixtures';

// Every unit test is offline. The separate NRAS tests below mock fetch and
// deliberately invoke the default GPU verifier instead.
function verifyChutesModelAttestation(
  params: VerifyChutesModelAttestationParams,
) {
  return verifyChutesEvidence({
    ...params,
    verifiers: { gpuEvidence: async () => {}, ...params.verifiers },
  });
}

function sha256(value: string | Uint8Array): Buffer {
  return createHash('sha256').update(value).digest();
}

describe('Chutes model attestation', () => {
  beforeEach(() => {
    jest
      .spyOn(globalThis, 'fetch')
      .mockRejectedValue(new Error('Unexpected network request'));
  });
  afterEach(() => jest.restoreAllMocks());

  test('starts GPU verification while quote verification is pending', async () => {
    const quoteStarted = createDeferred<void>();
    const quoteFinished = createDeferred<TdxQuoteVerificationResult>();
    await expect(
      verifyChutesModelAttestation({
        attestation: createAttestation(),
        clientBinding: { nonce: NONCE },
        verifiers: {
          tdxQuote: async () => {
            quoteStarted.resolve();
            return quoteFinished.promise;
          },
          gpuEvidence: async () => {
            await quoteStarted.promise;
            quoteFinished.resolve(createQuote());
          },
        },
      }),
    ).resolves.toMatchObject({ gpuEvidence: 'verified' });
  });

  test('authenticates the original key, certificate SPKI and all eight GPU entries', async () => {
    const gpuVerifier = jest.fn(async (_payload: string) => {});
    const result = await verifyChutesModelAttestation({
      attestation: createAttestation(),
      clientBinding: { nonce: NONCE },
      verifiers: {
        tdxQuote: async () => createQuote(),
        gpuEvidence: gpuVerifier,
      },
    });
    expect(result).toEqual({
      provider: 'chutes',
      tcbStatus: 'UpToDate',
      advisoryIds: [],
      publicKey: PUBLIC_KEY,
      spkiFingerprint: SPKI_FINGERPRINT,
      gpuEvidence: 'verified',
      deployment: {
        mrTd: BASELINE.mrTd,
        rtMr0: BASELINE.rtMr0,
        rtMr1: BASELINE.rtMr1,
        rtMr2: BASELINE.rtMr2,
        rtMr3: BASELINE.rtMr3,
        baseline: { name: BASELINE.name, version: BASELINE.version },
      },
      deploymentProvenance: 'verified',
    });
    expect(gpuVerifier).toHaveBeenCalledTimes(1);
    const submitted = JSON.parse(gpuVerifier.mock.calls[0][0]);
    expect(submitted).toEqual({
      nonce: sha256(NONCE + PUBLIC_KEY).toString('hex'),
      arch: 'HOPPER',
      evidence_list: createAttestation().gpuEvidence.map(
        ({ certificate, evidence }) => ({
          certificate,
          evidence,
        }),
      ),
    });
    expect(submitted.nonce).not.toBe(
      sha256(
        Buffer.concat([
          Buffer.from(NONCE, 'hex'),
          Buffer.from(PUBLIC_KEY, 'base64'),
        ]),
      ).toString('hex'),
    );
    expect(result).not.toHaveProperty('signer');
  });

  test('rejects a changed echoed nonce before invoking the quote verifier', async () => {
    const verifier = jest.fn(async () => createQuote());
    await expect(
      verifyChutesModelAttestation({
        attestation: createAttestation({ nonce: NONCE.toLowerCase() }),
        clientBinding: { nonce: NONCE },
        verifiers: { tdxQuote: verifier },
      }),
    ).rejects.toMatchObject({
      failure: { code: 'binding.nonce_mismatch' },
    });
    expect(verifier).not.toHaveBeenCalled();
  });

  test('rejects substituting another well-formed ML-KEM public key', async () => {
    await expect(
      verifyChutesModelAttestation({
        attestation: createAttestation({
          publicKey: Buffer.alloc(1184, 43).toString('base64'),
        }),
        clientBinding: { nonce: NONCE },
        verifiers: { tdxQuote: async () => createQuote() },
      }),
    ).rejects.toMatchObject({
      failure: {
        code: 'binding.report_data_mismatch',
        details: { source: 'chutesFreshness' },
      },
    });
  });

  test('rejects a stale quote when the report echo matches a new client nonce', async () => {
    const freshNonce = 'ef'.repeat(32);
    await expect(
      verifyChutesModelAttestation({
        attestation: createAttestation({ nonce: freshNonce }),
        clientBinding: { nonce: freshNonce },
        verifiers: { tdxQuote: async () => createQuote() },
      }),
    ).rejects.toMatchObject({
      failure: {
        code: 'binding.report_data_mismatch',
        details: { source: 'chutesFreshness' },
      },
    });
  });

  test('requires the DER SPKI hash, not the whole certificate hash', async () => {
    await expect(
      verifyChutesModelAttestation({
        attestation: createAttestation(),
        clientBinding: { nonce: NONCE },
        verifiers: {
          tdxQuote: async () =>
            createQuote({
              overrides: {
                reportData: Buffer.concat([
                  sha256(NONCE + PUBLIC_KEY),
                  sha256(Buffer.from(CERTIFICATE, 'base64')),
                ]),
              },
            }),
        },
      }),
    ).rejects.toMatchObject({
      failure: {
        code: 'binding.report_data_mismatch',
        details: { source: 'chutesCertificate' },
      },
    });
  });

  test('rejects report data with trailing bytes after the two bindings', async () => {
    const reportData = Buffer.concat([
      createQuote().reportData,
      Buffer.alloc(1),
    ]);
    await expect(
      verifyChutesModelAttestation({
        attestation: createAttestation(),
        clientBinding: { nonce: NONCE },
        verifiers: {
          tdxQuote: async () => createQuote({ overrides: { reportData } }),
        },
      }),
    ).rejects.toMatchObject({
      failure: {
        code: 'binding.report_data_invalid',
        details: { expectedBytes: 64, actualBytes: 65 },
      },
    });
  });

  test.each(['mrTd', 'rtMr0', 'rtMr1', 'rtMr2', 'rtMr3'] as const)(
    'rejects an unapproved %s register',
    async (register) => {
      await expect(
        verifyChutesModelAttestation({
          attestation: createAttestation(),
          clientBinding: { nonce: NONCE },
          verifiers: {
            tdxQuote: async () =>
              createQuote({ overrides: { [register]: Buffer.alloc(48) } }),
          },
        }),
      ).rejects.toMatchObject({
        failure: { code: 'measurement.chutes_baseline_mismatch' },
      });
    },
  );

  test('does not combine registers from different accepted baseline versions', async () => {
    await expect(
      verifyChutesModelAttestation({
        attestation: createAttestation(),
        clientBinding: { nonce: NONCE },
        verifiers: {
          tdxQuote: async () =>
            createQuote({
              overrides: {
                mrTd: Buffer.from(CHUTES_MEASUREMENT_BASELINES[9].mrTd, 'hex'),
                rtMr0: Buffer.from(
                  CHUTES_MEASUREMENT_BASELINES[9].rtMr0,
                  'hex',
                ),
              },
            }),
        },
      }),
    ).rejects.toMatchObject({
      failure: { code: 'measurement.chutes_baseline_mismatch' },
    });
  });

  test('accepts each of the 29 pinned Gateway baselines', async () => {
    expect(CHUTES_MEASUREMENT_BASELINES).toHaveLength(29);
    for (const baseline of CHUTES_MEASUREMENT_BASELINES) {
      const result = await verifyChutesModelAttestation({
        attestation: createAttestation(),
        clientBinding: { nonce: NONCE },
        verifiers: {
          tdxQuote: async () => createQuote({ baseline }),
          gpuEvidence: async () => {},
        },
      });
      // Two published names can intentionally share the same complete tuple.
      expect(result.deployment.mrTd).toBe(baseline.mrTd);
      expect(result.deployment.rtMr0).toBe(baseline.rtMr0);
      expect(result.deployment.baseline.version).toBe(baseline.version);
    }
  });

  test('supports caller-trusted baselines and additional deployment policy', async () => {
    const baseline = {
      ...BASELINE,
      name: 'caller-reviewed',
      mrTd: 'ab'.repeat(48),
    };
    const deployment = jest.fn(async () => {});
    const result = await verifyChutesModelAttestation({
      attestation: createAttestation(),
      clientBinding: { nonce: NONCE },
      policy: { baselines: [baseline] },
      verifiers: {
        tdxQuote: async () => createQuote({ baseline }),
        gpuEvidence: async () => {},
        deployment,
      },
    });
    expect(result.deployment.baseline.name).toBe('caller-reviewed');
    expect(deployment).toHaveBeenCalledWith(result.deployment);
  });

  test('rejects an empty baseline policy before quote verification', async () => {
    const verifier = jest.fn(async () => createQuote());
    await expect(
      verifyChutesModelAttestation({
        attestation: createAttestation(),
        clientBinding: { nonce: NONCE },
        policy: { baselines: [] },
        verifiers: { tdxQuote: verifier },
      }),
    ).rejects.toMatchObject({
      failure: { code: 'measurement.chutes_baseline_mismatch' },
    });
    expect(verifier).not.toHaveBeenCalled();
  });

  test('requires the extended TDX registers from a custom verifier', async () => {
    const { mrTd: _mrTd, ...quote } = createQuote();
    await expect(
      verifyChutesModelAttestation({
        attestation: createAttestation(),
        clientBinding: { nonce: NONCE },
        verifiers: { tdxQuote: async () => quote },
      }),
    ).rejects.toMatchObject({
      failure: {
        code: 'quote.invalid_result',
        details: { path: 'quote.mrTd' },
      },
    });
  });

  test('defaults to UpToDate only and still rejects debug quotes', async () => {
    for (const [quote, code] of [
      [
        createQuote({ overrides: { tcbStatus: 'OutOfDate' } }),
        'policy.tcb_status_not_allowed',
      ],
      [
        createQuote({ overrides: { debugEnabled: true } }),
        'policy.debug_enabled',
      ],
    ] as const) {
      await expect(
        verifyChutesModelAttestation({
          attestation: createAttestation(),
          clientBinding: { nonce: NONCE },
          verifiers: { tdxQuote: async () => quote },
        }),
      ).rejects.toMatchObject({ failure: { code } });
    }
    await expect(
      verifyChutesModelAttestation({
        attestation: createAttestation(),
        clientBinding: { nonce: NONCE },
        policy: { acceptedTcbStatuses: ['OutOfDate'] },
        verifiers: {
          tdxQuote: async () =>
            createQuote({ overrides: { tcbStatus: 'OutOfDate' } }),
          gpuEvidence: async () => {},
        },
      }),
    ).resolves.toMatchObject({ tcbStatus: 'OutOfDate' });
  });

  test('does not allow an empty GPU evidence set', async () => {
    await expect(
      verifyChutesModelAttestation({
        attestation: createAttestation({ gpuEvidence: [] }),
        clientBinding: { nonce: NONCE },
      }),
    ).rejects.toMatchObject({
      failure: { code: 'policy.gpu_evidence_required' },
    });
  });

  test('rejects mixed GPU architectures instead of discarding an entry', async () => {
    const evidence = [...createAttestation().gpuEvidence];
    evidence[7] = { ...evidence[7], arch: 'BLACKWELL' };
    await expect(
      verifyChutesModelAttestation({
        attestation: createAttestation({ gpuEvidence: evidence }),
        clientBinding: { nonce: NONCE },
      }),
    ).rejects.toMatchObject({
      failure: {
        code: 'gpu.payload_invalid',
        details: { reason: 'mixed_architectures' },
      },
    });
  });

  test('rejects malformed certificate data', async () => {
    await expect(
      verifyChutesModelAttestation({
        attestation: createAttestation({
          certificate: Buffer.from('not DER').toString('base64'),
        }),
        clientBinding: { nonce: NONCE },
      }),
    ).rejects.toMatchObject({
      failure: {
        code: 'input.invalid',
        details: { reason: 'invalid_certificate' },
      },
    });
  });

  test('requires successful custom GPU and deployment verifiers', async () => {
    for (const [key, code] of [
      ['gpuEvidence', 'gpu.attestation_rejected'],
      ['deployment', 'provenance.verification_failed'],
    ] as const) {
      await expect(
        verifyChutesModelAttestation({
          attestation: createAttestation(),
          clientBinding: { nonce: NONCE },
          verifiers: {
            tdxQuote: async () => createQuote(),
            gpuEvidence: async () => {},
            [key]: async () => {
              throw new Error('rejected');
            },
          },
        }),
      ).rejects.toMatchObject({ failure: { code } });
    }
  });
});

describe('Chutes NRAS nonce binding', () => {
  const keys = generateKeyPairSync('ec', { namedCurve: 'secp384r1' });
  const jwks = {
    keys: [{ ...keys.publicKey.export({ format: 'jwk' }), kid: 'chutes-test' }],
  };

  afterEach(() => jest.restoreAllMocks());

  test.each([true, false])(
    'accepts only a signed derived nonce (correct=%s)',
    async (correct) => {
      const derivedNonce = sha256(NONCE + PUBLIC_KEY).toString('hex');
      const now = Math.floor(Date.now() / 1000);
      const header = Buffer.from(
        JSON.stringify({ alg: 'ES384', kid: 'chutes-test' }),
      ).toString('base64url');
      const payload = Buffer.from(
        JSON.stringify({
          iss: 'https://nras.attestation.nvidia.com',
          exp: now + 300,
          nbf: now - 5,
          iat: now - 5,
          eat_nonce: correct ? derivedNonce : NONCE,
          'x-nvidia-overall-att-result': true,
        }),
      ).toString('base64url');
      const input = `${header}.${payload}`;
      const signature = sign('sha384', Buffer.from(input), {
        key: keys.privateKey,
        dsaEncoding: 'ieee-p1363',
      }).toString('base64url');
      jest
        .spyOn(globalThis, 'fetch')
        .mockImplementation(async (_url, options) => {
          if (options?.method === 'POST') {
            const submitted = JSON.parse(String(options.body));
            expect(submitted.nonce).toBe(derivedNonce);
            expect(submitted.evidence_list).toHaveLength(8);
            return Response.json([['JWT', `${input}.${signature}`]]);
          }
          return Response.json(jwks);
        });
      const verification = verifyChutesEvidence({
        attestation: createAttestation(),
        clientBinding: { nonce: NONCE },
        verifiers: { tdxQuote: async () => createQuote() },
      });
      if (correct) {
        await expect(verification).resolves.toMatchObject({
          gpuEvidence: 'verified',
        });
      } else {
        await expect(verification).rejects.toMatchObject({
          failure: {
            code: 'gpu.jwt_verification_failed',
            details: { reason: 'nonce_mismatch' },
          },
        });
      }
    },
  );
});
