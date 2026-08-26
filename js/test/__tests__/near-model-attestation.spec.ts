import { verifyNearModelAttestation } from '../../src';
import { QuoteVerifier } from '../../src/types/verification';
import {
  appCompose,
  createNearModelAttestation,
  createQuote,
  nonce,
  sha384,
  signingAddress,
} from '../fixtures';

describe('verifyNearModelAttestation', () => {
  const quoteVerifier: QuoteVerifier = {
    verify: async () => createQuote(),
  };

  test('verifies quote bindings, RTMR3, and raw app_compose as separate checks', async () => {
    const result = await verifyNearModelAttestation({
      attestation: createNearModelAttestation(),
      expectedNonce: nonce,
      quoteVerifier,
    });

    expect(result).toMatchObject({
      kind: 'near_model',
      tcbStatus: 'UpToDate',
      appCompose,
      provenanceVerified: false,
      runtimeMeasurements: { composeHash: 'beef' },
    });
    expect(result.imageDigests).toEqual(['a'.repeat(64)]);
  });

  test('rejects a report whose echoed nonce is not the caller nonce', async () => {
    await expect(
      verifyNearModelAttestation({
        attestation: createNearModelAttestation({
          request_nonce: '44'.repeat(32),
        }),
        expectedNonce: nonce,
        quoteVerifier,
      }),
    ).rejects.toMatchObject({
      failure: {
        phase: 'binding',
        code: 'binding.nonce_mismatch',
        details: { source: 'request_nonce' },
      },
    });
  });

  test('rejects a NEAR model report without the strict TLS fingerprint binding', async () => {
    const quote = createQuote({
      reportData: Buffer.concat([
        Buffer.from(signingAddress.slice(2), 'hex'),
        Buffer.alloc(12),
        Buffer.from(nonce, 'hex'),
      ]),
    });

    await expect(
      verifyNearModelAttestation({
        attestation: createNearModelAttestation({
          tls_cert_fingerprint: undefined,
        }),
        expectedNonce: nonce,
        quoteVerifier: { verify: async () => quote },
      }),
    ).rejects.toMatchObject({
      failure: {
        phase: 'binding',
        code: 'binding.tls_fingerprint_missing',
        details: { target: 'near_model' },
      },
    });
  });

  test('rejects a debug-enabled TDX quote', async () => {
    await expect(
      verifyNearModelAttestation({
        attestation: createNearModelAttestation(),
        expectedNonce: nonce,
        quoteVerifier: {
          verify: async () => createQuote({ debugEnabled: true }),
        },
      }),
    ).rejects.toMatchObject({
      failure: {
        phase: 'policy',
        code: 'policy.debug_enabled',
        details: { target: 'near_model' },
      },
    });
  });

  test('normalizes a custom quote verifier failure', async () => {
    await expect(
      verifyNearModelAttestation({
        attestation: createNearModelAttestation(),
        expectedNonce: nonce,
        quoteVerifier: {
          verify: async () => {
            throw new Error('verifier implementation detail');
          },
        },
      }),
    ).rejects.toMatchObject({
      failure: {
        phase: 'quote',
        code: 'quote.verification_failed',
        details: { reason: 'verifier_error' },
      },
    });
  });

  test('normalizes an invalid custom quote verifier result', async () => {
    await expect(
      verifyNearModelAttestation({
        attestation: createNearModelAttestation(),
        expectedNonce: nonce,
        quoteVerifier: { verify: async () => undefined as never },
      }),
    ).rejects.toMatchObject({
      failure: {
        phase: 'quote',
        code: 'quote.invalid_result',
        details: {
          path: 'quote',
          expected: 'object',
          actual: 'undefined',
        },
      },
    });
  });

  test('accepts OutOfDate by default and permits a stricter TCB policy', async () => {
    await expect(
      verifyNearModelAttestation({
        attestation: createNearModelAttestation(),
        expectedNonce: nonce,
        quoteVerifier: {
          verify: async () => createQuote({ tcbStatus: 'OutOfDate' }),
        },
      }),
    ).resolves.toMatchObject({ tcbStatus: 'OutOfDate' });

    await expect(
      verifyNearModelAttestation({
        attestation: createNearModelAttestation(),
        expectedNonce: nonce,
        quoteVerifier: {
          verify: async () => createQuote({ tcbStatus: 'OutOfDate' }),
        },
        policy: { allowedTcbStatuses: ['UpToDate'] },
      }),
    ).rejects.toMatchObject({
      failure: {
        phase: 'policy',
        code: 'policy.tcb_status_not_allowed',
        details: { actual: 'OutOfDate', allowed: ['UpToDate'] },
      },
    });
  });

  test('rejects a TCB status outside the default allowlist', async () => {
    await expect(
      verifyNearModelAttestation({
        attestation: createNearModelAttestation(),
        expectedNonce: nonce,
        quoteVerifier: {
          verify: async () => createQuote({ tcbStatus: 'Revoked' }),
        },
      }),
    ).rejects.toMatchObject({
      failure: {
        phase: 'policy',
        code: 'policy.tcb_status_not_allowed',
        details: {
          actual: 'Revoked',
          allowed: ['UpToDate', 'OutOfDate'],
        },
      },
    });
  });

  test('identifies malformed Intel-verified quote report data', async () => {
    await expect(
      verifyNearModelAttestation({
        attestation: createNearModelAttestation(),
        expectedNonce: nonce,
        quoteVerifier: {
          verify: async () => createQuote({ reportData: Buffer.alloc(63) }),
        },
      }),
    ).rejects.toMatchObject({
      failure: {
        phase: 'binding',
        code: 'binding.report_data_invalid',
        details: {
          source: 'quote_report_data',
          reason: 'wrong_length',
          expectedBytes: 64,
          actualBytes: 63,
        },
      },
    });
  });

  test('rejects an event log that cannot replay the quoted RTMR3', async () => {
    await expect(
      verifyNearModelAttestation({
        attestation: createNearModelAttestation({
          event_log: [
            {
              digest: 'ff'.repeat(48),
              event_type: 0,
              event: 'compose-hash',
              event_payload: 'beef',
              imr: 3,
            },
          ],
        }),
        expectedNonce: nonce,
        quoteVerifier,
      }),
    ).rejects.toMatchObject({
      failure: {
        phase: 'measurement',
        code: 'measurement.rtmr3_mismatch',
        details: { reason: 'replay_mismatch' },
      },
    });
  });

  test('accepts defaulted optional fields in a non-runtime event', async () => {
    await expect(
      verifyNearModelAttestation({
        attestation: createNearModelAttestation({
          event_log: JSON.stringify([
            {
              digest: '00'.repeat(48),
              imr: 3,
            },
          ]),
        }),
        expectedNonce: nonce,
        quoteVerifier,
      }),
    ).resolves.toMatchObject({ kind: 'near_model' });
  });

  test('accepts an empty payload in a valid runtime event', async () => {
    const runtimeDigest = sha384(
      Buffer.concat([
        Buffer.from([0x01, 0x00, 0x00, 0x08]),
        Buffer.from(':'),
        Buffer.from('app-id'),
        Buffer.from(':'),
      ]),
    );
    const quote = createQuote({
      rtMr3: sha384(Buffer.concat([Buffer.alloc(48), runtimeDigest])),
    });

    await expect(
      verifyNearModelAttestation({
        attestation: createNearModelAttestation({
          event_log: [
            {
              digest: runtimeDigest.toString('hex'),
              event_type: 0x08000001,
              event: 'app-id',
              event_payload: '',
              imr: 3,
            },
          ],
        }),
        expectedNonce: nonce,
        quoteVerifier: { verify: async () => quote },
      }),
    ).resolves.toMatchObject({ kind: 'near_model' });
  });

  test('rejects app_compose that is not bound to MRCONFIGID', async () => {
    await expect(
      verifyNearModelAttestation({
        attestation: createNearModelAttestation({
          info: { tcb_info: { app_compose: '{"changed":true}' } },
        }),
        expectedNonce: nonce,
        quoteVerifier,
      }),
    ).rejects.toMatchObject({
      failure: {
        phase: 'measurement',
        code: 'measurement.app_compose_mrconfigid_mismatch',
      },
    });
  });

  test('checks the GPU payload nonce before calling the GPU verifier', async () => {
    const gpuVerifier = { verify: jest.fn(async () => undefined) };
    await expect(
      verifyNearModelAttestation({
        attestation: createNearModelAttestation({
          nvidia_payload: JSON.stringify({ nonce: '55'.repeat(32) }),
        }),
        expectedNonce: nonce,
        quoteVerifier,
        gpuVerifier,
      }),
    ).rejects.toMatchObject({
      failure: {
        phase: 'binding',
        code: 'binding.nonce_mismatch',
        details: { source: 'nvidia_payload' },
      },
    });
    expect(gpuVerifier.verify).not.toHaveBeenCalled();
  });

  test('enforces required GPU evidence and records successful GPU verification', async () => {
    await expect(
      verifyNearModelAttestation({
        attestation: createNearModelAttestation(),
        expectedNonce: nonce,
        quoteVerifier,
        policy: { requireGpuEvidence: true },
      }),
    ).rejects.toMatchObject({
      failure: {
        phase: 'policy',
        code: 'policy.gpu_evidence_required',
      },
    });

    await expect(
      verifyNearModelAttestation({
        attestation: createNearModelAttestation({
          nvidia_payload: JSON.stringify({ nonce }),
        }),
        expectedNonce: nonce,
        quoteVerifier,
        gpuVerifier: { verify: async () => undefined },
      }),
    ).resolves.toMatchObject({ gpuVerified: true });
  });

  test('rejects GPU evidence rejected by its verifier', async () => {
    await expect(
      verifyNearModelAttestation({
        attestation: createNearModelAttestation({
          nvidia_payload: JSON.stringify({ nonce }),
        }),
        expectedNonce: nonce,
        quoteVerifier,
        gpuVerifier: {
          verify: async () => {
            throw new Error('GPU evidence was rejected');
          },
        },
      }),
    ).rejects.toMatchObject({
      failure: {
        phase: 'gpu',
        code: 'gpu.attestation_rejected',
        details: { source: 'custom_verifier' },
      },
    });
  });

  test('rejects model report_data that contradicts the verified quote', async () => {
    await expect(
      verifyNearModelAttestation({
        attestation: createNearModelAttestation({
          report_data: 'ff'.repeat(64),
        }),
        expectedNonce: nonce,
        quoteVerifier,
      }),
    ).rejects.toMatchObject({
      failure: {
        phase: 'binding',
        code: 'binding.report_data_mismatch',
        details: { source: 'advertised_report_data' },
      },
    });
  });

  test('requires a provenance verifier when the policy requires deployment provenance', async () => {
    await expect(
      verifyNearModelAttestation({
        attestation: createNearModelAttestation(),
        expectedNonce: nonce,
        quoteVerifier,
        policy: { requireDeploymentProvenance: true },
      }),
    ).rejects.toMatchObject({
      failure: {
        phase: 'policy',
        code: 'policy.provenance_verifier_required',
      },
    });
  });

  test('passes verified measurements to a required provenance verifier', async () => {
    const provenanceVerifier = { verify: jest.fn(async () => undefined) };
    const osImageDigest = Buffer.alloc(48, 1);
    const composeDigest = Buffer.alloc(48, 2);
    const quote = createQuote({
      rtMr3: sha384(
        Buffer.concat([
          sha384(Buffer.concat([Buffer.alloc(48), osImageDigest])),
          composeDigest,
        ]),
      ),
    });

    const result = await verifyNearModelAttestation({
      attestation: createNearModelAttestation({
        event_log: [
          {
            digest: osImageDigest.toString('hex'),
            event_type: 0,
            event: 'os-image-hash',
            event_payload: 'cafe',
            imr: 3,
          },
          {
            digest: composeDigest.toString('hex'),
            event_type: 0,
            event: 'compose-hash',
            event_payload: 'beef',
            imr: 3,
          },
        ],
      }),
      expectedNonce: nonce,
      quoteVerifier: { verify: async () => quote },
      policy: { requireDeploymentProvenance: true },
      provenanceVerifier,
    });

    expect(provenanceVerifier.verify).toHaveBeenCalledWith({
      appCompose,
      imageDigests: ['a'.repeat(64)],
      runtimeMeasurements: {
        osImageHash: 'cafe',
        composeHash: 'beef',
      },
    });
    expect(result.provenanceVerified).toBe(true);
  });

  test('normalizes a custom provenance verifier failure', async () => {
    await expect(
      verifyNearModelAttestation({
        attestation: createNearModelAttestation(),
        expectedNonce: nonce,
        quoteVerifier,
        provenanceVerifier: {
          verify: async () => {
            throw new Error('verifier implementation detail');
          },
        },
      }),
    ).rejects.toMatchObject({
      failure: {
        phase: 'provenance',
        code: 'provenance.verification_failed',
      },
    });
  });
});
