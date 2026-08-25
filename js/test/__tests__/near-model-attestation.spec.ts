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
    ).rejects.toThrow('request_nonce does not match expectedNonce');
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
    ).rejects.toThrow('strict NEAR binding is required');
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
    ).rejects.toThrow('TDX debug mode is enabled');
  });

  test('applies the configured TCB policy', async () => {
    await expect(
      verifyNearModelAttestation({
        attestation: createNearModelAttestation(),
        expectedNonce: nonce,
        quoteVerifier: {
          verify: async () => createQuote({ tcbStatus: 'OutOfDate' }),
        },
      }),
    ).rejects.toThrow("TDX TCB status 'OutOfDate' is not allowed");
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
    ).rejects.toThrow('event log RTMR3 replay does not match quote');
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
    ).rejects.toThrow('raw app_compose does not match quote MRCONFIGID');
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
    ).rejects.toThrow('request_nonce does not match expectedNonce');
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
    ).rejects.toThrow('GPU evidence is required by policy');

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
    ).rejects.toThrow('GPU evidence was rejected');
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
    ).rejects.toThrow('reported report_data does not match');
  });

  test('requires a provenance verifier when the policy requires deployment provenance', async () => {
    await expect(
      verifyNearModelAttestation({
        attestation: createNearModelAttestation(),
        expectedNonce: nonce,
        quoteVerifier,
        policy: { requireDeploymentProvenance: true },
      }),
    ).rejects.toThrow('deployment provenance is required by policy');
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
});
