import { Buffer } from 'node:buffer';
import { verifyModelAttestation } from '../../src';
import type { QuoteVerifier } from '../../src';
import {
  appCompose,
  createLegacyModelQuote,
  createModelAttestation,
  createQuote,
  nonce,
  sha256,
  sha384,
  signingAddress,
  tlsFingerprint,
} from '../fixtures';

const DSTACK_RUNTIME_EVENT_TYPE = 0x08000001;

function createRuntimeEvent(event: string, eventPayload: string) {
  const eventType = Buffer.alloc(4);
  eventType.writeUInt32LE(DSTACK_RUNTIME_EVENT_TYPE);
  const digest = sha384(
    Buffer.concat([
      eventType,
      Buffer.from(':'),
      Buffer.from(event),
      Buffer.from(':'),
      Buffer.from(eventPayload, 'hex'),
    ]),
  );

  return {
    digest: digest.toString('hex'),
    event_type: DSTACK_RUNTIME_EVENT_TYPE,
    event,
    event_payload: eventPayload,
    imr: 3,
  };
}

function createQuoteForEventLog(events: readonly { digest: string }[]) {
  let rtmr3: Uint8Array = Buffer.alloc(48);
  for (const event of events) {
    rtmr3 = sha384(Buffer.concat([rtmr3, Buffer.from(event.digest, 'hex')]));
  }
  return createQuote({ rtMr3: Buffer.from(rtmr3) });
}

describe('model attestation verification', () => {
  const quoteVerifier: QuoteVerifier = async () => createQuote();

  test('returns verified model evidence with explicit verification states', async () => {
    const result = await verifyModelAttestation({
      attestation: createModelAttestation(),
      nonce,
      verifiers: { quote: quoteVerifier },
    });

    expect(result).toMatchObject({
      signer: { algorithm: 'ecdsa', address: signingAddress },
      tcbStatus: 'UpToDate',
      tlsBinding: { kind: 'declared', spkiFingerprint: tlsFingerprint },
      gpuEvidence: 'not_provided',
      deploymentProvenance: 'not_checked',
    });
    expect(result.deployment).toEqual({ appCompose, runtimeMeasurements: {} });
  });

  test('rejects a report whose echoed nonce is not the caller nonce', async () => {
    await expect(
      verifyModelAttestation({
        attestation: createModelAttestation({
          nonce: '44'.repeat(32),
        }),
        nonce,
        verifiers: { quote: quoteVerifier },
      }),
    ).rejects.toMatchObject({
      failure: {
        phase: 'binding',
        code: 'binding.nonce_mismatch',
        details: { source: 'attestationNonce' },
      },
    });
  });

  test('uses the signer snapshot captured before an async quote verifier runs', async () => {
    const laterAddress = `0x${'44'.repeat(20)}`;
    const attestation = createModelAttestation();
    const quote = createQuote({
      reportData: Buffer.concat([
        sha256(
          Buffer.concat([
            Buffer.from(laterAddress.slice(2), 'hex'),
            Buffer.from(tlsFingerprint, 'hex'),
          ]),
        ),
        Buffer.from(nonce, 'hex'),
      ]),
    });

    await expect(
      verifyModelAttestation({
        attestation,
        nonce,
        verifiers: {
          quote: async () => {
            attestation.signer = {
              algorithm: 'ecdsa',
              address: laterAddress,
            };
            return quote;
          },
        },
      }),
    ).rejects.toMatchObject({
      failure: {
        phase: 'binding',
        code: 'binding.report_data_mismatch',
        details: { source: 'signerTlsBinding' },
      },
    });
  });

  test.each([undefined, null])(
    'accepts the legacy signer-and-nonce model binding without a declared SPKI (%p)',
    async (fingerprint) => {
      const result = await verifyModelAttestation({
        attestation: createModelAttestation({
          declaredSpkiFingerprint: fingerprint,
        }),
        nonce,
        verifiers: { quote: async () => createLegacyModelQuote() },
      });

      expect(result.tlsBinding).toEqual({ kind: 'none' });
    },
  );

  test('does not downgrade a declared-SPKI report to the legacy layout', async () => {
    await expect(
      verifyModelAttestation({
        attestation: createModelAttestation(),
        nonce,
        verifiers: { quote: async () => createLegacyModelQuote() },
      }),
    ).rejects.toMatchObject({
      failure: {
        phase: 'binding',
        code: 'binding.report_data_mismatch',
        details: { source: 'signerTlsBinding' },
      },
    });
  });

  test('rejects a legacy report whose padded signer does not match', async () => {
    const quote = createLegacyModelQuote({
      reportData: Buffer.concat([
        Buffer.alloc(32, 0x44),
        Buffer.from(nonce, 'hex'),
      ]),
    });

    await expect(
      verifyModelAttestation({
        attestation: createModelAttestation({
          declaredSpkiFingerprint: undefined,
        }),
        nonce,
        verifiers: { quote: async () => quote },
      }),
    ).rejects.toMatchObject({
      failure: {
        phase: 'binding',
        code: 'binding.report_data_mismatch',
        details: { source: 'signerBinding' },
      },
    });
  });

  test('rejects debug-enabled TDX quotes before accepting measurements', async () => {
    await expect(
      verifyModelAttestation({
        attestation: createModelAttestation(),
        nonce,
        verifiers: {
          quote: async () => createQuote({ debugEnabled: true }),
        },
      }),
    ).rejects.toMatchObject({
      failure: { phase: 'policy', code: 'policy.debug_enabled' },
    });
  });

  test('normalizes custom quote verifier failures', async () => {
    await expect(
      verifyModelAttestation({
        attestation: createModelAttestation(),
        nonce,
        verifiers: {
          quote: async () => {
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

  test('rejects invalid quote verifier output', async () => {
    await expect(
      verifyModelAttestation({
        attestation: createModelAttestation(),
        nonce,
        verifiers: { quote: async () => undefined as never },
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

  test('accepts OutOfDate by default and supports an explicit TCB policy', async () => {
    await expect(
      verifyModelAttestation({
        attestation: createModelAttestation(),
        nonce,
        verifiers: {
          quote: async () => createQuote({ tcbStatus: 'OutOfDate' }),
        },
      }),
    ).resolves.toMatchObject({ tcbStatus: 'OutOfDate' });

    await expect(
      verifyModelAttestation({
        attestation: createModelAttestation(),
        nonce,
        policy: { acceptedTcbStatuses: ['UpToDate'] },
        verifiers: {
          quote: async () => createQuote({ tcbStatus: 'OutOfDate' }),
        },
      }),
    ).rejects.toMatchObject({
      failure: {
        phase: 'policy',
        code: 'policy.tcb_status_not_allowed',
        details: { actual: 'OutOfDate', accepted: ['UpToDate'] },
      },
    });
  });

  test('rejects a TCB status outside the default policy', async () => {
    await expect(
      verifyModelAttestation({
        attestation: createModelAttestation(),
        nonce,
        verifiers: {
          quote: async () => createQuote({ tcbStatus: 'Revoked' }),
        },
      }),
    ).rejects.toMatchObject({
      failure: {
        phase: 'policy',
        code: 'policy.tcb_status_not_allowed',
        details: {
          actual: 'Revoked',
          accepted: ['UpToDate', 'OutOfDate'],
        },
      },
    });
  });

  test('rejects malformed Intel-verified report data', async () => {
    await expect(
      verifyModelAttestation({
        attestation: createModelAttestation(),
        nonce,
        verifiers: {
          quote: async () => createQuote({ reportData: Buffer.alloc(63) }),
        },
      }),
    ).rejects.toMatchObject({
      failure: {
        phase: 'binding',
        code: 'binding.report_data_invalid',
        details: {
          source: 'quoteReportData',
          reason: 'wrong_length',
          expectedBytes: 64,
          actualBytes: 63,
        },
      },
    });
  });

  test('rejects an event log that cannot replay the quoted RTMR3', async () => {
    await expect(
      verifyModelAttestation({
        attestation: createModelAttestation({
          eventLog: [
            {
              digest: 'ff'.repeat(48),
              event_type: 0,
              event: 'compose-hash',
              event_payload: 'beef',
              imr: 3,
            },
          ],
        }),
        nonce,
        verifiers: { quote: quoteVerifier },
      }),
    ).rejects.toMatchObject({
      failure: {
        phase: 'measurement',
        code: 'measurement.rtmr3_mismatch',
        details: { reason: 'replay_mismatch' },
      },
    });
  });

  test('accepts defaulted optional event fields and an empty runtime payload', async () => {
    await expect(
      verifyModelAttestation({
        attestation: createModelAttestation({
          eventLog: JSON.stringify([{ digest: '00'.repeat(48), imr: 3 }]),
        }),
        nonce,
        verifiers: { quote: quoteVerifier },
      }),
    ).resolves.toMatchObject({ gpuEvidence: 'not_provided' });

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
      verifyModelAttestation({
        attestation: createModelAttestation({
          eventLog: [
            {
              digest: runtimeDigest.toString('hex'),
              event_type: 0x08000001,
              event: 'app-id',
              event_payload: '',
              imr: 3,
            },
          ],
        }),
        nonce,
        verifiers: { quote: async () => quote },
      }),
    ).resolves.toMatchObject({ gpuEvidence: 'not_provided' });
  });

  test('does not expose metadata from replay-only legacy events', async () => {
    const digest = Buffer.alloc(48, 7);
    const result = await verifyModelAttestation({
      attestation: createModelAttestation({
        eventLog: [
          {
            digest: digest.toString('hex'),
            event_type: 0,
            event: 'compose-hash',
            event_payload: 'forged',
            imr: 3,
          },
        ],
      }),
      nonce,
      verifiers: {
        quote: async () =>
          createQuote({
            rtMr3: sha384(Buffer.concat([Buffer.alloc(48), digest])),
          }),
      },
    });

    expect(result.deployment.runtimeMeasurements).toEqual({});
  });

  test('rejects app compose data that is not bound to MRCONFIGID', async () => {
    await expect(
      verifyModelAttestation({
        attestation: createModelAttestation({
          appCompose: '{"changed":true}',
        }),
        nonce,
        verifiers: { quote: quoteVerifier },
      }),
    ).rejects.toMatchObject({
      failure: {
        phase: 'measurement',
        code: 'measurement.app_compose_mrconfigid_mismatch',
      },
    });
  });

  test('checks the NVIDIA payload nonce before calling a custom verifier', async () => {
    const nvidia = jest.fn(async () => undefined);

    await expect(
      verifyModelAttestation({
        attestation: createModelAttestation({
          nvidiaPayload: JSON.stringify({ nonce: '55'.repeat(32) }),
        }),
        nonce,
        verifiers: { quote: quoteVerifier, nvidia },
      }),
    ).rejects.toMatchObject({
      failure: {
        phase: 'binding',
        code: 'binding.nonce_mismatch',
        details: { source: 'nvidiaPayload' },
      },
    });
    expect(nvidia).not.toHaveBeenCalled();
  });

  test('rejects an empty NVIDIA payload instead of treating it as absent', async () => {
    await expect(
      verifyModelAttestation({
        attestation: createModelAttestation({ nvidiaPayload: '' }),
        nonce,
        verifiers: { quote: quoteVerifier },
      }),
    ).rejects.toMatchObject({
      failure: {
        phase: 'gpu',
        code: 'gpu.payload_invalid',
        details: { reason: 'invalid_json' },
      },
    });
  });

  test('models GPU evidence as an explicit status', async () => {
    await expect(
      verifyModelAttestation({
        attestation: createModelAttestation(),
        nonce,
        policy: { gpuEvidence: 'required' },
        verifiers: { quote: quoteVerifier },
      }),
    ).rejects.toMatchObject({
      failure: { phase: 'policy', code: 'policy.gpu_evidence_required' },
    });

    const result = await verifyModelAttestation({
      attestation: createModelAttestation({
        nvidiaPayload: JSON.stringify({ nonce }),
      }),
      nonce,
      verifiers: { quote: quoteVerifier, nvidia: async () => undefined },
    });
    expect(result.gpuEvidence).toBe('verified');
  });

  test('normalizes NVIDIA verifier failures', async () => {
    await expect(
      verifyModelAttestation({
        attestation: createModelAttestation({
          nvidiaPayload: JSON.stringify({ nonce }),
        }),
        nonce,
        verifiers: {
          quote: quoteVerifier,
          nvidia: async () => {
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

  test('rejects model report data that contradicts the verified quote', async () => {
    await expect(
      verifyModelAttestation({
        attestation: createModelAttestation({
          reportedQuoteData: 'ff'.repeat(64),
        }),
        nonce,
        verifiers: { quote: quoteVerifier },
      }),
    ).rejects.toMatchObject({
      failure: {
        phase: 'binding',
        code: 'binding.report_data_mismatch',
        details: { source: 'reportedQuoteData' },
      },
    });
  });

  test('passes raw measured configuration to a deployment verifier', async () => {
    const osImageEvent = createRuntimeEvent('os-image-hash', 'cafe');
    const composeEvent = createRuntimeEvent('compose-hash', 'beef');
    const quote = createQuoteForEventLog([osImageEvent, composeEvent]);
    const deployment = jest.fn(async () => undefined);

    const result = await verifyModelAttestation({
      attestation: createModelAttestation({
        eventLog: [osImageEvent, composeEvent],
      }),
      nonce,
      verifiers: { quote: async () => quote, deployment },
    });

    expect(deployment).toHaveBeenCalledWith({
      appCompose,
      runtimeMeasurements: {
        osImageHash: 'cafe',
        composeHash: 'beef',
      },
    });
    expect(result.deploymentProvenance).toBe('verified');
  });

  test('keeps verified deployment measurements independent from the verifier input', async () => {
    const composeEvent = createRuntimeEvent('compose-hash', 'beef');
    const result = await verifyModelAttestation({
      attestation: createModelAttestation({ eventLog: [composeEvent] }),
      nonce,
      verifiers: {
        quote: async () => createQuoteForEventLog([composeEvent]),
        deployment: async (deployment) => {
          const mutable = deployment as {
            runtimeMeasurements: { composeHash?: string };
          };
          mutable.runtimeMeasurements.composeHash = 'changed';
        },
      },
    });

    expect(result.deployment.runtimeMeasurements.composeHash).toBe('beef');
  });

  test('normalizes deployment verifier failures', async () => {
    await expect(
      verifyModelAttestation({
        attestation: createModelAttestation(),
        nonce,
        verifiers: {
          quote: quoteVerifier,
          deployment: async () => {
            throw new Error('verifier implementation detail');
          },
        },
      }),
    ).rejects.toMatchObject({
      failure: { phase: 'provenance', code: 'provenance.verification_failed' },
    });
  });
});
