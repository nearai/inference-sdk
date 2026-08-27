import { Buffer } from 'node:buffer';
import {
  ApiError,
  isApiError,
  isVerificationError,
  VerificationError,
  verifyModelAttestation,
} from '../../src';
import type { QuoteVerifier, TcbStatus } from '../../src';
import {
  appCompose,
  createLegacyModelQuote,
  createModelAttestation,
  createQuote,
  nonce,
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

  afterEach(() => {
    jest.restoreAllMocks();
  });

  test('returns verified model evidence with explicit verification states', async () => {
    const result = await verifyModelAttestation({
      attestation: createModelAttestation(),
      nonce,
      verifiers: { quote: quoteVerifier },
    });

    expect(result).toMatchObject({
      signer: { signingAlgo: 'ecdsa', signingAddress },
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

  test('accepts the legacy signer-and-nonce model binding without a declared SPKI', async () => {
    const result = await verifyModelAttestation({
      attestation: createModelAttestation({
        declaredSpkiFingerprint: null,
      }),
      nonce,
      verifiers: { quote: async () => createLegacyModelQuote() },
    });

    expect(result.tlsBinding).toEqual({ kind: 'none' });
  });

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

  test('normalizes an API failure from a custom quote verifier', async () => {
    let error: unknown;
    try {
      await verifyModelAttestation({
        attestation: createModelAttestation(),
        nonce,
        verifiers: {
          quote: async () => {
            throw new ApiError({
              phase: 'api',
              code: 'api.transport_failed',
              details: { resource: 'model_attestation', reason: 'request' },
              retryable: true,
            });
          },
        },
      });
    } catch (cause) {
      error = cause;
    }

    expect(error).toBeInstanceOf(VerificationError);
    expect(error).not.toBeInstanceOf(ApiError);
    expect(isVerificationError(error)).toBe(true);
    expect(isApiError(error)).toBe(false);
    if (!isVerificationError(error)) {
      return;
    }
    expect(error.failure).toMatchObject({
      phase: 'quote',
      code: 'quote.verification_failed',
      details: { reason: 'verifier_error' },
    });
  });

  test('rejects a structurally malformed Intel quote without suggesting retry', async () => {
    await expect(
      verifyModelAttestation({
        attestation: createModelAttestation({ intelQuote: '00' }),
        nonce,
      }),
    ).rejects.toMatchObject({
      failure: {
        phase: 'quote',
        code: 'quote.verification_failed',
        details: { reason: 'invalid_quote' },
      },
      retryable: false,
    });
  });

  test('accepts OutOfDate by default and supports an explicit TCB policy', async () => {
    const accepted = await verifyModelAttestation({
      attestation: createModelAttestation(),
      nonce,
      verifiers: {
        quote: async () => createQuote({ tcbStatus: 'OutOfDate' }),
      },
    });

    expect(accepted.tcbStatus).toBe('OutOfDate');

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

  test('does not let a rejected default TCB policy alter a later default', async () => {
    const input = {
      attestation: createModelAttestation(),
      nonce,
      verifiers: {
        quote: async () => createQuote({ tcbStatus: 'Revoked' }),
      },
    };

    let error: unknown;
    try {
      await verifyModelAttestation(input);
    } catch (cause) {
      error = cause;
    }

    expect(error).toBeInstanceOf(VerificationError);
    if (!(error instanceof VerificationError)) {
      throw error;
    }
    expect(error.failure).toMatchObject({
      phase: 'policy',
      code: 'policy.tcb_status_not_allowed',
      details: { accepted: ['UpToDate', 'OutOfDate'] },
    });
    if (error.failure.code !== 'policy.tcb_status_not_allowed') {
      throw error;
    }

    (error.failure.details.accepted as TcbStatus[]).push('Revoked');

    await expect(verifyModelAttestation(input)).rejects.toMatchObject({
      failure: {
        phase: 'policy',
        code: 'policy.tcb_status_not_allowed',
        details: { accepted: ['UpToDate', 'OutOfDate'] },
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

  test('verifies NVIDIA evidence through NRAS by default', async () => {
    mockNrasOverallResult(true);

    const result = await verifyModelAttestation({
      attestation: createModelAttestation({
        nvidiaPayload: JSON.stringify({ nonce }),
      }),
      nonce,
      verifiers: { quote: quoteVerifier },
    });

    expect(result.gpuEvidence).toBe('verified');
  });

  test('reports rejected NVIDIA evidence from NRAS', async () => {
    mockNrasOverallResult(false);

    await expect(
      verifyModelAttestation({
        attestation: createModelAttestation({
          nvidiaPayload: JSON.stringify({ nonce }),
        }),
        nonce,
        verifiers: { quote: quoteVerifier },
      }),
    ).rejects.toMatchObject({
      failure: {
        phase: 'gpu',
        code: 'gpu.attestation_rejected',
        details: { source: 'nras' },
      },
    });
  });

  test('rejects an NRAS result whose overall verdict is not boolean', async () => {
    mockNrasOverallResult('PASS');

    await expect(
      verifyModelAttestation({
        attestation: createModelAttestation({
          nvidiaPayload: JSON.stringify({ nonce }),
        }),
        nonce,
        verifiers: { quote: quoteVerifier },
      }),
    ).rejects.toMatchObject({
      failure: {
        phase: 'gpu',
        code: 'gpu.nras_response_invalid',
        details: { reason: 'invalid_verdict_type' },
      },
    });
  });

  test('preserves an invalid NRAS response from the default NVIDIA verifier', async () => {
    mockNrasJwtPayload(null);

    await expect(
      verifyModelAttestation({
        attestation: createModelAttestation({
          nvidiaPayload: JSON.stringify({ nonce }),
        }),
        nonce,
        verifiers: { quote: quoteVerifier },
      }),
    ).rejects.toMatchObject({
      failure: {
        phase: 'gpu',
        code: 'gpu.nras_response_invalid',
        details: { reason: 'invalid_jwt' },
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

function mockNrasOverallResult(result: boolean | string): void {
  mockNrasJwtPayload({ 'x-nvidia-overall-att-result': result });
}

function mockNrasJwtPayload(payload: unknown): void {
  const header = Buffer.from(JSON.stringify({ alg: 'none' })).toString(
    'base64url',
  );
  const encodedPayload = Buffer.from(JSON.stringify(payload)).toString(
    'base64url',
  );
  const jwt = `${header}.${encodedPayload}.signature`;

  jest
    .spyOn(globalThis, 'fetch')
    .mockResolvedValue(
      new Response(JSON.stringify([['JWT', jwt]]), { status: 200 }),
    );
}
