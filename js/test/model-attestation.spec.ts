import { Buffer } from 'node:buffer';
import { generateKeyPairSync, sign } from 'node:crypto';
import { SigningKey, computeAddress } from 'ethers';
import { ApiError, verifyModelAttestation } from '../src';
import type { MeasuredDeployment, QuoteVerifier } from '../src';
import {
  appCompose,
  createModelAttestation,
  createModelQuote,
  nonce,
  sha384,
  signingAddress,
} from './fixtures';

const DSTACK_RUNTIME_EVENT_TYPE = 0x08000001;
const NRAS_KEYS = generateKeyPairSync('ec', { namedCurve: 'secp384r1' });
const NRAS_JWKS = {
  keys: [
    { ...NRAS_KEYS.publicKey.export({ format: 'jwk' }), kid: 'test-nras' },
  ],
};
type EventLogDigest = {
  digest: string;
};

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

function createQuoteForEventLog(events: readonly EventLogDigest[]) {
  let rtmr3: Uint8Array = Buffer.alloc(48);
  for (const event of events) {
    rtmr3 = sha384(Buffer.concat([rtmr3, Buffer.from(event.digest, 'hex')]));
  }
  return createModelQuote({ rtMr3: Buffer.from(rtmr3) });
}

function createModelQuoteForSigner(signer: string) {
  const signerBinding = Buffer.alloc(32);
  Buffer.from(signer.startsWith('0x') ? signer.slice(2) : signer, 'hex').copy(
    signerBinding,
  );
  return createModelQuote({
    reportData: Buffer.concat([signerBinding, Buffer.from(nonce, 'hex')]),
  });
}

describe('model attestation verification', () => {
  const quoteVerifier: QuoteVerifier = async () => createModelQuote();

  afterEach(() => {
    jest.restoreAllMocks();
  });

  test('returns verified model evidence with explicit verification states', async () => {
    const result = await verifyModelAttestation({
      attestation: createModelAttestation(),
      clientBinding: { nonce },
      verifiers: { quote: quoteVerifier },
    });

    expect(result).toMatchObject({
      signer: { signingAlgo: 'ecdsa', signingAddress },
      tcbStatus: 'UpToDate',
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
        clientBinding: { nonce },
        verifiers: { quote: quoteVerifier },
      }),
    ).rejects.toMatchObject({
      failure: {
        code: 'binding.nonce_mismatch',
        details: { source: 'attestationNonce' },
      },
    });
  });

  test('supports serialized event logs for an Ed25519 model signer', async () => {
    const ed25519SigningAddress = '66'.repeat(32);
    const eventLog = createModelAttestation().eventLog;
    const quote = createModelQuote({
      reportData: Buffer.concat([
        Buffer.from(ed25519SigningAddress, 'hex'),
        Buffer.from(nonce, 'hex'),
      ]),
    });
    const result = await verifyModelAttestation({
      attestation: createModelAttestation({
        signer: {
          signingAlgo: 'ed25519',
          signingAddress: ed25519SigningAddress,
        },
        eventLog: JSON.stringify(eventLog),
      }),
      clientBinding: { nonce },
      verifiers: { quote: async () => quote },
    });

    expect(result).toMatchObject({
      signer: { signingAlgo: 'ed25519', signingAddress: ed25519SigningAddress },
    });
  });

  test('binds an Ed25519 model public key to the quote signer', async () => {
    const ed25519SigningAddress = '66'.repeat(32);
    const result = await verifyModelAttestation({
      attestation: createModelAttestation({
        signer: {
          signingAlgo: 'ed25519',
          signingAddress: ed25519SigningAddress,
        },
        signingPublicKey: ed25519SigningAddress.toUpperCase(),
      }),
      clientBinding: { nonce },
      verifiers: {
        quote: async () => createModelQuoteForSigner(ed25519SigningAddress),
      },
    });

    expect(result.signingPublicKey).toBe(ed25519SigningAddress);
  });

  test('binds a raw ECDSA model public key to the quote signer', async () => {
    const signingKey = new SigningKey(
      '0x0123456789012345678901234567890123456789012345678901234567890123',
    );
    const signingPublicKey = signingKey.publicKey.slice(4);
    const signingAddress = computeAddress(signingKey.publicKey);
    const result = await verifyModelAttestation({
      attestation: createModelAttestation({
        signer: { signingAlgo: 'ecdsa', signingAddress },
        signingPublicKey: signingPublicKey.toUpperCase(),
      }),
      clientBinding: { nonce },
      verifiers: {
        quote: async () => createModelQuoteForSigner(signingAddress),
      },
    });

    expect(result.signingPublicKey).toBe(signingPublicKey);
  });

  test('accepts an uncompressed-prefix ECDSA model public key', async () => {
    const signingKey = new SigningKey(
      '0x0123456789012345678901234567890123456789012345678901234567890123',
    );
    const signingAddress = computeAddress(signingKey.publicKey);
    const result = await verifyModelAttestation({
      attestation: createModelAttestation({
        signer: { signingAlgo: 'ecdsa', signingAddress },
        signingPublicKey: signingKey.publicKey.slice(2),
      }),
      clientBinding: { nonce },
      verifiers: {
        quote: async () => createModelQuoteForSigner(signingAddress),
      },
    });

    expect(result.signingPublicKey).toBe(signingKey.publicKey.slice(4));
  });

  test('rejects an ECDSA model public key for a different quote signer', async () => {
    const expectedSigner = new SigningKey(
      '0x0123456789012345678901234567890123456789012345678901234567890123',
    );
    const suppliedKey = new SigningKey(
      '0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd',
    );
    const signingAddress = computeAddress(expectedSigner.publicKey);

    await expect(
      verifyModelAttestation({
        attestation: createModelAttestation({
          signer: { signingAlgo: 'ecdsa', signingAddress },
          signingPublicKey: suppliedKey.publicKey.slice(4),
        }),
        clientBinding: { nonce },
        verifiers: {
          quote: async () => createModelQuoteForSigner(signingAddress),
        },
      }),
    ).rejects.toMatchObject({
      failure: { code: 'binding.model_public_key_mismatch' },
    });
  });

  test('rejects an event log entry with a missing required field', async () => {
    await expect(
      verifyModelAttestation({
        attestation: createModelAttestation({ eventLog: '[{}]' }),
        clientBinding: { nonce },
        verifiers: { quote: quoteVerifier },
      }),
    ).rejects.toMatchObject({
      failure: {
        code: 'measurement.event_log_invalid',
        details: { path: 'eventLog[0].digest', reason: 'invalid_type' },
      },
    });
  });

  test('rejects an invalid serialized event log', async () => {
    await expect(
      verifyModelAttestation({
        attestation: createModelAttestation({ eventLog: '[' }),
        clientBinding: { nonce },
        verifiers: { quote: quoteVerifier },
      }),
    ).rejects.toMatchObject({
      failure: {
        code: 'measurement.event_log_invalid',
        details: { path: 'eventLog', reason: 'invalid_json' },
      },
    });
  });

  test('rejects a model report whose padded signer does not match', async () => {
    const quote = createModelQuote({
      reportData: Buffer.concat([
        Buffer.alloc(32, 0x44),
        Buffer.from(nonce, 'hex'),
      ]),
    });

    await expect(
      verifyModelAttestation({
        attestation: createModelAttestation(),
        clientBinding: { nonce },
        verifiers: { quote: async () => quote },
      }),
    ).rejects.toMatchObject({
      failure: {
        code: 'binding.report_data_mismatch',
        details: { source: 'signerBinding' },
      },
    });
  });

  test('rejects debug-enabled TDX quotes before accepting measurements', async () => {
    await expect(
      verifyModelAttestation({
        attestation: createModelAttestation(),
        clientBinding: { nonce },
        verifiers: {
          quote: async () => createModelQuote({ debugEnabled: true }),
        },
      }),
    ).rejects.toMatchObject({
      failure: { code: 'policy.debug_enabled' },
    });
  });

  test('normalizes an API failure from a custom quote verifier', async () => {
    await expect(
      verifyModelAttestation({
        attestation: createModelAttestation(),
        clientBinding: { nonce },
        verifiers: {
          quote: async () => {
            throw new ApiError({
              code: 'api.transport_failed',
              details: { resource: 'model_attestation', reason: 'request' },
              retryable: true,
            });
          },
        },
      }),
    ).rejects.toMatchObject({
      failure: {
        code: 'quote.verification_failed',
        details: { reason: 'verifier_error' },
      },
    });
  });

  test('rejects a structurally malformed Intel quote without suggesting retry', async () => {
    await expect(
      verifyModelAttestation({
        attestation: createModelAttestation({ intelQuote: '00' }),
        clientBinding: { nonce },
      }),
    ).rejects.toMatchObject({
      failure: {
        code: 'quote.verification_failed',
        details: { reason: 'invalid_quote' },
      },
      retryable: false,
    });
  });

  test('accepts OutOfDate by default and supports an explicit TCB policy', async () => {
    const accepted = await verifyModelAttestation({
      attestation: createModelAttestation(),
      clientBinding: { nonce },
      verifiers: {
        quote: async () => createModelQuote({ tcbStatus: 'OutOfDate' }),
      },
    });

    expect(accepted.tcbStatus).toBe('OutOfDate');

    await expect(
      verifyModelAttestation({
        attestation: createModelAttestation(),
        clientBinding: { nonce },
        policy: { acceptedTcbStatuses: ['UpToDate'] },
        verifiers: {
          quote: async () => createModelQuote({ tcbStatus: 'OutOfDate' }),
        },
      }),
    ).rejects.toMatchObject({
      failure: {
        code: 'policy.tcb_status_not_allowed',
        details: { actual: 'OutOfDate', accepted: ['UpToDate'] },
      },
    });
  });

  test('rejects malformed Intel-verified report data', async () => {
    await expect(
      verifyModelAttestation({
        attestation: createModelAttestation(),
        clientBinding: { nonce },
        verifiers: {
          quote: async () => createModelQuote({ reportData: Buffer.alloc(63) }),
        },
      }),
    ).rejects.toMatchObject({
      failure: {
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
        clientBinding: { nonce },
        verifiers: { quote: quoteVerifier },
      }),
    ).rejects.toMatchObject({
      failure: {
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
        clientBinding: { nonce },
        verifiers: { quote: quoteVerifier },
      }),
    ).rejects.toMatchObject({
      failure: {
        code: 'measurement.app_compose_mrconfigid_mismatch',
      },
    });
  });

  test('rejects NVIDIA evidence with a different nonce', async () => {
    await expect(
      verifyModelAttestation({
        attestation: createModelAttestation({
          nvidiaPayload: JSON.stringify({ nonce: '55'.repeat(32) }),
        }),
        clientBinding: { nonce },
        verifiers: { quote: quoteVerifier },
      }),
    ).rejects.toMatchObject({
      failure: {
        code: 'binding.nonce_mismatch',
        details: { source: 'nvidiaPayload' },
      },
    });
  });

  test('rejects NVIDIA evidence without a nonce', async () => {
    await expect(
      verifyModelAttestation({
        attestation: createModelAttestation({ nvidiaPayload: '{}' }),
        clientBinding: { nonce },
        verifiers: { quote: quoteVerifier },
      }),
    ).rejects.toMatchObject({
      failure: {
        code: 'gpu.payload_invalid',
        details: { reason: 'nonce_missing' },
      },
    });
  });

  test('models GPU evidence as an explicit status', async () => {
    await expect(
      verifyModelAttestation({
        attestation: createModelAttestation(),
        clientBinding: { nonce },
        policy: { gpuEvidence: 'required' },
        verifiers: { quote: quoteVerifier },
      }),
    ).rejects.toMatchObject({
      failure: { code: 'policy.gpu_evidence_required' },
    });

    const result = await verifyModelAttestation({
      attestation: createModelAttestation({
        nvidiaPayload: JSON.stringify({ nonce }),
      }),
      clientBinding: { nonce },
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
        clientBinding: { nonce },
        verifiers: {
          quote: quoteVerifier,
          nvidia: async () => {
            throw new Error('GPU evidence was rejected');
          },
        },
      }),
    ).rejects.toMatchObject({
      failure: {
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
      clientBinding: { nonce },
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
        clientBinding: { nonce },
        verifiers: { quote: quoteVerifier },
      }),
    ).rejects.toMatchObject({
      failure: {
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
        clientBinding: { nonce },
        verifiers: { quote: quoteVerifier },
      }),
    ).rejects.toMatchObject({
      failure: {
        code: 'gpu.jwt_verification_failed',
        details: { reason: 'invalid_claims' },
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
        clientBinding: { nonce },
        verifiers: { quote: quoteVerifier },
      }),
    ).rejects.toMatchObject({
      failure: {
        code: 'gpu.jwt_verification_failed',
        details: { reason: 'invalid_claims' },
      },
    });
  });

  test('rejects an NRAS response without a JWT envelope', async () => {
    jest
      .spyOn(globalThis, 'fetch')
      .mockResolvedValue(
        new Response(JSON.stringify([['TOKEN', 'not-a-jwt']]), { status: 200 }),
      );

    await expect(
      verifyModelAttestation({
        attestation: createModelAttestation({
          nvidiaPayload: JSON.stringify({ nonce }),
        }),
        clientBinding: { nonce },
        verifiers: { quote: quoteVerifier },
      }),
    ).rejects.toMatchObject({
      failure: {
        code: 'gpu.nras_response_invalid',
        details: { reason: 'invalid_schema' },
      },
    });
  });

  test.each([
    ['expired', { exp: 1 }, 'expired'],
    ['not yet valid', { nbf: 4102444800 }, 'not_yet_valid'],
    ['issued in the future', { iat: 4102444800 }, 'not_yet_valid'],
    ['wrong issuer', { iss: 'https://untrusted.example' }, 'invalid_claims'],
    ['missing expiration', { exp: undefined }, 'invalid_claims'],
    ['missing not-before time', { nbf: undefined }, 'invalid_claims'],
    ['invalid not-before time', { nbf: [] }, 'invalid_claims'],
    ['missing signed nonce', { eat_nonce: undefined }, 'invalid_claims'],
    ['wrong signed nonce', { eat_nonce: '44'.repeat(32) }, 'nonce_mismatch'],
  ])('rejects an NRAS token with %s', async (_, overrides, reason) => {
    mockNrasJwtPayload(nrasClaims(overrides));
    await expect(
      verifyModelAttestation({
        attestation: createModelAttestation({
          nvidiaPayload: JSON.stringify({ nonce }),
        }),
        clientBinding: { nonce },
        verifiers: { quote: quoteVerifier },
      }),
    ).rejects.toMatchObject({
      failure: { code: 'gpu.jwt_verification_failed', details: { reason } },
    });
  });

  test('rejects a modified NRAS token even when its verdict is true', async () => {
    const token = createNrasJwt(
      nrasClaims({ 'x-nvidia-overall-att-result': false }),
    );
    const [header, , signature] = token.split('.');
    const modifiedPayload = Buffer.from(JSON.stringify(nrasClaims())).toString(
      'base64url',
    );
    mockNrasResponse([['JWT', `${header}.${modifiedPayload}.${signature}`]]);
    await expect(
      verifyModelAttestation({
        attestation: createModelAttestation({
          nvidiaPayload: JSON.stringify({ nonce }),
        }),
        clientBinding: { nonce },
        verifiers: { quote: quoteVerifier },
      }),
    ).rejects.toMatchObject({
      failure: {
        code: 'gpu.jwt_verification_failed',
        details: { reason: 'invalid_signature' },
      },
    });
  });

  test.each([
    [{ alg: 'none', kid: 'test-nras' }, 'unsupported_algorithm'],
    [{ alg: 'ES384', kid: 'unknown-key' }, 'key_not_found'],
  ])(
    'rejects an NRAS token with untrusted signing metadata %p',
    async (header, reason) => {
      mockNrasResponse([['JWT', createNrasJwt(nrasClaims(), header)]]);
      await expect(
        verifyModelAttestation({
          attestation: createModelAttestation({
            nvidiaPayload: JSON.stringify({ nonce }),
          }),
          clientBinding: { nonce },
          verifiers: { quote: quoteVerifier },
        }),
      ).rejects.toMatchObject({
        failure: { code: 'gpu.jwt_verification_failed', details: { reason } },
      });
    },
  );

  test('rejects model report data that contradicts the verified quote', async () => {
    await expect(
      verifyModelAttestation({
        attestation: createModelAttestation({
          reportedQuoteData: 'ff'.repeat(64),
        }),
        clientBinding: { nonce },
        verifiers: { quote: quoteVerifier },
      }),
    ).rejects.toMatchObject({
      failure: {
        code: 'binding.report_data_mismatch',
        details: { source: 'reportedQuoteData' },
      },
    });
  });

  test('passes raw measured configuration to a deployment verifier', async () => {
    const osImageEvent = createRuntimeEvent('os-image-hash', 'cafe');
    const composeEvent = createRuntimeEvent('compose-hash', 'beef');
    const quote = createQuoteForEventLog([osImageEvent, composeEvent]);
    const verifiedDeployments: MeasuredDeployment[] = [];

    async function verifyDeployment(
      deployment: MeasuredDeployment,
    ): Promise<void> {
      verifiedDeployments.push(deployment);
    }

    const result = await verifyModelAttestation({
      attestation: createModelAttestation({
        eventLog: [osImageEvent, composeEvent],
      }),
      clientBinding: { nonce },
      verifiers: { quote: async () => quote, deployment: verifyDeployment },
    });

    expect(verifiedDeployments).toEqual([
      {
        appCompose,
        runtimeMeasurements: {
          osImageHash: 'cafe',
          composeHash: 'beef',
        },
      },
    ]);
    expect(result.deploymentProvenance).toBe('verified');
  });

  test('normalizes deployment verifier failures', async () => {
    await expect(
      verifyModelAttestation({
        attestation: createModelAttestation(),
        clientBinding: { nonce },
        verifiers: {
          quote: quoteVerifier,
          deployment: async () => {
            throw new Error('verifier implementation detail');
          },
        },
      }),
    ).rejects.toMatchObject({
      failure: { code: 'provenance.verification_failed' },
    });
  });
});

function mockNrasOverallResult(result: boolean | string): void {
  mockNrasJwtPayload(nrasClaims({ 'x-nvidia-overall-att-result': result }));
}

function nrasClaims(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  const now = Math.floor(Date.now() / 1000);
  return {
    iss: 'https://nras.attestation.nvidia.com',
    exp: now + 3600,
    nbf: now - 60,
    iat: now - 60,
    eat_nonce: nonce,
    'x-nvidia-overall-att-result': true,
    ...overrides,
  };
}

function mockNrasJwtPayload(payload: unknown): void {
  mockNrasResponse([['JWT', createNrasJwt(payload)]]);
}

function createNrasJwt(
  payload: unknown,
  protectedHeader = { alg: 'ES384', kid: 'test-nras' },
): string {
  const header = Buffer.from(JSON.stringify(protectedHeader)).toString(
    'base64url',
  );
  const encodedPayload = Buffer.from(JSON.stringify(payload)).toString(
    'base64url',
  );
  const signingInput = `${header}.${encodedPayload}`;
  const signature = sign('sha384', Buffer.from(signingInput), {
    key: NRAS_KEYS.privateKey,
    dsaEncoding: 'ieee-p1363',
  });
  return `${signingInput}.${signature.toString('base64url')}`;
}

function mockNrasResponse(body: unknown): void {
  jest
    .spyOn(globalThis, 'fetch')
    .mockImplementation(
      async (url) =>
        new Response(
          JSON.stringify(
            String(url).endsWith('/.well-known/jwks.json') ? NRAS_JWKS : body,
          ),
          { status: 200 },
        ),
    );
}
