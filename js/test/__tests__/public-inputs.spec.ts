import * as v from 'valibot';
import {
  isVerificationError,
  verifyGatewayAttestation,
  verifyGatewayResponse,
  verifyModelAttestation,
  verifyModelResponse,
} from '../../src';
import {
  createModelAttestation,
  createQuote,
  nonce,
  tlsFingerprint,
} from '../fixtures';

const invalidInput = {} as never;
const inputFailure = {
  failure: {
    phase: 'input',
    code: 'input.invalid',
  },
};

describe('public input validation', () => {
  test('returns structured errors for malformed attestation inputs', async () => {
    await expectSdkVerificationFailure(
      verifyModelAttestation(invalidInput),
      inputFailure,
    );
    await expect(verifyGatewayAttestation(invalidInput)).rejects.toMatchObject(
      inputFailure,
    );
  });

  test('returns structured errors for malformed response inputs', () => {
    expectInputFailure(() => verifyModelResponse(invalidInput));
    expectInputFailure(() => verifyGatewayResponse(invalidInput));
  });

  test('rejects misspelled verification options instead of applying defaults', async () => {
    await expect(
      verifyModelAttestation({
        attestation: createModelAttestation(),
        nonce,
        polciy: { gpuEvidence: 'required' },
      } as never),
    ).rejects.toMatchObject({
      failure: {
        phase: 'input',
        code: 'input.invalid',
        details: { field: 'input.polciy', reason: 'unsupported_value' },
      },
    });

    await expect(
      verifyModelAttestation({
        attestation: createModelAttestation(),
        nonce,
        policy: { gpuEvidnce: 'required' },
      } as never),
    ).rejects.toMatchObject({
      failure: {
        phase: 'input',
        code: 'input.invalid',
        details: { field: 'policy.gpuEvidnce', reason: 'unsupported_value' },
      },
    });

    await expect(
      verifyGatewayAttestation({
        attestation: {
          ...createModelAttestation(),
          reportedQuoteData: '00'.repeat(64),
        },
        nonce,
        peerSpkiFingerprint: tlsFingerprint,
        verifiers: { deploymnt: async () => undefined },
      } as never),
    ).rejects.toMatchObject({
      failure: {
        phase: 'input',
        code: 'input.invalid',
        details: { field: 'verifiers.deploymnt', reason: 'unsupported_value' },
      },
    });
  });

  test('rejects malformed policy and verifier bags before quote verification', async () => {
    const quote = jest.fn(async () => {
      throw new Error('quote verifier should not run');
    });

    await expect(
      verifyModelAttestation({
        attestation: createModelAttestation(),
        nonce,
        policy: true,
        verifiers: { quote },
      } as never),
    ).rejects.toMatchObject({
      failure: {
        phase: 'input',
        code: 'input.invalid',
        details: { field: 'policy', reason: 'unsupported_value' },
      },
    });
    expect(quote).not.toHaveBeenCalled();

    await expect(
      verifyModelAttestation({
        attestation: createModelAttestation(),
        nonce,
        verifiers: null,
      } as never),
    ).rejects.toMatchObject({
      failure: {
        phase: 'input',
        code: 'input.invalid',
        details: { field: 'verifiers', reason: 'unsupported_value' },
      },
    });
  });

  test('rejects unknown fields in normalized attestation input', async () => {
    await expect(
      verifyModelAttestation({
        attestation: {
          ...createModelAttestation(),
          appComose: '{}',
        },
        nonce,
      } as never),
    ).rejects.toMatchObject({
      failure: {
        phase: 'input',
        code: 'input.invalid',
        details: {
          field: 'attestation.appComose',
          reason: 'unsupported_value',
        },
      },
    });
  });

  test('accepts synchronous verifier callbacks', async () => {
    const result = await verifyModelAttestation({
      attestation: createModelAttestation({
        nvidiaPayload: JSON.stringify({ nonce }),
      }),
      nonce,
      verifiers: {
        quote: () => createQuote(),
        deployment: () => undefined,
        nvidia: () => undefined,
      },
    });

    expect(result).toMatchObject({
      deploymentProvenance: 'verified',
      gpuEvidence: 'verified',
    });
  });

  test('normalizes an invalid custom quote result into the SDK error contract', async () => {
    await expectSdkVerificationFailure(
      verifyModelAttestation({
        attestation: createModelAttestation(),
        nonce,
        verifiers: { quote: () => ({}) as never },
      }),
      {
        failure: {
          phase: 'quote',
          code: 'quote.invalid_result',
        },
      },
    );
  });

  test('rejects an array disguised as a custom quote result', async () => {
    const arrayQuote = Object.assign([], createQuote());

    await expectSdkVerificationFailure(
      verifyModelAttestation({
        attestation: createModelAttestation(),
        nonce,
        verifiers: { quote: () => arrayQuote as never },
      }),
      {
        failure: {
          phase: 'quote',
          code: 'quote.invalid_result',
        },
      },
    );
  });
});

function expectInputFailure(action: () => void): void {
  try {
    action();
  } catch (error) {
    expect(error).toMatchObject(inputFailure);
    return;
  }
  throw new Error('Expected verification to fail');
}

async function expectSdkVerificationFailure(
  action: Promise<unknown>,
  expected: object,
): Promise<void> {
  try {
    await action;
  } catch (error) {
    expect(v.isValiError(error)).toBe(false);
    expect(isVerificationError(error)).toBe(true);
    expect(error).toMatchObject(expected);
    return;
  }
  throw new Error('Expected verification to fail');
}
