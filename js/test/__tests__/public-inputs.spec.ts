import {
  verifyGatewayAttestation,
  verifyGatewayResponse,
  verifyModelAttestation,
  verifyModelResponse,
} from '../../src';
import { createModelAttestation, nonce, tlsFingerprint } from '../fixtures';

const invalidInput = {} as never;
const inputFailure = {
  failure: {
    phase: 'input',
    code: 'input.invalid',
  },
};

describe('public input validation', () => {
  test('returns structured errors for malformed attestation inputs', async () => {
    await expect(verifyModelAttestation(invalidInput)).rejects.toMatchObject(
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
