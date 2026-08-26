import {
  CloudApiError,
  isVerificationError,
  VerificationError,
} from '../../src';

describe('verification errors', () => {
  test('exposes a stable discriminated failure instead of requiring message parsing', () => {
    const cause = new Error('internal detail');
    const error = new VerificationError(
      {
        phase: 'policy',
        code: 'policy.tcb_status_not_allowed',
        details: {
          target: 'near_model',
          actual: 'Revoked',
          allowed: ['UpToDate', 'OutOfDate'],
          advisoryIds: ['INTEL-SA-00000'],
        },
      },
      { cause },
    );

    expect(isVerificationError(error)).toBe(true);
    expect(error).toMatchObject({
      code: 'policy.tcb_status_not_allowed',
      phase: 'policy',
      retryable: false,
      failure: {
        details: {
          actual: 'Revoked',
          allowed: ['UpToDate', 'OutOfDate'],
        },
      },
    });
    expect(error.cause).toBe(cause);
    if (error.failure.code !== 'policy.tcb_status_not_allowed') {
      throw new Error('Expected a TCB policy failure');
    }
    expect(error.failure.details.actual).toBe('Revoked');
    expect(error.toJSON()).toMatchObject({
      name: 'VerificationError',
      failure: error.failure,
      retryable: false,
    });
    expect(error.toJSON()).not.toHaveProperty('cause');
  });

  test('retains HTTP status as structured Cloud API context', () => {
    const error = new CloudApiError({
      phase: 'cloud_api',
      code: 'cloud_api.http_status',
      details: { operation: 'attestation report', status: 503 },
      retryable: true,
    });

    expect(error).toMatchObject({
      code: 'cloud_api.http_status',
      phase: 'cloud_api',
      status: 503,
      retryable: true,
      failure: { details: { operation: 'attestation report', status: 503 } },
    });
  });
});
