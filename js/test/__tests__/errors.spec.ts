import { ApiError, isVerificationError, VerificationError } from '../../src';

describe('verification errors', () => {
  test('exposes a stable discriminated failure instead of requiring message parsing', () => {
    const cause = new Error('internal detail');
    const error = new VerificationError(
      {
        phase: 'policy',
        code: 'policy.tcb_status_not_allowed',
        details: {
          actual: 'Revoked',
          accepted: ['UpToDate', 'OutOfDate'],
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
          accepted: ['UpToDate', 'OutOfDate'],
        },
      },
    });
    expect(error.cause).toBe(cause);
    if (error.failure.code !== 'policy.tcb_status_not_allowed') {
      throw new Error('Expected a TCB policy failure');
    }
    expect(error.failure.details.actual).toBe('Revoked');
    expect(error.failure.details.accepted).toEqual(['UpToDate', 'OutOfDate']);
    expect(error.toJSON()).toMatchObject({
      name: 'VerificationError',
      failure: error.failure,
      retryable: false,
    });
    expect(error.toJSON()).not.toHaveProperty('cause');
  });

  test('retains HTTP status as structured Cloud API context', () => {
    const error = new ApiError({
      phase: 'api',
      code: 'api.http_status',
      details: { resource: 'model_attestation', status: 503 },
      retryable: true,
    });

    expect(error).toMatchObject({
      code: 'api.http_status',
      phase: 'api',
      status: 503,
      retryable: true,
      failure: { details: { resource: 'model_attestation', status: 503 } },
    });
  });
});
