import type { VerificationFailure } from './errors';
import { VerificationError } from './errors';

type InputFailure = Extract<VerificationFailure, { code: 'input.invalid' }>;
type InputReason = InputFailure['details']['reason'];
type InputErrorDetails = Omit<InputFailure['details'], 'field' | 'reason'>;

export function requireInputObject(
  value: unknown,
  field: string,
): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw inputError(
      field,
      value === undefined ? 'missing' : 'unsupported_value',
      { expected: 'object' },
    );
  }

  return { ...value };
}

export function requireInputString(value: unknown, field: string): string {
  if (typeof value === 'string') {
    return value;
  }
  throw inputError(
    field,
    value === undefined ? 'missing' : 'unsupported_value',
    { expected: 'string' },
  );
}

export function optionalInputString(
  value: unknown,
  field: string,
): string | undefined {
  return value === undefined ? undefined : requireInputString(value, field);
}

export function requireInputFunction(
  value: unknown,
  field: string,
): (...args: never[]) => unknown {
  if (typeof value === 'function') {
    return value as (...args: never[]) => unknown;
  }
  throw inputError(
    field,
    value === undefined ? 'missing' : 'unsupported_value',
    { expected: 'function' },
  );
}

export function optionalInputFunction(
  value: unknown,
  field: string,
): ((...args: never[]) => unknown) | undefined {
  return value === undefined ? undefined : requireInputFunction(value, field);
}

export function requireInputBytes(value: unknown, field: string): Uint8Array {
  if (value instanceof Uint8Array) {
    return value;
  }
  throw inputError(
    field,
    value === undefined ? 'missing' : 'unsupported_value',
    { expected: 'Uint8Array' },
  );
}

export function requireInputArray(
  value: unknown,
  field: string,
): readonly unknown[] {
  if (!Array.isArray(value)) {
    throw inputError(
      field,
      value === undefined ? 'missing' : 'unsupported_value',
      { expected: 'array' },
    );
  }

  return value;
}

/** Reject misspelled security options instead of silently weakening a policy. */
export function rejectUnknownInputKeys(
  value: Record<string, unknown>,
  field: string,
  allowed: readonly string[],
): void {
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) {
      throw inputError(`${field}.${key}`, 'unsupported_value', {
        expected: `one of: ${allowed.join(', ')}`,
      });
    }
  }
}

/** Create the SDK's single structured error shape for invalid public input. */
export function inputError(
  field: string,
  reason: InputReason,
  details: InputErrorDetails = {},
): VerificationError {
  return new VerificationError({
    phase: 'input',
    code: 'input.invalid',
    details: { field, reason, ...details },
  });
}
