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
      { expected: 'plain object' },
    );
  }

  let descriptors: Record<string, PropertyDescriptor>;
  try {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError('non-plain object');
    }
    descriptors = Object.getOwnPropertyDescriptors(value);
  } catch {
    throw inputError(field, 'unsupported_value', { expected: 'plain object' });
  }

  const snapshot: Record<string, unknown> = Object.create(null) as Record<
    string,
    unknown
  >;
  for (const key of Object.keys(descriptors)) {
    const descriptor = descriptors[key];
    if (!descriptor.enumerable) {
      continue;
    }
    if (!('value' in descriptor)) {
      throw inputError(`${field}.${key}`, 'unsupported_value', {
        expected: 'data property',
      });
    }
    snapshot[key] = descriptor.value;
  }
  return snapshot;
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
  let descriptors: Record<string, PropertyDescriptor>;
  try {
    if (!Array.isArray(value)) {
      throw new TypeError('not an array');
    }
    descriptors = Object.getOwnPropertyDescriptors(value);
  } catch {
    throw inputError(
      field,
      value === undefined ? 'missing' : 'unsupported_value',
      { expected: 'array' },
    );
  }

  const length = descriptors.length?.value;
  if (
    typeof length !== 'number' ||
    !Number.isSafeInteger(length) ||
    length < 0
  ) {
    throw inputError(field, 'unsupported_value', { expected: 'array' });
  }

  const snapshot: unknown[] = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (descriptor === undefined) {
      // Preserve a sparse slot as an explicit undefined value so a later
      // element validator rejects it rather than skipping it via Array#map.
      snapshot.push(undefined);
      continue;
    }
    if (!('value' in descriptor)) {
      throw inputError(`${field}.${index}`, 'unsupported_value', {
        expected: 'data property',
      });
    }
    snapshot.push(descriptor.value);
  }
  return snapshot;
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
