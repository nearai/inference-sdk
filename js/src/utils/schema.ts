import * as v from 'valibot';
import { ApiError, VerificationError } from './errors';
import { inputError } from './input';

type ValidationIssue = v.BaseIssue<unknown>;
export type ValidationSchema = v.BaseSchema<unknown, unknown, ValidationIssue>;
export type SchemaOutput<TSchema extends ValidationSchema> =
  v.InferOutput<TSchema>;

/**
 * Parse an SDK-owned public input without exposing Valibot's error type.
 * Strict schemas reject unknown option names before any verification runs.
 */
export function parsePublicInput<TSchema extends ValidationSchema>(
  schema: TSchema,
  value: unknown,
  root: string,
): SchemaOutput<TSchema> {
  const result = safeParse(schema, value);
  if (result.success) {
    return result.output;
  }

  if ('cause' in result) {
    throw new VerificationError(
      {
        phase: 'input',
        code: 'input.invalid',
        details: {
          field: root,
          reason: 'unsupported_value',
          expected: 'a readable value matching the documented input shape',
        },
      },
      { cause: result.cause },
    );
  }

  const issue = selectIssue(result.issues);
  throw inputError(
    inputField(issue, root),
    issue.input === undefined && issue.expected !== 'never'
      ? 'missing'
      : 'unsupported_value',
    { expected: describeExpected(issue.expected) },
  );
}

/**
 * Parse an untrusted HTTP response without exposing Valibot's error type.
 * Wire schemas deliberately accept extra server fields for forward compatibility.
 */
export function parseApiResponse<TSchema extends ValidationSchema>(
  schema: TSchema,
  value: unknown,
  root: string,
): SchemaOutput<TSchema> {
  const result = safeParse(schema, value);
  if (result.success) {
    return result.output;
  }

  if ('cause' in result) {
    throw new ApiError(
      {
        phase: 'api',
        code: 'api.invalid_response',
        details: {
          path: root,
          expected: 'a readable value matching the documented response shape',
          actual: describeValue(value),
        },
      },
      { cause: result.cause },
    );
  }

  const issue = selectIssue(result.issues);
  throw new ApiError({
    phase: 'api',
    code: 'api.invalid_response',
    details: {
      path: apiPath(issue, root),
      expected: describeExpected(issue.expected),
      actual: describeValue(issue.input),
    },
  });
}

/**
 * Attempt an explicitly optional wire-response shape. The caller must still
 * parse the alternative shape with `parseApiResponse` if this returns
 * `undefined`; no Valibot error escapes either path.
 */
export function tryParse<TSchema extends ValidationSchema>(
  schema: TSchema,
  value: unknown,
): SchemaOutput<TSchema> | undefined {
  const result = safeParse(schema, value);
  return result.success ? result.output : undefined;
}

/** Parse a custom quote-adapter result into the SDK's quote error contract. */
export function parseQuoteResult<TSchema extends ValidationSchema>(
  schema: TSchema,
  value: unknown,
): SchemaOutput<TSchema> {
  const result = safeParse(schema, value);
  if (result.success) {
    return result.output;
  }

  if ('cause' in result) {
    throw new VerificationError(
      {
        phase: 'quote',
        code: 'quote.invalid_result',
        details: {
          path: 'quote',
          expected:
            'a readable value matching the documented quote result shape',
          actual: describeValue(value),
        },
      },
      { cause: result.cause },
    );
  }

  const issue = selectIssue(result.issues);
  throw new VerificationError({
    phase: 'quote',
    code: 'quote.invalid_result',
    details: {
      path: apiPath(issue, 'quote'),
      expected: describeExpected(issue.expected),
      actual: describeValue(issue.input),
    },
  });
}

type SafeValidationResult<TSchema extends ValidationSchema> =
  | { success: true; output: SchemaOutput<TSchema> }
  | { success: false; issues: readonly ValidationIssue[] }
  | { success: false; cause: unknown };

function safeParse<TSchema extends ValidationSchema>(
  schema: TSchema,
  value: unknown,
): SafeValidationResult<TSchema> {
  try {
    const result = v.safeParse(schema, value);
    if (result.success) {
      return { success: true, output: result.output };
    }
    return { success: false, issues: result.issues };
  } catch (cause) {
    // `safeParse` normally represents schema failures as issues. This branch
    // protects the SDK boundary from exceptional values such as throwing
    // property accessors, and lets each caller choose its public error code.
    return { success: false, cause };
  }
}

function selectIssue(issues: readonly ValidationIssue[]): ValidationIssue {
  return (
    issues.find(
      (issue) => issue.type === 'strict_object' && issue.expected === 'never',
    ) ?? issues[0]
  );
}

function inputField(issue: ValidationIssue, root: string): string {
  const path = v.getDotPath(issue);
  if (!path) {
    return root;
  }
  if (
    issue.type === 'strict_object' &&
    issue.expected === 'never' &&
    !path.includes('.')
  ) {
    return `${root}.${path}`;
  }
  return path;
}

function apiPath(issue: ValidationIssue, root: string): string {
  const path = v.getDotPath(issue);
  if (!path) {
    return root;
  }
  return path.startsWith('[') ? `${root}${path}` : `${root}.${path}`;
}

function describeExpected(expected: string | null): string {
  if (expected === null) {
    return 'valid input';
  }
  switch (expected) {
    case 'Object':
      return 'object';
    case 'Array':
      return 'array';
    case 'string':
      return 'string';
    case 'boolean':
      return 'boolean';
    case 'Function':
      return 'function';
    default:
      return expected;
  }
}

function describeValue(value: unknown): string {
  try {
    if (value === null) {
      return 'null';
    }
    if (Array.isArray(value)) {
      return 'array';
    }
    return typeof value;
  } catch {
    return 'unreadable';
  }
}
