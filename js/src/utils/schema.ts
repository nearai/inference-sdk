import * as v from 'valibot';
import { ApiError, VerificationError } from './errors';

type ValidationIssue = v.BaseIssue<unknown>;
export type ValidationSchema = v.BaseSchema<unknown, unknown, ValidationIssue>;
export type SchemaOutput<TSchema extends ValidationSchema> =
  v.InferOutput<TSchema>;

/**
 * Parse an untrusted HTTP response without exposing Valibot's error type.
 * Wire schemas deliberately accept extra server fields for forward compatibility.
 */
export function parseApiResponse<TSchema extends ValidationSchema>(
  schema: TSchema,
  value: unknown,
  root: string,
): SchemaOutput<TSchema> {
  const result = v.safeParse(schema, value);
  if (result.success) {
    return result.output;
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
  const result = v.safeParse(schema, value);
  return result.success ? result.output : undefined;
}

/** Parse a custom quote-adapter result into the SDK's quote error contract. */
export function parseQuoteResult<TSchema extends ValidationSchema>(
  schema: TSchema,
  value: unknown,
): SchemaOutput<TSchema> {
  const result = v.safeParse(schema, value);
  if (result.success) {
    return result.output;
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

function selectIssue(issues: readonly ValidationIssue[]): ValidationIssue {
  return issues[0];
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
  if (value === null) {
    return 'null';
  }
  if (Array.isArray(value)) {
    return 'array';
  }
  return typeof value;
}
