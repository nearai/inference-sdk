import * as v from 'valibot';
import type { SigningAlgo } from '../types/attestation-common';
import type { VerifiedCompletionResult } from '../types/inference-client';
import type {
  SystemOneRequest,
  SystemOneRequestOptions,
  SystemOneResult,
} from '../types/systemone';
import { ApiError, isApiError, isVerificationError } from '../utils/errors';
import { NO_ALIASING_HEADER } from './cloud-api';
import { removeE2eeHeaders } from './e2ee-request';
import type { InferenceSession } from './inference-client';

const content = v.union([
  v.string(),
  v.record(v.string(), v.unknown()),
  v.array(v.unknown()),
]);
const instructions = v.optional(content);
const probability = v.pipe(v.number(), v.minValue(0), v.maxValue(1));
const probabilities = v.record(v.string(), probability);
const question = v.variant('type', [
  v.strictObject({
    type: v.literal('noul'),
    instructions,
    criteria: v.optional(
      v.strictObject({ true: v.optional(content), false: v.optional(content) }),
    ),
  }),
  v.strictObject({
    type: v.literal('choice'),
    instructions,
    criteria: v.pipe(
      v.record(v.string(), v.nullable(content)),
      v.minEntries(1),
      v.maxEntries(255),
    ),
  }),
  v.strictObject({
    type: v.literal('score'),
    instructions,
    criteria: v.pipe(v.array(content), v.minLength(1), v.maxLength(10)),
  }),
]);

export const SystemOneRequestSchema = v.strictObject({
  model: v.pipe(
    v.string(),
    v.check((value) => value.trim().length > 0),
  ),
  state: content,
  questions: v.pipe(v.record(v.string(), question), v.minEntries(1)),
});

export const SystemOneResponseSchema = v.looseObject({
  id: v.optional(v.nullable(v.string())),
  model: v.pipe(v.string(), v.minLength(1)),
  answers: v.record(
    v.string(),
    v.variant('type', [
      v.looseObject({ type: v.literal('noul'), noul: probability }),
      v.looseObject({
        type: v.literal('choice'),
        choice: v.string(),
        confidence: probability,
        probabilities,
      }),
      v.looseObject({
        type: v.literal('score'),
        score: v.pipe(v.number(), v.finite()),
        confidence: probability,
        probabilities,
        legend: v.record(v.string(), content),
      }),
    ]),
  ),
  usage: v.looseObject({
    input_tokens: v.pipe(
      v.number(),
      v.integer(),
      v.minValue(0),
      v.maxValue(2147483647),
    ),
    output_tokens: v.pipe(
      v.number(),
      v.integer(),
      v.minValue(0),
      v.maxValue(2147483647),
    ),
  }),
});

type CreateSystemOneParams = {
  readonly request: SystemOneRequest;
  readonly options?: SystemOneRequestOptions;
  readonly baseUrl: string;
  readonly signingAlgo: SigningAlgo;
  readonly encryptionEnabled: boolean;
  readonly headers: Headers;
  readonly createSession: (
    model: string,
  ) => Promise<InferenceSession<VerifiedCompletionResult>>;
};

/** One inference attempt. Signature lookups may be retried without repeating inference. */
export async function createSystemOne({
  request,
  options,
  baseUrl,
  signingAlgo,
  encryptionEnabled,
  headers,
  createSession,
}: CreateSystemOneParams): Promise<SystemOneResult> {
  if (encryptionEnabled)
    throw invalidInput('System One requires e2ee: false and ohttp: false');
  // Validate the serialized wire body as well as its shape; toJSON cannot change
  // the model after the evidence has been selected.
  let body: string;
  let parsed: SystemOneRequest;
  try {
    body = JSON.stringify(request);
    parsed = v.parse(SystemOneRequestSchema, JSON.parse(body));
  } catch {
    throw invalidInput(
      'a System One request with model, state, and typed questions (no stream)',
    );
  }
  options?.signal?.throwIfAborted();
  const session = await createSession(parsed.model);
  options?.signal?.throwIfAborted();
  removeE2eeHeaders(headers);
  headers.set(NO_ALIASING_HEADER, 'true');
  headers.set('content-type', 'application/json');
  headers.set('accept', 'application/json');
  const requestBody = new TextEncoder().encode(body);
  const httpRequest = new Request(new URL('systemone', baseUrl), {
    method: 'POST',
    headers,
    body,
    signal: options?.signal,
  });
  let response: Response;
  try {
    response = await session.transport.fetch(httpRequest);
  } catch (cause) {
    if (isApiError(cause) || isVerificationError(cause)) throw cause;
    throw new ApiError(
      {
        code: 'api.transport_failed',
        details: { resource: 'completion', reason: 'request' },
        retryable: false,
      },
      { cause },
    );
  }
  if (!response.ok) {
    // Error bodies may contain private state; do not retain them.
    await response.body?.cancel();
    throw new ApiError({
      code: 'api.http_status',
      details: { resource: 'completion', status: response.status },
      retryable: false,
    });
  }
  const signatureId = response.headers.get('x-signature-id');
  if (signatureId === null || !/^[A-Za-z0-9_-]{1,255}$/.test(signatureId)) {
    await response.body?.cancel();
    throw invalidResponse('System One X-Signature-Id');
  }
  let responseBody: Uint8Array;
  try {
    responseBody = new Uint8Array(await response.arrayBuffer());
  } catch (cause) {
    throw new ApiError(
      {
        code: 'api.transport_failed',
        details: { resource: 'completion', reason: 'response_body' },
        retryable: false,
      },
      { cause },
    );
  }
  let data: v.InferOutput<typeof SystemOneResponseSchema>;
  try {
    data = v.parse(
      SystemOneResponseSchema,
      JSON.parse(
        new TextDecoder('utf-8', { fatal: true }).decode(responseBody),
      ),
    );
  } catch {
    throw invalidResponse('System One response');
  }
  if (
    data.usage.input_tokens + data.usage.output_tokens > 2147483647 ||
    !sameKeys(Object.keys(parsed.questions), Object.keys(data.answers))
  )
    throw invalidResponse('System One answers or usage');
  for (const [name, question] of Object.entries(parsed.questions)) {
    const answer = data.answers[name];
    if (question.type !== answer.type)
      throw invalidResponse('System One answer type');
    if (
      question.type === 'choice' &&
      answer.type === 'choice' &&
      (!Object.hasOwn(question.criteria, answer.choice) ||
        !sameKeys(
          Object.keys(question.criteria),
          Object.keys(answer.probabilities),
        ))
    )
      throw invalidResponse('System One choice');
    if (question.type === 'score' && answer.type === 'score') {
      const levels = question.criteria.map((_, index) => String(index));
      if (
        answer.score < 0 ||
        answer.score > levels.length - 1 ||
        !sameKeys(levels, Object.keys(answer.probabilities)) ||
        !sameKeys(levels, Object.keys(answer.legend))
      )
        throw invalidResponse('System One score');
    }
  }
  let verification: Promise<VerifiedCompletionResult> | undefined;
  return {
    data,
    signatureId,
    verify: () => {
      verification ??= (async () => {
        const signature = await session.transport.fetchCompletionSignature({
          completionId: signatureId,
          signingAlgo,
        });
        return session.verifyResponse({
          completionId: signatureId,
          requestBody,
          responseBody,
          signature,
        });
      })().catch((cause: unknown) => {
        if (isApiError(cause) && cause.retryable) verification = undefined;
        throw cause;
      });
      return verification;
    },
  };
}

function sameKeys(left: string[], right: string[]): boolean {
  return (
    left.length === right.length && left.every((key) => right.includes(key))
  );
}
function invalidInput(expected: string): ApiError {
  return new ApiError({
    code: 'api.invalid_input',
    details: { field: 'systemone', reason: 'unsupported_value', expected },
  });
}
function invalidResponse(path: string): ApiError {
  return new ApiError({
    code: 'api.invalid_response',
    details: {
      path,
      expected: 'a valid System One response and receipt ID',
      actual: 'missing or invalid',
    },
  });
}
