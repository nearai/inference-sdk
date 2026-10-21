import { readBoundedBody } from './body-limit';
import * as v from 'valibot';
import {
  CompletionResponseIdSchema,
  SystemOneResponseSchema,
} from '../schemas';
import type { VerifiedCompletionResult } from '../types/inference-client';
import type {
  SystemOneQuestions,
  SystemOneRequest,
  SystemOneRequestOptions,
  SystemOneResponse,
  SystemOneResult,
} from '../types/systemone';
import { ApiError, isApiError, isVerificationError } from '../utils/errors';
import { NO_ALIASING_HEADER } from './cloud-api';
import { removeE2eeHeaders } from './e2ee-request';
import type {
  InferenceSession,
  VerifyCapturedResponseParams,
} from './inference-client';

type CreateSystemOneParams<
  Questions extends object & SystemOneQuestions<Questions>,
> = {
  readonly request: SystemOneRequest<Questions>;
  readonly options?: SystemOneRequestOptions;
  readonly baseUrl: string;
  readonly encryptionEnabled: boolean;
  readonly responseByteLimit: (requestSize: number) => number;
  readonly headers: Headers;
  readonly getSession: (
    model: string,
  ) => Promise<InferenceSession<VerifiedCompletionResult>>;
  readonly registerResponse: (
    params: VerifyCapturedResponseParams<VerifiedCompletionResult>,
  ) => void;
};

/** Send once and retain exact bytes for the client's ordinary verifyResponse API. */
export async function createSystemOne<
  Questions extends object & SystemOneQuestions<Questions>,
>({
  request,
  options,
  baseUrl,
  encryptionEnabled,
  responseByteLimit,
  headers,
  getSession,
  registerResponse,
}: CreateSystemOneParams<Questions>): Promise<SystemOneResult> {
  if (encryptionEnabled)
    throw invalidInput('System One requires e2ee: false and ohttp: false');
  if ('stream' in request)
    throw invalidInput('System One does not support streaming');
  options?.signal?.throwIfAborted();
  const body = JSON.stringify(request);
  const requestBody = new TextEncoder().encode(body);
  const responseLimit = responseByteLimit(requestBody.byteLength);
  const session = await getSession(request.model);
  options?.signal?.throwIfAborted();
  removeE2eeHeaders(headers);
  // These headers must describe the generated JSON, not a caller's old body.
  for (const name of [
    'content-length',
    'content-encoding',
    'transfer-encoding',
    'trailer',
    'content-md5',
    'digest',
    'content-digest',
    'repr-digest',
  ])
    headers.delete(name);
  headers.set(NO_ALIASING_HEADER, 'true');
  headers.set('content-type', 'application/json');
  headers.set('accept', 'application/json');
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
    options?.signal?.throwIfAborted();
    if (isApiError(cause) || isVerificationError(cause)) throw cause;
    throw new ApiError(
      {
        code: 'api.inference_transport_failed',
        details: { resource: 'completion', reason: 'request' },
        retryable: false,
      },
      { cause },
    );
  }
  if (!response.ok) {
    // Error bodies may contain private state; do not retain them.
    await discardResponse(response);
    throw new ApiError({
      code: 'api.http_status',
      details: { resource: 'completion', status: response.status },
      retryable: false,
    });
  }
  const parsedId = v.safeParse(CompletionResponseIdSchema, {
    id: response.headers.get('x-generation-id'),
  });
  if (!parsedId.success) {
    await discardResponse(response);
    throw invalidResponse('System One X-Generation-Id');
  }
  const decisionId = parsedId.output.id;
  let responseBody: Uint8Array;
  try {
    responseBody = await readBoundedBody(
      response.body,
      responseLimit,
      options?.signal,
    );
  } catch (cause) {
    options?.signal?.throwIfAborted();
    if (isApiError(cause)) throw cause;
    throw new ApiError(
      {
        code: 'api.inference_transport_failed',
        details: { resource: 'completion', reason: 'response_body' },
        retryable: false,
      },
      { cause },
    );
  }
  let data: SystemOneResponse;
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
  registerResponse({
    id: decisionId,
    requestBody,
    responseBody: Promise.resolve(responseBody),
    session,
  });
  return { data, decisionId };
}

async function discardResponse(response: Response): Promise<void> {
  try {
    await response.body?.cancel();
  } catch {
    // Cleanup must not replace the classified HTTP/response error.
  }
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
