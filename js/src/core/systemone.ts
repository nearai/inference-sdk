import * as v from 'valibot';
import { SystemOneResponseSchema } from '../schemas';
import type { VerifiedCompletionResult } from '../types/inference-client';
import type {
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
  VerifyCapturedCompletionParams,
} from './inference-client';

type CreateSystemOneParams = {
  readonly request: SystemOneRequest;
  readonly options?: SystemOneRequestOptions;
  readonly baseUrl: string;
  readonly encryptionEnabled: boolean;
  readonly headers: Headers;
  readonly getSession: (
    model: string,
  ) => Promise<InferenceSession<VerifiedCompletionResult>>;
  readonly registerResponse: (
    params: VerifyCapturedCompletionParams<VerifiedCompletionResult>,
  ) => void;
};

/** Send once and retain exact bytes for the client's ordinary verifyResponse API. */
export async function createSystemOne({
  request,
  options,
  baseUrl,
  encryptionEnabled,
  headers,
  getSession,
  registerResponse,
}: CreateSystemOneParams): Promise<SystemOneResult> {
  if (encryptionEnabled)
    throw invalidInput('System One requires e2ee: false and ohttp: false');
  if ('stream' in request)
    throw invalidInput('System One does not support streaming');
  options?.signal?.throwIfAborted();
  let body: string;
  try {
    body = JSON.stringify(request);
  } catch {
    throw invalidInput('a JSON-serializable System One request');
  }
  // Request business rules belong to the server. Select evidence using the
  // typed model field and preserve the serialized bytes for verification.
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
  const completionId = response.headers.get('x-generation-id');
  if (completionId === null || !/^[A-Za-z0-9_-]{1,255}$/.test(completionId)) {
    await response.body?.cancel();
    throw invalidResponse('System One X-Generation-Id');
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
    completionId,
    requestBody,
    responseBody: Promise.resolve(responseBody),
    session,
  });
  return { data, completionId };
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
