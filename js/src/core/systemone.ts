import * as v from 'valibot';
import {
  ChatCompletionRequestSchema,
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
import { readBoundedBody } from './body-limit';
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

type SendSystemOneParams = {
  readonly request: Request;
  readonly responseByteLimit: (requestSize: number) => number;
  readonly encryptionEnabled: boolean;
  readonly headers: Headers;
  readonly getSession: (
    model: string,
  ) => Promise<InferenceSession<VerifiedCompletionResult>>;
  readonly registerResponse: (
    params: VerifyCapturedResponseParams<VerifiedCompletionResult>,
  ) => void;
};

/** Preserve the official SDK's wire format and let it parse the response. */
export async function sendSystemOne(
  params: SendSystemOneParams,
): Promise<Response> {
  const captured = await captureSystemOne(params);
  params.registerResponse(captured.record);
  return captured.response;
}

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
  headers.set('content-type', 'application/json');
  const httpRequest = new Request(new URL('systemone', baseUrl), {
    method: 'POST',
    headers,
    body,
    signal: options?.signal,
  });
  const captured = await captureSystemOne({
    request: httpRequest,
    responseByteLimit,
    encryptionEnabled,
    headers,
    getSession,
    registerResponse,
  });
  let data: SystemOneResponse;
  try {
    data = v.parse(
      SystemOneResponseSchema,
      JSON.parse(
        new TextDecoder('utf-8', { fatal: true }).decode(
          await captured.response.arrayBuffer(),
        ),
      ),
    );
  } catch {
    throw invalidResponse('System One response');
  }
  registerResponse(captured.record);
  return { data, decisionId: captured.record.id };
}

async function captureSystemOne({
  request,
  responseByteLimit,
  encryptionEnabled,
  headers,
  getSession,
}: SendSystemOneParams): Promise<{
  response: Response;
  record: VerifyCapturedResponseParams<VerifiedCompletionResult>;
}> {
  if (encryptionEnabled)
    throw invalidInput('System One requires e2ee: false and ohttp: false');
  request.signal.throwIfAborted();
  const encoding = headers.get('content-encoding')?.trim().toLowerCase();
  const contentType = headers
    .get('content-type')
    ?.split(';')[0]
    .trim()
    .toLowerCase();
  if (
    (encoding && encoding !== 'identity') ||
    contentType !== 'application/json'
  )
    throw invalidInput('an uncompressed JSON System One request');
  const requestBody = await readBoundedBody(
    request.body,
    responseByteLimit(0),
    request.signal,
  );
  const responseLimit = responseByteLimit(requestBody.byteLength);
  let parsed: unknown;
  try {
    parsed = JSON.parse(
      new TextDecoder('utf-8', { fatal: true }).decode(requestBody),
    );
  } catch {
    throw invalidInput('a JSON System One request with a non-empty model');
  }
  const result = v.safeParse(ChatCompletionRequestSchema, parsed);
  if (!result.success)
    throw invalidInput('a JSON System One request with a non-empty model');
  if ('stream' in result.output)
    throw invalidInput('System One does not support streaming');
  const session = await getSession(result.output.model);
  request.signal.throwIfAborted();
  removeE2eeHeaders(headers);
  if (session.modelKey !== undefined)
    headers.set('x-model-pub-key', session.modelKey.publicKey);
  for (const name of ['content-length', 'transfer-encoding', 'trailer'])
    headers.delete(name);
  headers.set(NO_ALIASING_HEADER, 'true');
  headers.set('accept', 'application/json');
  headers.set('accept-encoding', 'identity');
  const httpRequest = new Request(request.url, {
    method: 'POST',
    headers,
    body: requestBody,
    signal: request.signal,
  });
  let response: Response;
  try {
    response = await session.transport.fetch(httpRequest);
  } catch (cause) {
    request.signal.throwIfAborted();
    if (isApiError(cause) || isVerificationError(cause)) throw cause;
    throw new ApiError(
      {
        code: 'api.transport_failed',
        details: { resource: 'systemone', reason: 'request' },
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
      details: { resource: 'systemone', status: response.status },
      retryable: false,
    });
  }
  if (
    response.headers
      .get('content-encoding')
      ?.split(',')
      .some((value) => !['', 'identity'].includes(value.trim().toLowerCase()))
  ) {
    await discardResponse(response);
    throw invalidResponse('System One response content-encoding');
  }
  const parsedId = v.safeParse(CompletionResponseIdSchema, {
    id: response.headers.get('x-generation-id'),
  });
  if (!parsedId.success) {
    await discardResponse(response);
    throw invalidResponse('System One X-Generation-Id');
  }
  const decisionId = parsedId.output.id;
  let responseBody: Uint8Array<ArrayBuffer>;
  try {
    responseBody = await readBoundedBody(
      response.body,
      responseLimit,
      request.signal,
    );
  } catch (cause) {
    request.signal.throwIfAborted();
    if (isApiError(cause)) throw cause;
    throw new ApiError(
      {
        code: 'api.transport_failed',
        details: { resource: 'systemone', reason: 'response_body' },
        retryable: false,
      },
      { cause },
    );
  }
  return {
    response: new Response(responseBody, {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers,
    }),
    record: {
      id: decisionId,
      requestBody,
      responseBody: Promise.resolve(responseBody),
      session,
    },
  };
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
