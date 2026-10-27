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
import { NO_ALIASING_HEADER } from './cloud-api';
import { removeE2eeHeaders } from './e2ee-request';
import { normalizeSystemOneRequest } from './systemone-assets';
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
  readonly encryptionEnabled: boolean;
  readonly headers: Headers;
  readonly getSession: (
    model: string,
  ) => Promise<InferenceSession<VerifiedCompletionResult>>;
  readonly registerResponse: (
    params: VerifyCapturedResponseParams<VerifiedCompletionResult>,
  ) => void;
};

/** Adapt official SDK images and let it parse the unchanged response. */
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
    (contentType !== 'application/json' &&
      contentType !== 'multipart/form-data')
  )
    throw invalidInput('an uncompressed JSON or multipart System One request');
  const body = request.body?.pipeThrough(new TransformStream(), {
    signal: request.signal,
  });
  const { body: requestBody, parsed } = await normalizeSystemOneRequest(
    new Uint8Array(await new Response(body).arrayBuffer()),
    headers,
  );
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
    responseBody = new Uint8Array(await response.arrayBuffer());
  } catch (cause) {
    request.signal.throwIfAborted();
    throw new ApiError(
      {
        code: 'api.transport_failed',
        details: { resource: 'systemone', reason: 'response_body' },
        retryable: false,
      },
      { cause },
    );
  }
  // Fetch may retain compression headers after decoding the body.
  const responseHeaders = new Headers(response.headers);
  responseHeaders.delete('content-encoding');
  responseHeaders.delete('content-length');
  return {
    response: new Response(responseBody, {
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders,
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
