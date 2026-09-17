import * as v from 'valibot';
import { ChatCompletionRequestSchema } from '../schemas';
import type {
  PreparedE2eeChatRequest,
  PrepareE2eeChatRequestParams,
} from '../types/e2ee';
import type { SecureChatCompletionResponse } from '../types/inference-client';
import { ApiError } from '../utils/errors';
import { NO_ALIASING_HEADER } from './cloud-api';
import { createE2eeClientKeyPair, type E2eeClientKeyPair } from './e2ee';
import {
  createE2eeChatSseTransform,
  decryptE2eeChatResponse,
  encryptE2eeChatRequest,
  parseE2eeChatResponse,
} from './e2ee-chat';

type DecodeChatRequestParams = {
  readonly request: Request;
};

type DecryptE2eeResponseParams = {
  readonly response: Response;
  readonly clientKeyPair: E2eeClientKeyPair;
};

type AwaitWithAbortParams<T> = {
  readonly operation: Promise<T>;
  readonly signal: AbortSignal;
};

/**
 * Prepare one Chat Completions request using the supplied model E2EE key.
 *
 * Each call creates a fresh response key pair. The returned decryption
 * operation handles JSON and SSE without exposing the private key. Only
 * protocol-defined Chat fields are encrypted; other JSON is preserved.
 * The caller verifies the key's attestation before preparing the request.
 * This operation performs no network requests or completion-signature checks.
 */
export async function prepareE2eeChatRequest({
  request,
  modelKey,
}: PrepareE2eeChatRequestParams): Promise<PreparedE2eeChatRequest> {
  request.signal.throwIfAborted();
  if (request.method !== 'POST') {
    throw invalidInput({
      field: 'request',
      reason: 'unsupported_value',
      expected: 'a POST Chat Completions request',
      actual: request.method,
    });
  }
  const value = await decodeChatRequest({ request });
  const parsed = v.safeParse(ChatCompletionRequestSchema, value);
  if (!parsed.success) {
    throw invalidInput({
      field: 'request body',
      reason: 'unsupported_value',
      expected: 'a JSON Chat Completions request with a string model',
    });
  }
  request.signal.throwIfAborted();
  const clientKeyPair = createE2eeClientKeyPair(modelKey.signingAlgo);
  const encrypted = encryptE2eeChatRequest({ body: parsed.output, modelKey });
  const headers = new Headers(request.headers);
  headers.delete('content-length');
  headers.set('content-type', 'application/json');
  removeE2eeHeaders(headers);
  headers.set('x-signing-algo', modelKey.signingAlgo);
  headers.set('x-client-pub-key', clientKeyPair.publicKey);
  headers.set('x-model-pub-key', modelKey.publicKey);
  if (modelKey.signingAlgo === 'ed25519') {
    headers.set('x-encryption-version', '2');
  }
  headers.set(NO_ALIASING_HEADER, 'true');
  headers.set('x-encrypt-all-fields', 'true');

  return {
    request: new Request(request, {
      headers,
      body: JSON.stringify(encrypted.body),
    }),
    decryptResponse: (response) => decryptResponse({ response, clientKeyPair }),
  };
}

/** Internal Chat body reader shared by the public preparation and client paths. */
export async function decodeChatRequest({
  request,
}: DecodeChatRequestParams): Promise<unknown> {
  request.signal.throwIfAborted();
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
  const decoder = new TextDecoder();
  let text = '';
  try {
    reader = request.clone().body?.getReader();
    if (reader !== undefined) {
      while (true) {
        const chunk = await awaitWithAbort({
          operation: reader.read(),
          signal: request.signal,
        });
        if (chunk.done) break;
        text += decoder.decode(chunk.value, { stream: true });
      }
      text += decoder.decode();
    }
    return JSON.parse(text);
  } catch (cause) {
    if (request.signal.aborted) {
      // A cloned stream's cancellation may wait for the other branch. Preserve
      // the caller's abort immediately instead of awaiting that cancellation.
      void reader?.cancel(request.signal.reason).catch(() => undefined);
      throw request.signal.reason;
    }
    throw invalidInput(
      {
        field: 'request body',
        reason: 'invalid_json',
        expected: 'a JSON Chat Completions request',
      },
      cause,
    );
  } finally {
    reader?.releaseLock();
  }
}

export function isServerSentEventResponse(response: Response): boolean {
  return isServerSentEventContentType(response.headers.get('content-type'));
}

export function isServerSentEventContentType(
  contentType: string | null,
): boolean {
  return contentType?.toLowerCase().startsWith('text/event-stream') ?? false;
}

export function removeE2eeHeaders(headers: Headers): void {
  headers.delete('x-signing-algo');
  headers.delete('x-client-pub-key');
  headers.delete('x-model-pub-key');
  headers.delete('x-encryption-version');
  headers.delete('x-encrypt-all-fields');
}

async function decryptResponse({
  response,
  clientKeyPair,
}: DecryptE2eeResponseParams): Promise<Response> {
  if (!response.ok) return response;
  const headers = new Headers(response.headers);
  headers.delete('content-length');
  if (isServerSentEventResponse(response)) {
    if (response.body === null) throw invalidResponse();
    return new Response(
      response.body.pipeThrough(createE2eeChatSseTransform({ clientKeyPair })),
      { status: response.status, statusText: response.statusText, headers },
    );
  }
  const body = await decodeResponseBody(response);
  const decrypted = decryptE2eeChatResponse({ body, clientKeyPair });
  headers.set('content-type', 'application/json');
  return new Response(JSON.stringify(decrypted), {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

async function decodeResponseBody(
  response: Response,
): Promise<SecureChatCompletionResponse> {
  let text: string;
  try {
    text = await response.text();
  } catch (cause) {
    throw new ApiError(
      {
        code: 'api.transport_failed',
        details: { resource: 'completion', reason: 'response_body' },
        retryable: true,
      },
      { cause },
    );
  }
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch (cause) {
    throw invalidResponse(cause);
  }
  return parseE2eeChatResponse({ body: value });
}

function awaitWithAbort<T>({
  operation,
  signal,
}: AwaitWithAbortParams<T>): Promise<T> {
  if (signal.aborted) return Promise.reject(signal.reason);
  return new Promise((resolve, reject) => {
    const abort = (): void => reject(signal.reason);
    signal.addEventListener('abort', abort, { once: true });
    void operation.then(
      (value) => {
        signal.removeEventListener('abort', abort);
        resolve(value);
      },
      (cause: unknown) => {
        signal.removeEventListener('abort', abort);
        reject(cause);
      },
    );
  });
}

function invalidInput(
  details: Extract<
    ApiError['failure'],
    { code: 'api.invalid_input' }
  >['details'],
  cause?: unknown,
): ApiError {
  return new ApiError(
    { code: 'api.invalid_input', details },
    cause === undefined ? undefined : { cause },
  );
}

function invalidResponse(cause?: unknown): ApiError {
  return new ApiError(
    {
      code: 'api.invalid_response',
      details: {
        path: 'Chat Completions response',
        expected: 'an encrypted Chat Completions response',
        actual: 'invalid',
      },
    },
    cause === undefined ? undefined : { cause },
  );
}
