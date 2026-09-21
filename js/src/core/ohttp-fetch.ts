import {
  AEAD_AES_128_GCM,
  CipherSuite,
  KDF_HKDF_SHA256,
  KEM_DHKEM_X25519_HKDF_SHA256,
} from 'hpke';
import { ChunkedOHTTPClient, KeyConfig } from 'ohttp-ts';
import type { CreateOhttpFetchParams } from '../types/ohttp';
import {
  ApiError,
  VerificationError,
  isApiError,
  isVerificationError,
} from '../utils/errors';

/** Send requests using a key configuration authenticated by the caller. */
export function createOhttpFetch({
  keyConfig,
  baseUrl,
  fetch: transport = globalThis.fetch.bind(globalThis),
  forwardedHeaders = [],
}: CreateOhttpFetchParams): typeof globalThis.fetch {
  const relay = new URL('/ohttp', baseUrl);
  const outerHeaderNames = new Set(
    forwardedHeaders.map((name) => name.toLowerCase()),
  );
  outerHeaderNames.add('authorization');
  let client: ChunkedOHTTPClient;
  try {
    client = new ChunkedOHTTPClient(
      new CipherSuite(
        KEM_DHKEM_X25519_HKDF_SHA256,
        KDF_HKDF_SHA256,
        AEAD_AES_128_GCM,
      ),
      KeyConfig.parse(keyConfig.slice()),
    );
  } catch (cause) {
    throw new VerificationError(
      { code: 'ohttp.key_config_invalid' },
      { cause },
    );
  }

  return async (input, init) => {
    const request = new Request(input, init);
    request.signal.throwIfAborted();
    if (new URL(request.url).origin !== relay.origin) {
      throw new ApiError({
        code: 'api.invalid_input',
        details: {
          field: 'request.url',
          reason: 'invalid_url',
          expected: 'the configured OHTTP origin',
        },
      });
    }

    let encapsulated: Awaited<
      ReturnType<ChunkedOHTTPClient['encapsulateRequest']>
    >;
    let body: ArrayBuffer;
    try {
      encapsulated = await client.encapsulateRequest(request);
      // Fetch upload streams are not portable across browsers or pinned TLS
      // transports. Requests are buffered; the encrypted response stays streaming.
      body = await new Response(encapsulated.init.body).arrayBuffer();
    } catch (cause) {
      request.signal.throwIfAborted();
      throw new VerificationError(
        { code: 'ohttp.encryption_failed' },
        { cause },
      );
    }
    request.signal.throwIfAborted();

    const headers = new Headers();
    for (const name of outerHeaderNames) {
      if (isInnerHeader(name)) continue;
      const value = request.headers.get(name);
      if (value !== null) headers.set(name, value);
    }
    headers.set('content-type', 'message/ohttp-chunked-req');
    let response: Response;
    try {
      response = await transport(
        new Request(relay, {
          method: 'POST',
          headers,
          body,
          signal: request.signal,
          credentials: request.credentials,
          redirect: 'error',
        }),
      );
    } catch (cause) {
      request.signal.throwIfAborted();
      if (isApiError(cause) || isVerificationError(cause)) throw cause;
      throw new ApiError(
        {
          code: 'api.transport_failed',
          details: { resource: 'ohttp', reason: 'request' },
          retryable: true,
        },
        { cause },
      );
    }
    if (request.signal.aborted) {
      void response.body?.cancel(request.signal.reason).catch(() => undefined);
      throw request.signal.reason;
    }
    if (!response.ok) {
      void response.body?.cancel().catch(() => undefined);
      throw new ApiError({
        code: 'api.http_status',
        details: { resource: 'ohttp', status: response.status },
        retryable: response.status === 429 || response.status >= 500,
      });
    }

    try {
      const decoded = await encapsulated.context.decapsulateResponse(response, {
        signal: request.signal,
      });
      if (request.method === 'HEAD') {
        // Even an empty entity must authenticate the final chunk and trailers.
        await decoded.body?.pipeTo(new WritableStream());
        return new Response(null, decoded);
      }
      if (decoded.body === null) return decoded;
      return new Response(
        authenticatedBody(decoded.body, request.signal),
        decoded,
      );
    } catch (cause) {
      void response.body?.cancel(cause).catch(() => undefined);
      request.signal.throwIfAborted();
      throw decryptionFailed(cause);
    }
  };
}

function isInnerHeader(name: string): boolean {
  return (
    name.startsWith('content-') ||
    name === 'host' ||
    name === 'transfer-encoding' ||
    name === 'x-signing-algo' ||
    name === 'x-client-pub-key' ||
    name === 'x-model-pub-key' ||
    name === 'x-encryption-version' ||
    name === 'x-encrypt-all-fields'
  );
}

function authenticatedBody(
  body: ReadableStream<Uint8Array>,
  signal: AbortSignal,
): ReadableStream<Uint8Array> {
  const reader = body.getReader();
  return new ReadableStream({
    async pull(controller) {
      try {
        const chunk = await reader.read();
        signal.throwIfAborted();
        if (chunk.done) {
          reader.releaseLock();
          controller.close();
        } else {
          controller.enqueue(chunk.value);
        }
      } catch (cause) {
        void reader.cancel(cause).catch(() => undefined);
        reader.releaseLock();
        controller.error(
          signal.aborted ? signal.reason : decryptionFailed(cause),
        );
      }
    },
    async cancel(reason) {
      try {
        await reader.cancel(reason);
      } finally {
        reader.releaseLock();
      }
    },
  });
}

function decryptionFailed(cause: unknown): VerificationError {
  return new VerificationError({ code: 'ohttp.decryption_failed' }, { cause });
}
