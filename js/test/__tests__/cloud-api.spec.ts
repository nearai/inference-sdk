import * as v from 'valibot';
import type { CompletionSignature } from '../../src';
import { ApiError, NearAiCloudClient } from '../../src';
import { nonce } from '../fixtures';

const baseUrl = 'https://cloud-api.near.ai/v1';
const signerAddress = `0x${'22'.repeat(20)}`;

function modelSignature(address = signerAddress): CompletionSignature {
  return {
    kind: 'provider_tee',
    signedText: 'canonical-model:request:response',
    signature: '00',
    signer: { algorithm: 'ecdsa', address },
  };
}

function gatewaySignature(): CompletionSignature {
  return {
    kind: 'gateway',
    signedText: 'request:response',
    signature: '00',
    signer: { algorithm: 'ecdsa', address: signerAddress },
  };
}

function dstackAttestation(overrides: Record<string, unknown> = {}) {
  return {
    request_nonce: nonce,
    signing_algo: 'ecdsa',
    signing_address: signerAddress,
    intel_quote: 'aa',
    event_log: [],
    info: { tcb_info: { app_compose: '{}' } },
    tls_cert_fingerprint: '33'.repeat(32),
    ...overrides,
  };
}

function nearReport(
  model_attestations: unknown[] = [
    dstackAttestation({ report_data: '44'.repeat(64) }),
  ],
) {
  return {
    gateway_attestation: {
      ...dstackAttestation(),
      report_data: '00'.repeat(64),
    },
    model_attestations,
  };
}

function clientReplyingWith(response: unknown) {
  let request: Request | undefined;

  return {
    client: new NearAiCloudClient({
      baseUrl,
      apiKey: 'test',
      fetch: async (input, init) => {
        request = new Request(input, init);
        return new Response(JSON.stringify(response), { status: 200 });
      },
    }),
    request(): Request {
      if (!request) throw new Error('Expected a Cloud API request');
      return request;
    },
  };
}

describe('NEAR AI Cloud client', () => {
  test('fetches a NEAR model attestation selected by its model signature', async () => {
    const selectedSignerAddress = `0x${'44'.repeat(20)}`;
    const selectedSignature = modelSignature(selectedSignerAddress);
    const api = clientReplyingWith({
      gateway_attestation: { this: 'is unrelated to model parsing' },
      model_attestations: [
        dstackAttestation({
          signing_address: selectedSignerAddress,
          report_data: '44'.repeat(64),
        }),
      ],
    });

    const attestation = await api.client.fetchModelAttestation({
      model: 'canonical-model',
      nonce,
      signature: selectedSignature,
    });

    expect(attestation).toMatchObject({
      nonce,
      signer: { algorithm: 'ecdsa', address: selectedSignerAddress },
      intelQuote: 'aa',
      eventLog: [],
      appCompose: '{}',
      declaredSpkiFingerprint: '33'.repeat(32),
      reportedQuoteData: '44'.repeat(64),
    });
    expect(attestation).not.toHaveProperty('request_nonce');

    const request = api.request();
    const url = new URL(request.url);
    expect(request.method).toBe('GET');
    expect(Object.fromEntries(url.searchParams)).toEqual({
      model: 'canonical-model',
      nonce,
      signing_algo: 'ecdsa',
      signing_address: selectedSignerAddress,
      provider: 'near',
    });
    expect(request.headers.get('authorization')).toBe('Bearer test');
    expect(request.headers.get('x-no-aliasing')).toBe('true');
  });

  test('fetches gateway attestation selected by its gateway signature', async () => {
    const api = clientReplyingWith(nearReport([{ provider: 'chutes' }]));

    const attestation = await api.client.fetchGatewayAttestation({
      nonce,
      signature: gatewaySignature(),
    });

    expect(attestation.reportedQuoteData).toBe('00'.repeat(64));

    const request = api.request();
    const url = new URL(request.url);
    expect(Object.fromEntries(url.searchParams)).toEqual({
      nonce,
      signing_algo: 'ecdsa',
      signing_address: signerAddress,
      include_tls_fingerprint: 'true',
    });
    expect(request.headers.get('authorization')).toBe('Bearer test');
    expect(request.headers.has('x-no-aliasing')).toBe(false);
  });

  test('looks up an unavailable completion signature explicitly', async () => {
    const api = clientReplyingWith({
      error_code: 'SIGNATURE_UNSUPPORTED',
      message: 'No provider signature',
    });

    const lookup = await api.client.lookupCompletionSignature({
      completionId: 'chat-1',
      algorithm: 'ed25519',
    });

    expect(lookup).toEqual({
      status: 'unavailable',
      unavailable: {
        errorCode: 'SIGNATURE_UNSUPPORTED',
        message: 'No provider signature',
      },
    });
    expect(Object.fromEntries(new URL(api.request().url).searchParams)).toEqual(
      {
        signing_algo: 'ed25519',
      },
    );
  });

  test('throws a structured error for an unavailable completion signature', async () => {
    const api = clientReplyingWith({
      error_code: 'SIGNATURE_UNSUPPORTED',
      message: 'No provider signature',
    });

    await expect(
      api.client.fetchCompletionSignature({
        completionId: 'chat-1',
        algorithm: 'ed25519',
      }),
    ).rejects.toMatchObject({
      failure: {
        phase: 'signature',
        code: 'signature.unavailable',
        details: { providerErrorCode: 'SIGNATURE_UNSUPPORTED' },
      },
    });
  });

  test('fetches and normalizes a model completion signature', async () => {
    const api = clientReplyingWith({
      text: 'canonical-model:request:response',
      signature: '00',
      signing_address: signerAddress,
      signing_algo: 'ecdsa',
      signature_kind: 'provider_tee',
    });

    const signature = await api.client.fetchCompletionSignature({
      completionId: 'chat-1',
    });

    expect(signature).toEqual(modelSignature());
    const url = new URL(api.request().url);
    expect(url.pathname).toBe('/v1/signature/chat-1');
    expect(Object.fromEntries(url.searchParams)).toEqual({});
  });

  test('retains a gateway signature source', async () => {
    const api = clientReplyingWith({
      text: 'request:response',
      signature: '00',
      signing_address: signerAddress,
      signing_algo: 'ecdsa',
      signature_kind: 'gateway',
    });

    const signature = await api.client.fetchCompletionSignature({
      completionId: 'chat-1',
      algorithm: 'ecdsa',
    });

    expect(signature).toEqual(gatewaySignature());
  });

  test('rejects a signature without an explicit source', async () => {
    const api = clientReplyingWith({
      text: 'old-format',
      signature: 'aa',
      signing_address: signerAddress,
      signing_algo: 'ecdsa',
    });

    await expect(
      api.client.lookupCompletionSignature({
        completionId: 'chat-1',
        algorithm: 'ecdsa',
      }),
    ).rejects.toMatchObject({
      failure: {
        phase: 'api',
        code: 'api.invalid_response',
        details: {
          path: 'signature.signature_kind',
          expected: "'provider_tee' or 'gateway'",
          actual: 'undefined',
        },
      },
    });
  });

  test('rejects an unrecognized explicit signature source', async () => {
    const api = clientReplyingWith({
      text: 'old-format',
      signature: 'aa',
      signing_address: signerAddress,
      signing_algo: 'ecdsa',
      signature_kind: 'other',
    });

    await expect(
      api.client.fetchCompletionSignature({
        completionId: 'chat-1',
        algorithm: 'ecdsa',
      }),
    ).rejects.toMatchObject({
      failure: {
        phase: 'api',
        code: 'api.invalid_response',
        details: {
          path: 'signature.signature_kind',
          expected: "'provider_tee' or 'gateway'",
          actual: 'string',
        },
      },
    });
  });

  test('rejects a null signature source instead of treating it as legacy', async () => {
    const api = clientReplyingWith({
      text: 'old-format',
      signature: 'aa',
      signing_address: signerAddress,
      signing_algo: 'ecdsa',
      signature_kind: null,
    });

    await expect(
      api.client.fetchCompletionSignature({
        completionId: 'chat-1',
      }),
    ).rejects.toMatchObject({
      failure: {
        phase: 'api',
        code: 'api.invalid_response',
        details: {
          path: 'signature.signature_kind',
          expected: "'provider_tee' or 'gateway'",
          actual: 'null',
        },
      },
    });
  });

  test('does not parse provider-specific evidence as a NEAR model attestation', async () => {
    const api = clientReplyingWith(nearReport([{ provider: 'chutes' }]));

    await expect(
      api.client.fetchModelAttestation({
        model: 'model',
        nonce,
        signature: modelSignature(),
      }),
    ).rejects.toMatchObject({
      failure: {
        phase: 'api',
        code: 'api.invalid_response',
        details: {
          path: 'model_attestations[0].info',
          expected: 'object',
          actual: 'undefined',
        },
      },
    });
  });

  test('normalizes malformed API JSON into ApiError', async () => {
    const api = clientReplyingWith({ model_attestations: 'not-an-array' });

    try {
      await api.client.fetchModelAttestation({
        model: 'canonical-model',
        nonce,
        signature: modelSignature(),
      });
    } catch (error) {
      expect(v.isValiError(error)).toBe(false);
      expect(error).toBeInstanceOf(ApiError);
      expect(error).toMatchObject({
        failure: { phase: 'api', code: 'api.invalid_response' },
      });
      return;
    }
    throw new Error('Expected malformed API JSON to fail');
  });

  test('normalizes an unreadable transport response into ApiError', async () => {
    const client = new NearAiCloudClient({
      baseUrl,
      apiKey: 'test',
      fetch: (() => {
        const response = Proxy.revocable({}, {});
        const promise = new Promise((resolve) => {
          resolve(response.proxy);
          response.revoke();
        });
        return promise;
      }) as never,
    });

    try {
      await client.fetchGatewayAttestation({
        nonce,
        signature: gatewaySignature(),
      });
    } catch (error) {
      expect(v.isValiError(error)).toBe(false);
      expect(error).toBeInstanceOf(ApiError);
      expect(error).toMatchObject({
        failure: {
          phase: 'api',
          code: 'api.invalid_response',
          details: { actual: 'unreadable' },
        },
      });
      return;
    }
    throw new Error('Expected unreadable transport response to fail');
  });

  test('rejects evidence whose signer differs from the selected signature', async () => {
    const api = clientReplyingWith({
      model_attestations: [
        dstackAttestation({ signing_address: `0x${'44'.repeat(20)}` }),
      ],
    });

    await expect(
      api.client.fetchModelAttestation({
        model: 'canonical-model',
        nonce,
        signature: modelSignature(),
      }),
    ).rejects.toMatchObject({
      failure: {
        phase: 'api',
        code: 'api.attestation_signer_mismatch',
        details: { resource: 'model_attestation' },
      },
    });
  });

  test('rejects explicitly incompatible signatures before sending attestation requests', async () => {
    let requestCount = 0;
    const client = new NearAiCloudClient({
      baseUrl,
      apiKey: 'test',
      fetch: async () => {
        requestCount += 1;
        return new Response('{}', { status: 200 });
      },
    });

    await expect(
      client.fetchModelAttestation({
        model: 'canonical-model',
        nonce,
        signature: gatewaySignature(),
      }),
    ).rejects.toMatchObject({
      failure: {
        phase: 'signature',
        code: 'signature.kind_mismatch',
        details: { expected: 'provider_tee', actual: 'gateway' },
      },
    });
    expect(requestCount).toBe(0);

    await expect(
      client.fetchGatewayAttestation({
        nonce,
        signature: modelSignature(),
      }),
    ).rejects.toMatchObject({
      failure: {
        phase: 'signature',
        code: 'signature.kind_mismatch',
        details: { expected: 'gateway', actual: 'provider_tee' },
      },
    });
    expect(requestCount).toBe(0);
  });

  test('reports HTTP failures with status and retry guidance, not response text', async () => {
    const client = new NearAiCloudClient({
      baseUrl,
      apiKey: 'test',
      fetch: async () =>
        new Response('private upstream response', { status: 503 }),
    });

    try {
      await client.fetchGatewayAttestation({
        nonce,
        signature: gatewaySignature(),
      });
      throw new Error('Expected the Cloud API request to fail');
    } catch (error) {
      expect(error).toBeInstanceOf(ApiError);
      expect(error).toMatchObject({
        failure: {
          phase: 'api',
          code: 'api.http_status',
          details: { resource: 'gateway_attestation', status: 503 },
          retryable: true,
        },
        status: 503,
        retryable: true,
      });
      expect(JSON.stringify(error)).not.toContain('private upstream response');
    }
  });

  test('marks a pending completion signature lookup as retryable', async () => {
    const client = new NearAiCloudClient({
      baseUrl,
      apiKey: 'test',
      fetch: async () => new Response('', { status: 404 }),
    });

    await expect(
      client.lookupCompletionSignature({ completionId: 'chat-1' }),
    ).rejects.toMatchObject({
      failure: {
        phase: 'api',
        code: 'api.http_status',
        details: { resource: 'completion_signature', status: 404 },
        retryable: true,
      },
      retryable: true,
    });
  });

  test('does not mark an evidence 404 as retryable', async () => {
    const client = new NearAiCloudClient({
      baseUrl,
      apiKey: 'test',
      fetch: async () => new Response('', { status: 404 }),
    });

    await expect(
      client.fetchGatewayAttestation({
        nonce,
        signature: gatewaySignature(),
      }),
    ).rejects.toMatchObject({
      failure: {
        phase: 'api',
        code: 'api.http_status',
        details: { resource: 'gateway_attestation', status: 404 },
        retryable: false,
      },
      retryable: false,
    });
  });

  test('returns structured errors for malformed client inputs', async () => {
    expectClientInputFailure(() => new NearAiCloudClient(undefined as never), {
      field: 'options',
      reason: 'missing',
    });
    expectClientInputFailure(
      () => new NearAiCloudClient({ apiKey: 'test', baseUr: baseUrl } as never),
      { field: 'options.baseUr', reason: 'unsupported_value' },
    );

    const client = new NearAiCloudClient({ baseUrl, apiKey: 'test' });
    const expected = {
      failure: { phase: 'input', code: 'input.invalid' },
    };
    await expect(
      client.fetchModelAttestation(undefined as never),
    ).rejects.toMatchObject(expected);
    await expect(
      client.fetchGatewayAttestation(undefined as never),
    ).rejects.toMatchObject(expected);
    await expect(
      client.fetchCompletionSignature(undefined as never),
    ).rejects.toMatchObject(expected);
  });

  test('supports a synchronous custom transport', async () => {
    const client = new NearAiCloudClient({
      baseUrl,
      apiKey: 'test',
      fetch: () =>
        new Response(
          JSON.stringify({
            error_code: 'SIGNATURE_UNSUPPORTED',
            message: 'No provider signature',
          }),
          { status: 200 },
        ),
    });

    await expect(
      client.lookupCompletionSignature({ completionId: 'chat-1' }),
    ).resolves.toEqual({
      status: 'unavailable',
      unavailable: {
        errorCode: 'SIGNATURE_UNSUPPORTED',
        message: 'No provider signature',
      },
    });
  });

  test('rejects a malformed custom transport response before reading status', async () => {
    const client = new NearAiCloudClient({
      baseUrl,
      apiKey: 'test',
      fetch: (() => ({
        ok: false,
        text: () => '',
      })) as never,
    });

    await expect(
      client.fetchGatewayAttestation({
        nonce,
        signature: gatewaySignature(),
      }),
    ).rejects.toMatchObject({
      failure: {
        phase: 'api',
        code: 'api.invalid_response',
      },
    });
  });

  test('rejects a null model report-data field instead of treating it as absent', async () => {
    const api = clientReplyingWith({
      model_attestations: [dstackAttestation({ report_data: null })],
    });

    await expect(
      api.client.fetchModelAttestation({
        model: 'canonical-model',
        nonce,
        signature: modelSignature(),
      }),
    ).rejects.toMatchObject({
      failure: {
        phase: 'api',
        code: 'api.invalid_response',
        details: {
          path: 'model_attestations[0].report_data',
          actual: 'null',
        },
      },
    });
  });

  test('accepts an HTTPS base URL and rejects an HTTP base URL', () => {
    expect(
      () => new NearAiCloudClient({ baseUrl, apiKey: 'test' }),
    ).not.toThrow();

    try {
      new NearAiCloudClient({
        baseUrl: 'http://cloud-api.near.ai/v1',
        apiKey: 'test',
      });
      throw new Error('Expected an HTTP base URL to be rejected');
    } catch (error) {
      expect(error).toMatchObject({
        failure: {
          phase: 'input',
          code: 'input.invalid',
          details: { field: 'baseUrl', reason: 'invalid_url' },
        },
      });
    }
  });

  test('rejects an API key that cannot be sent as an HTTP header', () => {
    expect(
      () =>
        new NearAiCloudClient({
          baseUrl,
          apiKey: 'invalid\nheader',
        }),
    ).toThrow(
      expect.objectContaining({
        failure: {
          phase: 'input',
          code: 'input.invalid',
          details: {
            field: 'apiKey',
            reason: 'invalid_header',
            expected: 'non-empty HTTP header value',
          },
        },
      }),
    );
  });
});

function expectClientInputFailure(
  action: () => unknown,
  details: Record<string, unknown>,
): void {
  try {
    action();
  } catch (error) {
    expect(error).toMatchObject({
      failure: { phase: 'input', code: 'input.invalid', details },
    });
    return;
  }
  throw new Error('Expected client input validation to fail');
}
