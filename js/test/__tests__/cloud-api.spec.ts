import { CloudApiError, NearAiCloudClient } from '../../src';
import { nonce } from '../fixtures';

const baseUrl = 'https://cloud-api.near.ai/v1';

function dstackAttestation(overrides: Record<string, unknown> = {}) {
  return {
    request_nonce: nonce,
    signing_algo: 'ecdsa',
    signing_address: `0x${'22'.repeat(20)}`,
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

describe('NearAiCloudClient', () => {
  test('fetches NEAR model evidence with strict alias handling', async () => {
    const api = clientReplyingWith(nearReport());

    const report = await api.client.fetchNearAiCloudAttestationReport({
      model: 'canonical-model',
      nonce,
      signingAlgo: 'ecdsa',
    });

    expect(report.model_attestations).toHaveLength(1);

    const request = api.request();
    const url = new URL(request.url);
    expect(request.method).toBe('GET');
    expect(Object.fromEntries(url.searchParams)).toEqual({
      model: 'canonical-model',
      nonce,
      signing_algo: 'ecdsa',
      provider: 'near',
      include_tls_fingerprint: 'true',
    });
    expect(request.headers.get('authorization')).toBe('Bearer test');
    expect(request.headers.get('x-no-aliasing')).toBe('true');
  });

  test('fetches gateway evidence without selecting a model provider', async () => {
    const api = clientReplyingWith(nearReport([{ provider: 'chutes' }]));

    const report = await api.client.fetchGatewayAttestation({
      nonce,
      signingAlgo: 'ecdsa',
    });

    expect(report.report_data).toBe('00'.repeat(64));

    const request = api.request();
    const url = new URL(request.url);
    expect(Object.fromEntries(url.searchParams)).toEqual({
      nonce,
      signing_algo: 'ecdsa',
      include_tls_fingerprint: 'true',
    });
    expect(request.headers.get('authorization')).toBe('Bearer test');
    expect(request.headers.has('x-no-aliasing')).toBe(false);
  });

  test('models an unavailable completion signature explicitly', async () => {
    const api = clientReplyingWith({
      error_code: 'SIGNATURE_UNSUPPORTED',
      message: 'No provider signature',
    });

    const signature = await api.client.fetchCompletionSignature({
      chatId: 'chat-1',
      signingAlgo: 'ed25519',
    });

    expect(signature).toEqual({
      status: 'unavailable',
      unavailable: {
        error_code: 'SIGNATURE_UNSUPPORTED',
        message: 'No provider signature',
      },
    });
  });

  test('marks a legacy signature without a kind as unverifiable', async () => {
    const api = clientReplyingWith({
      text: 'old-format',
      signature: 'aa',
      signing_address: '11'.repeat(20),
      signing_algo: 'ecdsa',
    });

    const signature = await api.client.fetchCompletionSignature({
      chatId: 'chat-1',
      signingAlgo: 'ecdsa',
    });

    expect(signature).toMatchObject({ status: 'unknown_kind' });
  });

  test('does not parse provider-specific evidence as a NEAR model report', async () => {
    const api = clientReplyingWith(nearReport([{ provider: 'chutes' }]));

    await expect(
      api.client.fetchNearModelAttestation({
        model: 'model',
        nonce,
        signingAlgo: 'ecdsa',
      }),
    ).rejects.toMatchObject({
      failure: {
        phase: 'cloud_api',
        code: 'cloud_api.invalid_response',
        details: {
          path: 'model_attestations[0].info',
          expected: 'object',
          actual: 'undefined',
        },
      },
    });
  });

  test('reports HTTP failures with status and retry guidance, not response text', async () => {
    const client = new NearAiCloudClient({
      baseUrl,
      apiKey: 'test',
      fetch: async () =>
        new Response('private upstream response', { status: 503 }),
    });

    try {
      await client.fetchGatewayAttestation({ nonce, signingAlgo: 'ecdsa' });
      throw new Error('Expected the Cloud API request to fail');
    } catch (error) {
      expect(error).toBeInstanceOf(CloudApiError);
      expect(error).toMatchObject({
        failure: {
          phase: 'cloud_api',
          code: 'cloud_api.http_status',
          details: { operation: 'gateway attestation report', status: 503 },
          retryable: true,
        },
        status: 503,
        retryable: true,
      });
      expect(JSON.stringify(error)).not.toContain('private upstream response');
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
