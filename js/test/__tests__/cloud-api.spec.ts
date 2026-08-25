import { NearAiCloudClient } from '../../src';
import { nonce } from '../fixtures';

function attestation(overrides: Record<string, unknown> = {}) {
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

describe('NearAiCloudClient', () => {
  test('requests NEAR model evidence with strict alias handling', async () => {
    const fetch = jest.fn(
      async (input: string | URL | Request, init?: RequestInit) => {
        const url = new URL(
          input instanceof URL
            ? input.toString()
            : typeof input === 'string'
              ? input
              : input.url,
        );
        expect(url.searchParams.get('provider')).toBe('near');
        expect(url.searchParams.get('model')).toBe('canonical-model');
        expect(url.searchParams.get('nonce')).toBe(nonce);
        expect(url.searchParams.get('include_tls_fingerprint')).toBe('true');
        const headers = new Headers(init?.headers);
        expect(headers.get('authorization')).toBe('Bearer test');
        expect(headers.get('x-no-aliasing')).toBe('true');
        return {
          ok: true,
          status: 200,
          text: async () =>
            JSON.stringify({
              gateway_attestation: {
                ...attestation(),
                report_data: '00'.repeat(64),
              },
              model_attestations: [
                attestation({ report_data: '44'.repeat(64) }),
              ],
            }),
        } as Response;
      },
    );
    const client = new NearAiCloudClient({
      baseUrl: 'https://cloud-api.near.ai/v1',
      apiKey: 'test',
      fetch,
    });

    const report = await client.fetchNearAiCloudAttestationReport({
      model: 'canonical-model',
      nonce,
      signingAlgo: 'ecdsa',
    });

    expect(report.gateway_attestation.report_data).toBe('00'.repeat(64));
    expect(report.model_attestations).toHaveLength(1);
    expect(report.model_attestations?.[0].report_data).toBe('44'.repeat(64));
  });

  test('fetches gateway evidence without selecting or parsing a model provider', async () => {
    const fetch = jest.fn(
      async (input: string | URL | Request, init?: RequestInit) => {
        const url = new URL(
          input instanceof URL
            ? input.toString()
            : typeof input === 'string'
              ? input
              : input.url,
        );
        expect(url.searchParams.has('model')).toBe(false);
        expect(url.searchParams.has('provider')).toBe(false);
        expect(url.searchParams.get('include_tls_fingerprint')).toBe('true');
        expect(new Headers(init?.headers).get('x-no-aliasing')).toBeNull();
        return {
          ok: true,
          status: 200,
          text: async () =>
            JSON.stringify({
              gateway_attestation: {
                ...attestation(),
                report_data: '00'.repeat(64),
              },
              model_attestations: [{ provider: 'chutes' }],
            }),
        } as Response;
      },
    );
    const client = new NearAiCloudClient({
      baseUrl: 'https://cloud-api.near.ai/v1',
      apiKey: 'test',
      fetch,
    });

    const report = await client.fetchGatewayAttestation({
      nonce,
      signingAlgo: 'ecdsa',
    });

    expect(report.report_data).toBe('00'.repeat(64));
  });

  test('models signature-unavailable responses as a non-success result', async () => {
    const client = new NearAiCloudClient({
      baseUrl: 'https://cloud-api.near.ai/v1',
      apiKey: 'test',
      fetch: async () =>
        ({
          ok: true,
          status: 200,
          text: async () =>
            JSON.stringify({
              error_code: 'SIGNATURE_UNSUPPORTED',
              message: 'No provider signature',
            }),
        }) as Response,
    });

    await expect(
      client.fetchCompletionSignature({
        chatId: 'chat-1',
        signingAlgo: 'ed25519',
      }),
    ).resolves.toEqual({
      status: 'unavailable',
      unavailable: {
        error_code: 'SIGNATURE_UNSUPPORTED',
        message: 'No provider signature',
      },
    });
  });

  test('marks a signature without a known kind as unverifiable', async () => {
    const client = new NearAiCloudClient({
      baseUrl: 'https://cloud-api.near.ai/v1',
      apiKey: 'test',
      fetch: async () =>
        ({
          ok: true,
          status: 200,
          text: async () =>
            JSON.stringify({
              text: 'old-format',
              signature: 'aa',
              signing_address: '11'.repeat(20),
              signing_algo: 'ecdsa',
            }),
        }) as Response,
    });

    await expect(
      client.fetchCompletionSignature({
        chatId: 'chat-1',
        signingAlgo: 'ecdsa',
      }),
    ).resolves.toMatchObject({ status: 'unknown_kind' });
  });

  test('does not parse a provider-specific report as NEAR evidence', async () => {
    const client = new NearAiCloudClient({
      baseUrl: 'https://cloud-api.near.ai/v1',
      apiKey: 'test',
      fetch: async () =>
        ({
          ok: true,
          status: 200,
          text: async () =>
            JSON.stringify({
              gateway_attestation: {
                ...attestation(),
                report_data: '00'.repeat(64),
              },
              model_attestations: [{ provider: 'chutes' }],
            }),
        }) as Response,
    });

    await expect(
      client.fetchNearModelAttestation({
        model: 'model',
        nonce,
        signingAlgo: 'ecdsa',
      }),
    ).rejects.toThrow('model_attestations[0].info');
  });
});
