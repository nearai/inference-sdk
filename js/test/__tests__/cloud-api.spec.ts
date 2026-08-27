import type {
  CompletionSignature,
  CompletionSignatureReference,
  ModelAttestation,
} from '../../src';
import {
  ApiError,
  findModelAttestationForSignature,
  isVerificationError,
  NearAiCloudClient,
} from '../../src';
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

function modelAttestation(
  overrides: Partial<ModelAttestation> = {},
): ModelAttestation {
  return {
    nonce,
    signer: { algorithm: 'ecdsa', address: signerAddress },
    intelQuote: 'aa',
    eventLog: [],
    appCompose: '{}',
    declaredSpkiFingerprint: '33'.repeat(32),
    reportedQuoteData: '44'.repeat(64),
    ...overrides,
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
        const requestNonce = new URL(request.url).searchParams.get('nonce');
        return new Response(
          JSON.stringify(echoRequestNonce(response, requestNonce)),
          { status: 200 },
        );
      },
    }),
    request(): Request {
      if (!request) throw new Error('Expected a Cloud API request');
      return request;
    },
  };
}

function echoRequestNonce(
  response: unknown,
  requestNonce: string | null,
): unknown {
  if (requestNonce === null) return response;
  if (Array.isArray(response)) {
    return response.map((item) => echoRequestNonce(item, requestNonce));
  }
  if (!isRecord(response)) return response;

  return Object.fromEntries(
    Object.entries(response).map(([key, value]) => [
      key,
      key === 'request_nonce' && value === nonce
        ? requestNonce
        : echoRequestNonce(value, requestNonce),
    ]),
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object';
}

describe('NEAR AI Cloud client', () => {
  test('fetches and selects a NEAR model attestation for a model signature', async () => {
    const selectedSignerAddress = `0x${'44'.repeat(20)}`;
    const selectedSignature: CompletionSignatureReference = {
      kind: 'provider_tee',
      signer: { algorithm: 'ecdsa', address: selectedSignerAddress },
    };
    const api = clientReplyingWith({
      gateway_attestation: { this: 'is unrelated to model parsing' },
      model_attestations: [
        dstackAttestation({
          signing_address: selectedSignerAddress,
          report_data: '44'.repeat(64),
        }),
      ],
    });

    const fetched = await api.client.fetchModelAttestationForSignature({
      model: 'canonical-model',
      signature: selectedSignature,
    });

    expect(fetched.nonce).toMatch(/^[0-9a-f]{64}$/);
    expect(fetched.attestation).toMatchObject({
      nonce: fetched.nonce,
      signer: { algorithm: 'ecdsa', address: selectedSignerAddress },
      intelQuote: 'aa',
      eventLog: [],
      appCompose: '{}',
      declaredSpkiFingerprint: '33'.repeat(32),
      reportedQuoteData: '44'.repeat(64),
    });
    expect(fetched.attestation).not.toHaveProperty('request_nonce');

    const request = api.request();
    const url = new URL(request.url);
    expect(request.method).toBe('GET');
    expect(Object.fromEntries(url.searchParams)).toEqual({
      model: 'canonical-model',
      nonce: fetched.nonce,
      signing_algo: 'ecdsa',
      signing_address: selectedSignerAddress,
      provider: 'near',
    });
    expect(request.headers.get('authorization')).toBe('Bearer test');
    expect(request.headers.get('x-no-aliasing')).toBe('true');
  });

  test('fetches the current Cloud API model-attestation list without signing filters', async () => {
    const api = clientReplyingWith(nearReport());

    const fetched = await api.client.fetchModelAttestations({
      model: 'canonical-model',
    });

    expect(fetched.nonce).toMatch(/^[0-9a-f]{64}$/);
    expect(fetched.attestations).toHaveLength(1);
    expect(fetched.attestations[0]).toMatchObject({
      nonce: fetched.nonce,
      signer: { algorithm: 'ecdsa', address: signerAddress },
      reportedQuoteData: '44'.repeat(64),
    });
    expect(Object.fromEntries(new URL(api.request().url).searchParams)).toEqual(
      {
        model: 'canonical-model',
        nonce: fetched.nonce,
        provider: 'near',
      },
    );
  });

  test('rejects a model report whose echoed nonce differs from the request', async () => {
    const api = clientReplyingWith(
      nearReport([dstackAttestation({ request_nonce: '44'.repeat(32) })]),
    );

    await expect(
      api.client.fetchModelAttestations({
        model: 'canonical-model',
      }),
    ).rejects.toMatchObject({
      failure: {
        phase: 'api',
        code: 'api.nonce_mismatch',
        details: { resource: 'model_attestation' },
      },
    });
  });

  test('forwards an optional model signer filter', async () => {
    const api = clientReplyingWith(nearReport());

    await api.client.fetchModelAttestations({
      model: 'canonical-model',
      algorithm: 'ecdsa',
      signingAddress: signerAddress,
    });

    expect(new URL(api.request().url).searchParams.get('signing_address')).toBe(
      signerAddress,
    );
  });

  test('allows an address filter without an algorithm filter', async () => {
    const api = clientReplyingWith(nearReport());

    await api.client.fetchModelAttestations({
      model: 'canonical-model',
      signingAddress: signerAddress,
    });

    const query = new URL(api.request().url).searchParams;
    expect(query.get('signing_address')).toBe(signerAddress);
    expect(query.has('signing_algo')).toBe(false);
  });

  test.each([
    { attestations: [], actualCount: 0 },
    {
      attestations: [dstackAttestation(), dstackAttestation()],
      actualCount: 2,
    },
  ])(
    'rejects a Cloud API model-attestation list with $actualCount entries',
    async ({ attestations, actualCount }) => {
      const api = clientReplyingWith(nearReport(attestations));

      await expect(
        api.client.fetchModelAttestations({
          model: 'canonical-model',
        }),
      ).rejects.toMatchObject({
        failure: {
          phase: 'api',
          code: 'api.unexpected_model_attestation_count',
          details: { expectedCount: 1, actualCount },
        },
      });
    },
  );

  test('finds the one model attestation for a matching provider signature', () => {
    const attestation = modelAttestation({
      signer: { algorithm: 'ecdsa', address: `0x${'44'.repeat(20)}` },
    });

    expect(
      findModelAttestationForSignature({
        attestations: [modelAttestation(), attestation],
        signature: modelSignature(`0X${'44'.repeat(20)}`),
      }),
    ).toEqual(attestation);
  });

  test('rejects a model-attestation list with no matching signature signer', () => {
    expect(() =>
      findModelAttestationForSignature({
        attestations: [modelAttestation()],
        signature: modelSignature(`0x${'44'.repeat(20)}`),
      }),
    ).toThrow(
      expect.objectContaining({
        failure: {
          phase: 'api',
          code: 'api.attestation_signer_mismatch',
          details: { resource: 'model_attestation' },
        },
      }),
    );
  });

  test('requires a unique model attestation for a signature signer', () => {
    const first = modelAttestation();
    const second = modelAttestation({ reportedQuoteData: '55'.repeat(64) });

    expect(() =>
      findModelAttestationForSignature({
        attestations: [first, second],
        signature: modelSignature(),
      }),
    ).toThrow(
      expect.objectContaining({
        failure: {
          phase: 'api',
          code: 'api.ambiguous_model_attestation_signer',
          details: { matchingCount: 2, totalCount: 2 },
        },
      }),
    );
  });

  test('rejects a gateway signature in local model-attestation selection', () => {
    expect(() =>
      findModelAttestationForSignature({
        attestations: [modelAttestation()],
        signature: gatewaySignature(),
      }),
    ).toThrow(
      expect.objectContaining({
        failure: {
          phase: 'signature',
          code: 'signature.kind_mismatch',
          details: { expected: 'provider_tee', actual: 'gateway' },
        },
      }),
    );
  });

  test('rejects unknown fields in a model signer reference', () => {
    expect(() =>
      findModelAttestationForSignature({
        attestations: [modelAttestation()],
        signature: {
          kind: 'provider_tee',
          signer: {
            algorithm: 'ecdsa',
            address: signerAddress,
            signingAddres: signerAddress,
          },
        },
      } as never),
    ).toThrow(
      expect.objectContaining({
        failure: expect.objectContaining({
          phase: 'input',
          code: 'input.invalid',
          details: expect.objectContaining({
            field: 'signature.signer.signingAddres',
            reason: 'unsupported_value',
          }),
        }),
      }),
    );
  });

  test('fetches standalone gateway attestation with TLS binding enabled', async () => {
    const api = clientReplyingWith(nearReport([{ provider: 'chutes' }]));

    const fetched = await api.client.fetchGatewayAttestation();

    expect(fetched.nonce).toMatch(/^[0-9a-f]{64}$/);
    expect(fetched.attestation).toMatchObject({
      nonce: fetched.nonce,
      reportedQuoteData: '00'.repeat(64),
    });

    const request = api.request();
    const url = new URL(request.url);
    expect(Object.fromEntries(url.searchParams)).toEqual({
      nonce: fetched.nonce,
      signing_algo: 'ed25519',
      include_tls_fingerprint: 'true',
    });
    expect(request.headers.get('authorization')).toBe('Bearer test');
    expect(request.headers.has('x-no-aliasing')).toBe(false);
  });

  test('rejects a gateway report whose echoed nonce differs from the request', async () => {
    const api = clientReplyingWith({
      gateway_attestation: {
        ...dstackAttestation({ request_nonce: '44'.repeat(32) }),
        report_data: '00'.repeat(64),
      },
    });

    await expect(api.client.fetchGatewayAttestation()).rejects.toMatchObject({
      failure: {
        phase: 'api',
        code: 'api.nonce_mismatch',
        details: { resource: 'gateway_attestation' },
      },
    });
  });

  test('requests an explicit gateway signing algorithm when provided', async () => {
    const api = clientReplyingWith(nearReport());

    await api.client.fetchGatewayAttestation({
      algorithm: 'ecdsa',
    });

    expect(new URL(api.request().url).searchParams.get('signing_algo')).toBe(
      'ecdsa',
    );
  });

  test('rejects a completion signature in standalone gateway input before sending a request', async () => {
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
      client.fetchGatewayAttestation({
        signature: gatewaySignature(),
      } as never),
    ).rejects.toMatchObject({
      failure: {
        phase: 'input',
        code: 'input.invalid',
        details: { field: 'input.signature', reason: 'unsupported_value' },
      },
    });
    expect(requestCount).toBe(0);
  });

  test('rejects a caller-supplied nonce instead of silently ignoring it', async () => {
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
      client.fetchModelAttestations({
        model: 'canonical-model',
        nonce,
      } as never),
    ).rejects.toMatchObject({
      failure: {
        phase: 'input',
        code: 'input.invalid',
        details: { field: 'input.nonce', reason: 'unsupported_value' },
      },
    });
    expect(requestCount).toBe(0);
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
          actual: 'undefined',
        },
      },
    });
  });

  test.each([
    { value: 'other', actual: 'string' },
    { value: 0, actual: 'number' },
    { value: [], actual: 'array' },
    { value: {}, actual: 'object' },
  ])(
    'rejects an unrecognized signature source with $actual input',
    async ({ value, actual }) => {
      const api = clientReplyingWith({
        text: 'old-format',
        signature: 'aa',
        signing_address: signerAddress,
        signing_algo: 'ecdsa',
        signature_kind: value,
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
            actual,
          },
        },
      });
    },
  );

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
          actual: 'null',
        },
      },
    });
  });

  test('does not classify a malformed signature payload as unavailable', async () => {
    const api = clientReplyingWith({
      error_code: 'SIGNATURE_UNSUPPORTED',
      message: 'No provider signature',
      text: 'old-format',
      signature: 'aa',
      signing_address: signerAddress,
      signing_algo: 'ecdsa',
      signature_kind: 'other',
    });

    await expect(
      api.client.lookupCompletionSignature({
        completionId: 'chat-1',
      }),
    ).rejects.toMatchObject({
      failure: {
        phase: 'api',
        code: 'api.invalid_response',
        details: {
          path: 'signature.signature_kind',
          actual: 'string',
        },
      },
    });
  });

  test('does not parse provider-specific evidence as a NEAR model attestation', async () => {
    const api = clientReplyingWith(nearReport([{ provider: 'chutes' }]));

    await expect(
      api.client.fetchModelAttestations({
        model: 'model',
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
      await api.client.fetchModelAttestations({
        model: 'canonical-model',
      });
    } catch (error) {
      expect(error).toBeInstanceOf(ApiError);
      expect(isVerificationError(error)).toBe(true);
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
      await client.fetchGatewayAttestation();
    } catch (error) {
      expect(error).toBeInstanceOf(ApiError);
      expect(isVerificationError(error)).toBe(true);
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
      api.client.fetchModelAttestationForSignature({
        model: 'canonical-model',
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

  test('rejects an incompatible model signature before sending its attestation request', async () => {
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
      client.fetchModelAttestationForSignature({
        model: 'canonical-model',
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
  });

  test('reports HTTP failures with status and retry guidance, not response text', async () => {
    const client = new NearAiCloudClient({
      baseUrl,
      apiKey: 'test',
      fetch: async () =>
        new Response('private upstream response', { status: 503 }),
    });

    try {
      await client.fetchGatewayAttestation();
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

    await expect(client.fetchGatewayAttestation()).rejects.toMatchObject({
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
      client.fetchModelAttestations(undefined as never),
    ).rejects.toMatchObject(expected);
    await expect(
      client.fetchModelAttestationForSignature(undefined as never),
    ).rejects.toMatchObject(expected);
    await expect(
      client.fetchGatewayAttestation(null as never),
    ).rejects.toMatchObject(expected);
    await expect(
      client.fetchCompletionSignature(undefined as never),
    ).rejects.toMatchObject(expected);
    expectClientInputFailure(
      () => findModelAttestationForSignature(undefined as never),
      { field: 'input', reason: 'missing' },
    );
  });

  test('fails before sending an attestation request without secure random bytes', async () => {
    let requestCount = 0;
    const client = new NearAiCloudClient({
      baseUrl,
      apiKey: 'test',
      fetch: async () => {
        requestCount += 1;
        return new Response('{}', { status: 200 });
      },
    });
    const cryptoDescriptor = Object.getOwnPropertyDescriptor(
      globalThis,
      'crypto',
    );

    Object.defineProperty(globalThis, 'crypto', {
      configurable: true,
      value: undefined,
    });

    try {
      await expect(client.fetchGatewayAttestation()).rejects.toMatchObject({
        failure: {
          phase: 'runtime',
          code: 'runtime.crypto_unavailable',
          details: { capability: 'secure_random' },
        },
      });
      expect(requestCount).toBe(0);
    } finally {
      if (cryptoDescriptor === undefined) {
        Reflect.deleteProperty(globalThis, 'crypto');
      } else {
        Object.defineProperty(globalThis, 'crypto', cryptoDescriptor);
      }
    }
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

    await expect(client.fetchGatewayAttestation()).rejects.toMatchObject({
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
      api.client.fetchModelAttestations({
        model: 'canonical-model',
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
