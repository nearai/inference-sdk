import type { CompletionSignature, ModelAttestation } from '../src';
import { AttestationClient, findModelAttestationForSignature } from '../src';
import { nonce } from './fixtures';

const baseUrl = 'https://cloud-api.near.ai/v1';
const signingAddress = `0x${'22'.repeat(20)}`;

function modelSignature(
  modelSigningAddress = signingAddress,
): CompletionSignature {
  return {
    kind: 'provider_tee',
    signedText: 'canonical-model:request:response',
    signature: '00',
    signer: { signingAlgo: 'ecdsa', signingAddress: modelSigningAddress },
  };
}

function gatewaySignature(): CompletionSignature {
  return {
    kind: 'gateway',
    signedText: 'request:response',
    signature: '00',
    signer: { signingAlgo: 'ecdsa', signingAddress },
  };
}

function modelAttestation(
  overrides: Partial<ModelAttestation> = {},
): ModelAttestation {
  return {
    nonce,
    signer: { signingAlgo: 'ecdsa', signingAddress },
    intelQuote: 'aa',
    eventLog: [],
    appCompose: '{}',
    reportedQuoteData: '44'.repeat(64),
    ...overrides,
  };
}

function cloudAttestation(
  requestNonce: string,
  overrides: Record<string, unknown> = {},
) {
  return {
    request_nonce: requestNonce,
    signing_algo: 'ecdsa',
    signing_address: signingAddress,
    intel_quote: 'aa',
    event_log: [],
    info: { tcb_info: { app_compose: '{}' } },
    tls_cert_fingerprint: '33'.repeat(32),
    ...overrides,
  };
}

function modelReport(
  requestNonce: string,
  attestations: unknown[] = [
    cloudAttestation(requestNonce, { report_data: '44'.repeat(64) }),
  ],
) {
  return { model_attestations: attestations };
}

function gatewayReport(
  requestNonce: string,
  overrides: Record<string, unknown> = {},
) {
  return {
    gateway_attestation: cloudAttestation(requestNonce, {
      signing_algo: 'ed25519',
      signing_address: '55'.repeat(32),
      report_data: '00'.repeat(64),
      ...overrides,
    }),
  };
}

function completionSignature(
  kind: CompletionSignature['kind'],
  signingAlgo: CompletionSignature['signer']['signingAlgo'] = 'ecdsa',
) {
  const signatureSigningAddress =
    signingAlgo === 'ecdsa' ? signingAddress : '66'.repeat(32);
  return {
    text:
      kind === 'provider_tee'
        ? 'canonical-model:request:response'
        : 'request:response',
    signature: '00',
    signing_address: signatureSigningAddress,
    signing_algo: signingAlgo,
    signature_kind: kind,
  };
}

function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), { status });
}

function cloudFor(response: (request: Request) => Response) {
  let lastRequest: Request | undefined;
  jest.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    lastRequest = new Request(input, init);
    return response(lastRequest);
  });
  const client = new AttestationClient({
    baseUrl,
    apiKey: 'test',
  });

  return {
    client,
    request(): Request {
      if (lastRequest === undefined) {
        throw new Error('Expected a Cloud API request');
      }
      return lastRequest;
    },
  };
}

function requestNonce(request: Request): string {
  const value = new URL(request.url).searchParams.get('nonce');
  if (value === null) {
    throw new Error('Expected the Cloud API request to include a nonce');
  }
  return value;
}

describe('AttestationClient', () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('model attestations', () => {
    test('fetches model evidence and selects the signer for a model response', async () => {
      const selectedSigningAddress = `0x${'44'.repeat(20)}`;
      const signature = modelSignature(selectedSigningAddress);
      const api = cloudFor((request) => {
        const clientNonce = requestNonce(request);
        return jsonResponse(
          modelReport(clientNonce, [
            cloudAttestation(clientNonce, {
              signing_address: selectedSigningAddress,
              report_data: '44'.repeat(64),
            }),
          ]),
        );
      });

      const { attestations, clientBinding } =
        await api.client.fetchModelAttestations({
          model: 'canonical-model',
          signingAlgo: signature.signer.signingAlgo,
          signingAddress: signature.signer.signingAddress,
        });
      const attestation = findModelAttestationForSignature({
        attestations,
        signature,
      });

      expect(attestation).toMatchObject({
        nonce: clientBinding.nonce,
        signer: signature.signer,
        appCompose: '{}',
        reportedQuoteData: '44'.repeat(64),
      });

      const request = api.request();
      const query = new URL(request.url).searchParams;
      expect(query.get('model')).toBe('canonical-model');
      expect(query.get('provider')).toBe('near');
      expect(query.get('nonce')).toBe(clientBinding.nonce);
      expect(query.get('include_tls_fingerprint')).toBe('false');
      expect(query.get('signing_algo')).toBe('ecdsa');
      expect(query.get('signing_address')).toBe(selectedSigningAddress);
      expect(request.headers.get('authorization')).toBe('Bearer test');
      expect(request.headers.get('x-no-aliasing')).toBe('true');
    });

    test('fetches the single model attestation for a provider signature', async () => {
      const signature = modelSignature();
      const api = cloudFor((request) => {
        const clientNonce = requestNonce(request);
        return jsonResponse(modelReport(clientNonce));
      });

      const fetched = await api.client.fetchModelAttestationForSignature({
        model: 'canonical-model',
        signature,
      });

      expect(fetched).toMatchObject({
        clientBinding: { nonce: fetched.attestation.nonce },
        attestation: { signer: signature.signer },
      });
    });

    test('matches signer encodings by bytes', () => {
      const signature = modelSignature(`0x${'ab'.repeat(20)}`);
      const attestation = modelAttestation({
        signer: {
          signingAlgo: 'ecdsa',
          signingAddress: `0X${'AB'.repeat(20)}`,
        },
      });

      expect(
        findModelAttestationForSignature({
          attestations: [attestation],
          signature,
        }),
      ).toBe(attestation);
    });

    test('fetches model evidence without signer filters', async () => {
      const api = cloudFor((request) =>
        jsonResponse(modelReport(requestNonce(request))),
      );

      const fetched = await api.client.fetchModelAttestations({
        model: 'canonical-model',
      });

      const query = new URL(api.request().url).searchParams;
      expect(query.get('model')).toBe('canonical-model');
      expect(query.get('provider')).toBe('near');
      expect(query.get('nonce')).toBe(fetched.clientBinding.nonce);
      expect(query.has('signing_algo')).toBe(false);
      expect(query.has('signing_address')).toBe(false);
    });

    test('normalizes nullable service evidence to absent optional fields', async () => {
      const api = cloudFor((request) => {
        const clientNonce = requestNonce(request);
        return jsonResponse(
          modelReport(clientNonce, [
            cloudAttestation(clientNonce, {
              tls_cert_fingerprint: null,
              report_data: null,
              nvidia_payload: null,
            }),
          ]),
        );
      });

      const { attestations } = await api.client.fetchModelAttestations({
        model: 'canonical-model',
      });
      const [attestation] = attestations;

      expect(attestation).not.toHaveProperty('spkiFingerprint');
      expect(attestation).not.toHaveProperty('reportedQuoteData');
      expect(attestation).not.toHaveProperty('nvidiaPayload');
    });

    test('accepts a serialized tcb_info object from Cloud API', async () => {
      const api = cloudFor((request) => {
        const clientNonce = requestNonce(request);
        return jsonResponse(
          modelReport(clientNonce, [
            cloudAttestation(clientNonce, {
              info: {
                tcb_info: JSON.stringify({ app_compose: '{"services":{}}' }),
              },
            }),
          ]),
        );
      });

      const { attestations } = await api.client.fetchModelAttestations({
        model: 'canonical-model',
      });

      expect(attestations[0].appCompose).toBe('{"services":{}}');
    });

    test('reports the nested wire field when serialized TCB info is malformed', async () => {
      const api = cloudFor((request) => {
        const clientNonce = requestNonce(request);
        return jsonResponse(
          modelReport(clientNonce, [
            cloudAttestation(clientNonce, {
              info: { tcb_info: '{not JSON}' },
            }),
          ]),
        );
      });

      await expect(
        api.client.fetchModelAttestations({
          model: 'canonical-model',
        }),
      ).rejects.toMatchObject({
        failure: {
          code: 'api.invalid_response',
          details: { path: 'model_attestations[0].info.tcb_info' },
        },
      });
    });

    test('rejects a model report whose nonce does not match the request', async () => {
      const api = cloudFor(() => jsonResponse(modelReport('44'.repeat(32))));

      await expect(
        api.client.fetchModelAttestations({
          model: 'canonical-model',
        }),
      ).rejects.toMatchObject({
        failure: {
          code: 'api.nonce_mismatch',
          details: { resource: 'model_attestation' },
        },
      });
    });

    test('accepts an equivalent nonce encoding', async () => {
      const api = cloudFor((request) => {
        const responseNonce = `0X${requestNonce(request).toUpperCase()}`;
        return jsonResponse(modelReport(responseNonce));
      });

      const { attestations } = await api.client.fetchModelAttestations({
        model: 'canonical-model',
      });

      expect(attestations[0].nonce).toMatch(/^0X[0-9A-F]{64}$/);
    });

    test('requires exactly one model attestation when Cloud API returns multiple candidates', async () => {
      const api = cloudFor((request) => {
        const clientNonce = requestNonce(request);
        return jsonResponse(
          modelReport(clientNonce, [
            cloudAttestation(clientNonce),
            cloudAttestation(clientNonce),
          ]),
        );
      });

      await expect(
        api.client.fetchModelAttestations({
          model: 'canonical-model',
        }),
      ).rejects.toMatchObject({
        failure: {
          code: 'api.unexpected_model_attestation_count',
          details: { actualCount: 2 },
        },
      });
    });

    test('treats an omitted model-attestations field as zero candidates', async () => {
      const api = cloudFor(() => jsonResponse({}));

      await expect(
        api.client.fetchModelAttestations({
          model: 'canonical-model',
        }),
      ).rejects.toMatchObject({
        failure: {
          code: 'api.unexpected_model_attestation_count',
          details: { actualCount: 0 },
        },
      });
    });

    test.each([
      {
        label: 'a provider signer with no matching attestation',
        attestations: [modelAttestation()],
        signature: modelSignature(`0x${'44'.repeat(20)}`),
        failure: {
          code: 'api.model_attestation_signer_not_found',
        },
      },
      {
        label: 'multiple attestations for the same signer',
        attestations: [modelAttestation(), modelAttestation()],
        signature: modelSignature(),
        failure: {
          code: 'api.ambiguous_model_attestation_signer',
          details: { matchingCount: 2, totalCount: 2 },
        },
      },
      {
        label: 'a gateway signature',
        attestations: [modelAttestation()],
        signature: gatewaySignature(),
        failure: {
          code: 'signature.kind_mismatch',
          details: { expected: 'provider_tee', actual: 'gateway' },
        },
      },
    ])('rejects $label', ({ attestations, signature, failure }) => {
      expect(() =>
        findModelAttestationForSignature({ attestations, signature }),
      ).toThrow(expect.objectContaining({ failure }));
    });
  });

  describe('gateway attestations', () => {
    test('fetches gateway evidence without TLS binding', async () => {
      const api = cloudFor((request) =>
        jsonResponse(
          gatewayReport(requestNonce(request), {
            tls_cert_fingerprint: null,
          }),
        ),
      );

      const fetched = await api.client.fetchGatewayAttestation();

      expect(fetched).toMatchObject({
        clientBinding: { nonce: fetched.attestation.nonce },
        attestation: {
          reportedQuoteData: '00'.repeat(64),
        },
      });
      expect(fetched.attestation).not.toHaveProperty('spkiFingerprint');
      const query = new URL(api.request().url).searchParams;
      expect(query.get('nonce')).toBe(fetched.clientBinding.nonce);
      expect(query.get('signing_algo')).toBeNull();
      expect(query.get('include_tls_fingerprint')).toBe('false');
    });

    test('requests the gateway signing algorithm needed by a response signature', async () => {
      const api = cloudFor((request) =>
        jsonResponse(
          gatewayReport(requestNonce(request), {
            signing_algo: 'ecdsa',
            signing_address: signingAddress,
            tls_cert_fingerprint: null,
          }),
        ),
      );

      await api.client.fetchGatewayAttestation({
        signingAlgo: 'ecdsa',
      });

      expect(new URL(api.request().url).searchParams.get('signing_algo')).toBe(
        'ecdsa',
      );
    });

    test('rejects a Gateway TLS fingerprint returned when it was not requested', async () => {
      const api = cloudFor((request) =>
        jsonResponse(gatewayReport(requestNonce(request))),
      );

      await expect(api.client.fetchGatewayAttestation()).rejects.toMatchObject({
        failure: {
          code: 'api.invalid_response',
          details: {
            path: 'gateway_attestation.tls_cert_fingerprint',
            expected: 'missing',
            actual: 'present',
          },
        },
      });
    });

    test('rejects gateway evidence whose nonce does not match the request', async () => {
      const api = cloudFor(() =>
        jsonResponse(
          gatewayReport('44'.repeat(32), { tls_cert_fingerprint: null }),
        ),
      );

      await expect(api.client.fetchGatewayAttestation()).rejects.toMatchObject({
        failure: {
          code: 'api.nonce_mismatch',
          details: { resource: 'gateway_attestation' },
        },
      });
    });
  });

  describe('completion signatures', () => {
    test.each([
      { kind: 'provider_tee' as const, expected: modelSignature() },
      { kind: 'gateway' as const, expected: gatewaySignature() },
    ])('fetches a $kind completion signature', async ({ kind, expected }) => {
      const api = cloudFor(() => jsonResponse(completionSignature(kind)));

      const signature = await api.client.fetchCompletionSignature({
        completionId: 'chat-1',
      });

      expect(signature).toEqual(expected);
      expect(new URL(api.request().url).pathname).toBe('/v1/signature/chat-1');
    });

    test('passes an explicit signing algorithm when fetching a completion signature', async () => {
      const api = cloudFor(() =>
        jsonResponse(completionSignature('gateway', 'ed25519')),
      );

      const signature = await api.client.fetchCompletionSignature({
        completionId: 'chat-1',
        signingAlgo: 'ed25519',
      });

      expect(signature.signer.signingAlgo).toBe('ed25519');
      expect(new URL(api.request().url).searchParams.get('signing_algo')).toBe(
        'ed25519',
      );
    });

    test('lets callers choose between an unavailable result and an error', async () => {
      const api = cloudFor(() =>
        jsonResponse({
          error_code: 'SIGNATURE_UNSUPPORTED',
          message: 'No provider signature',
        }),
      );

      const lookup = await api.client.lookupCompletionSignature({
        completionId: 'chat-1',
      });

      expect(lookup).toEqual({
        status: 'unavailable',
        unavailable: {
          errorCode: 'SIGNATURE_UNSUPPORTED',
          message: 'No provider signature',
        },
      });
      await expect(
        api.client.fetchCompletionSignature({
          completionId: 'chat-1',
        }),
      ).rejects.toMatchObject({
        failure: {
          code: 'api.completion_signature_unavailable',
          details: { providerErrorCode: 'SIGNATURE_UNSUPPORTED' },
        },
      });
    });

    test('marks a pending completion signature lookup as retryable', async () => {
      const api = cloudFor(() => new Response('', { status: 404 }));

      await expect(
        api.client.lookupCompletionSignature({
          completionId: 'chat-1',
        }),
      ).rejects.toMatchObject({
        failure: {
          code: 'api.http_status',
          details: { resource: 'completion_signature', status: 404 },
          retryable: true,
        },
      });
    });
  });

  describe('API errors', () => {
    test('distinguishes missing gateway evidence from a transient gateway failure', async () => {
      const missing = cloudFor(() => new Response('', { status: 404 }));

      await expect(
        missing.client.fetchGatewayAttestation(),
      ).rejects.toMatchObject({
        failure: {
          code: 'api.http_status',
          details: { resource: 'gateway_attestation', status: 404 },
          retryable: false,
        },
      });

      const unavailable = cloudFor(() => new Response('', { status: 503 }));
      await expect(
        unavailable.client.fetchGatewayAttestation(),
      ).rejects.toMatchObject({
        failure: {
          code: 'api.http_status',
          details: { resource: 'gateway_attestation', status: 503 },
          retryable: true,
        },
      });
    });

    test('normalizes a malformed model-attestation response into an API error', async () => {
      const api = cloudFor(() =>
        jsonResponse({ model_attestations: 'not-an-array' }),
      );

      await expect(
        api.client.fetchModelAttestations({
          model: 'canonical-model',
        }),
      ).rejects.toMatchObject({
        failure: { code: 'api.invalid_response' },
      });
    });
  });
});
