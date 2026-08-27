import type {
  CompletionSignature,
  ModelAttestation,
  NearAiCloudOptions,
} from '../../src';
import {
  ApiError,
  fetchCompletionSignature,
  fetchGatewayAttestation,
  fetchModelAttestationForSignature,
  fetchModelAttestations,
  findModelAttestationForSignature,
  isApiError,
  isVerificationError,
  lookupCompletionSignature,
  VerificationError,
} from '../../src';
import { nonce } from '../fixtures';

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
    declaredSpkiFingerprint: '33'.repeat(32),
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

function completionSignature(kind: CompletionSignature['kind']) {
  return {
    text:
      kind === 'provider_tee'
        ? 'canonical-model:request:response'
        : 'request:response',
    signature: '00',
    signing_address: signingAddress,
    signing_algo: 'ecdsa',
    signature_kind: kind,
  };
}

function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), { status });
}

function cloudFor(response: (request: Request) => Response) {
  let lastRequest: Request | undefined;
  const cloud: NearAiCloudOptions = {
    baseUrl,
    apiKey: 'test',
    fetch: async (input, init) => {
      lastRequest = new Request(input, init);
      return response(lastRequest);
    },
  };

  return {
    cloud,
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

describe('NEAR AI Cloud fetch helpers', () => {
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

      const { attestations, nonce: clientNonce } = await fetchModelAttestations(
        api.cloud,
        {
          model: 'canonical-model',
          signingAlgo: signature.signer.signingAlgo,
          signingAddress: signature.signer.signingAddress,
        },
      );
      const attestation = findModelAttestationForSignature({
        attestations,
        signature,
      });

      expect(attestation).toMatchObject({
        nonce: clientNonce,
        signer: signature.signer,
        appCompose: '{}',
        reportedQuoteData: '44'.repeat(64),
      });

      const request = api.request();
      const query = new URL(request.url).searchParams;
      expect(query.get('model')).toBe('canonical-model');
      expect(query.get('provider')).toBe('near');
      expect(query.get('nonce')).toBe(clientNonce);
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

      const fetched = await fetchModelAttestationForSignature(api.cloud, {
        model: 'canonical-model',
        signature,
      });

      expect(fetched).toMatchObject({
        nonce: fetched.attestation.nonce,
        attestation: { signer: signature.signer },
      });
    });

    test('fetches model evidence without signer filters', async () => {
      const api = cloudFor((request) =>
        jsonResponse(modelReport(requestNonce(request))),
      );

      const fetched = await fetchModelAttestations(api.cloud, {
        model: 'canonical-model',
      });

      const query = new URL(api.request().url).searchParams;
      expect(query.get('model')).toBe('canonical-model');
      expect(query.get('provider')).toBe('near');
      expect(query.get('nonce')).toBe(fetched.nonce);
      expect(query.has('signing_algo')).toBe(false);
      expect(query.has('signing_address')).toBe(false);
    });

    test('rejects a model report whose nonce does not match the request', async () => {
      const api = cloudFor(() => jsonResponse(modelReport('44'.repeat(32))));

      await expect(
        fetchModelAttestations(api.cloud, { model: 'canonical-model' }),
      ).rejects.toMatchObject({
        failure: {
          phase: 'api',
          code: 'api.nonce_mismatch',
          details: { resource: 'model_attestation' },
        },
      });
    });

    test.each([
      { label: 'no candidates', attestations: [], actualCount: 0 },
      {
        label: 'multiple candidates',
        attestations: [cloudAttestation(nonce), cloudAttestation(nonce)],
        actualCount: 2,
      },
    ])(
      'requires exactly one model attestation when Cloud API returns $label',
      async ({ attestations, actualCount }) => {
        const api = cloudFor((request) =>
          jsonResponse(modelReport(requestNonce(request), attestations)),
        );

        await expect(
          fetchModelAttestations(api.cloud, { model: 'canonical-model' }),
        ).rejects.toMatchObject({
          failure: {
            phase: 'api',
            code: 'api.unexpected_model_attestation_count',
            details: { expectedCount: 1, actualCount },
          },
        });
      },
    );

    test.each([
      {
        label: 'a provider signer with no matching attestation',
        attestations: [modelAttestation()],
        signature: modelSignature(`0x${'44'.repeat(20)}`),
        failure: {
          phase: 'api',
          code: 'api.attestation_signer_mismatch',
          details: { resource: 'model_attestation' },
        },
      },
      {
        label: 'multiple attestations for the same signer',
        attestations: [modelAttestation(), modelAttestation()],
        signature: modelSignature(),
        failure: {
          phase: 'api',
          code: 'api.ambiguous_model_attestation_signer',
          details: { matchingCount: 2, totalCount: 2 },
        },
      },
      {
        label: 'a gateway signature',
        attestations: [modelAttestation()],
        signature: gatewaySignature(),
        failure: {
          phase: 'signature',
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
    test('fetches gateway evidence with TLS binding and the default signing algorithm', async () => {
      const api = cloudFor((request) =>
        jsonResponse(gatewayReport(requestNonce(request))),
      );

      const fetched = await fetchGatewayAttestation(api.cloud);

      expect(fetched).toMatchObject({
        nonce: fetched.attestation.nonce,
        attestation: { reportedQuoteData: '00'.repeat(64) },
      });
      const query = new URL(api.request().url).searchParams;
      expect(query.get('nonce')).toBe(fetched.nonce);
      expect(query.get('signing_algo')).toBe('ed25519');
      expect(query.get('include_tls_fingerprint')).toBe('true');
    });

    test('requests the gateway signing algorithm needed by a response signature', async () => {
      const api = cloudFor((request) =>
        jsonResponse(
          gatewayReport(requestNonce(request), {
            signing_algo: 'ecdsa',
            signing_address: signingAddress,
          }),
        ),
      );

      await fetchGatewayAttestation(api.cloud, { signingAlgo: 'ecdsa' });

      expect(new URL(api.request().url).searchParams.get('signing_algo')).toBe(
        'ecdsa',
      );
    });

    test('rejects gateway evidence whose nonce does not match the request', async () => {
      const api = cloudFor(() => jsonResponse(gatewayReport('44'.repeat(32))));

      await expect(fetchGatewayAttestation(api.cloud)).rejects.toMatchObject({
        failure: {
          phase: 'api',
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

      const signature = await fetchCompletionSignature(api.cloud, {
        completionId: 'chat-1',
      });

      expect(signature).toEqual(expected);
      expect(new URL(api.request().url).pathname).toBe('/v1/signature/chat-1');
    });

    test('lets callers choose between an unavailable result and an error', async () => {
      const api = cloudFor(() =>
        jsonResponse({
          error_code: 'SIGNATURE_UNSUPPORTED',
          message: 'No provider signature',
        }),
      );

      const lookup = await lookupCompletionSignature(api.cloud, {
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
        fetchCompletionSignature(api.cloud, { completionId: 'chat-1' }),
      ).rejects.toMatchObject({
        failure: {
          phase: 'signature',
          code: 'signature.unavailable',
          details: { providerErrorCode: 'SIGNATURE_UNSUPPORTED' },
        },
      });
    });

    test('marks a pending completion signature lookup as retryable', async () => {
      const api = cloudFor(() => new Response('', { status: 404 }));

      await expect(
        lookupCompletionSignature(api.cloud, { completionId: 'chat-1' }),
      ).rejects.toMatchObject({
        failure: {
          phase: 'api',
          code: 'api.http_status',
          details: { resource: 'completion_signature', status: 404 },
          retryable: true,
        },
      });
    });

    test('does not mistake malformed signature data for an unavailable result', async () => {
      const api = cloudFor(() =>
        jsonResponse({
          error_code: 'SIGNATURE_UNSUPPORTED',
          message: 'No provider signature',
          ...completionSignature('provider_tee'),
          signature_kind: 'unknown',
        }),
      );

      await expect(
        lookupCompletionSignature(api.cloud, { completionId: 'chat-1' }),
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
  });

  describe('API errors', () => {
    test('distinguishes missing gateway evidence from a transient gateway failure', async () => {
      const missing = cloudFor(() => new Response('', { status: 404 }));
      const unavailable = cloudFor(() => new Response('', { status: 503 }));

      await expect(
        fetchGatewayAttestation(missing.cloud),
      ).rejects.toMatchObject({
        failure: {
          phase: 'api',
          code: 'api.http_status',
          details: { resource: 'gateway_attestation', status: 404 },
          retryable: false,
        },
      });
      await expect(
        fetchGatewayAttestation(unavailable.cloud),
      ).rejects.toMatchObject({
        failure: {
          phase: 'api',
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

      let error: unknown;
      try {
        await fetchModelAttestations(api.cloud, { model: 'canonical-model' });
      } catch (cause) {
        error = cause;
      }

      expect(error).toBeInstanceOf(ApiError);
      expect(error).not.toBeInstanceOf(VerificationError);
      expect(isApiError(error)).toBe(true);
      expect(isVerificationError(error)).toBe(false);
      if (!isApiError(error)) {
        return;
      }
      expect(error.failure).toMatchObject({
        phase: 'api',
        code: 'api.invalid_response',
      });
    });
  });

  describe('Cloud configuration', () => {
    test.each([
      'http://cloud-api.near.ai/v1',
      'https://cloud-api.near.ai/v1?',
      'https://cloud-api.near.ai/v1#',
    ])('rejects an unsafe base URL: %s', async (invalidBaseUrl) => {
      await expect(
        fetchGatewayAttestation({
          baseUrl: invalidBaseUrl,
          apiKey: 'test',
        }),
      ).rejects.toThrow('Invalid baseUrl');
    });
  });
});
