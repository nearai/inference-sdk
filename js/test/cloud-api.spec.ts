import { Buffer } from 'buffer';
import type {
  AttestationClientOptions,
  CompletionSignature,
  VerifiedChutesModelAttestation,
  VerifiedNearModelAttestation,
} from '../src';
import { AttestationClient, findModelAttestationForSignature } from '../src';
import {
  createCloudApiRequestConfiguration,
  mergeCloudApiRequestHeaders,
} from '../src/core/cloud-api';
import { AttestationClient as NodeAttestationClient } from '../src/node';

const baseUrl = 'https://cloud-api.near.ai/v1';
const signingAddress = `0x${'22'.repeat(20)}`;
const ohttpWireAttestation = {
  signing_algo: 'ed25519',
  signing_key: '55'.repeat(32),
  key_config: '010020',
  signature: '66'.repeat(64),
};

type RequestAuthenticationCase = {
  name: string;
  options: AttestationClientOptions;
  expectedAuthorization: string | null;
};

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

function verifiedModelAttestation(
  overrides: Partial<VerifiedNearModelAttestation> = {},
): VerifiedNearModelAttestation {
  return {
    provider: 'near',
    signer: { signingAlgo: 'ecdsa', signingAddress },
    tcbStatus: 'UpToDate',
    advisoryIds: [],
    deployment: { appCompose: '{}', runtimeMeasurements: {} },
    deploymentProvenance: 'not_checked',
    gpuEvidence: 'not_provided',
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

/** Current Cloud API Chutes response shape, with synthetic evidence bytes. */
function chutesAttestation(
  nonce: string,
  overrides: Record<string, unknown> = {},
) {
  return {
    provider: 'chutes',
    verified: true,
    model: 'canonical-model',
    instance_id: 'chutes-instance-1',
    measurement_config: '8xh200 v1.3.1',
    tcb_status: 'UpToDate',
    gpu_verdict: 'PASS',
    e2e_pubkey: Buffer.alloc(1184, 0x42).toString('base64'),
    nonce,
    quote_b64: Buffer.from('01020304', 'hex').toString('base64'),
    certificate_b64: Buffer.from('30010203', 'hex').toString('base64'),
    gpu_evidence: Array.from({ length: 8 }, (_, index) => ({
      arch: 'HOPPER',
      certificate: Buffer.from([0x30, index]).toString('base64'),
      evidence: Buffer.from([0xab, index]).toString('base64'),
    })),
    ...overrides,
  };
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

function cloudFor(
  response: (request: Request) => Response,
  options: AttestationClientOptions = { baseUrl, apiKey: 'test' },
) {
  let lastRequest: Request | undefined;
  jest.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    lastRequest = new Request(input, init);
    return response(lastRequest);
  });
  const client = new AttestationClient(options);

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

describe('request authentication', () => {
  test.each<RequestAuthenticationCase>([
    {
      name: 'uses the configured API key over both Authorization headers',
      options: {
        apiKey: 'direct-key',
        headers: { Authorization: 'Bearer proxy-token', 'x-tenant': 'default' },
      },
      expectedAuthorization: 'Bearer direct-key',
    },
    {
      name: 'keeps proxy authentication when OpenAI adds its Authorization header',
      options: {
        headers: { Authorization: 'Bearer proxy-token', 'x-tenant': 'default' },
      },
      expectedAuthorization: 'Bearer proxy-token',
    },
    {
      name: 'omits request authorization when none is configured',
      options: { headers: { 'x-tenant': 'default' } },
      expectedAuthorization: null,
    },
  ])('$name', ({ options, expectedAuthorization }) => {
    const configuration = createCloudApiRequestConfiguration(options);
    const headers = mergeCloudApiRequestHeaders({
      configuration,
      requestHeaders: {
        authorization: 'Bearer openai-key',
        'x-tenant': 'request-tenant',
      },
    });

    expect(headers.get('authorization')).toBe(expectedAuthorization);
    expect(headers.get('x-tenant')).toBe('request-tenant');
  });
});

describe('AttestationClient', () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  test.each(['not a URL', '/v1', 'ftp://cloud.example/v1'])(
    'rejects an invalid base URL: %s',
    (invalidBaseUrl) => {
      expect(
        () =>
          new AttestationClient({ apiKey: 'test', baseUrl: invalidBaseUrl }),
      ).toThrow(
        expect.objectContaining({
          failure: expect.objectContaining({
            code: 'api.invalid_input',
            details: expect.objectContaining({
              field: 'baseUrl',
              reason: 'invalid_url',
              expected: 'an absolute HTTP(S) URL without a query or fragment',
            }),
          }),
        }),
      );
    },
  );

  test.each([
    ['query', 'https://cloud.example/v1?tenant=example'],
    ['fragment', 'https://cloud.example/v1#attestation'],
  ])('rejects a base URL with a %s', (_kind, invalidBaseUrl) => {
    expect(
      () => new AttestationClient({ apiKey: 'test', baseUrl: invalidBaseUrl }),
    ).toThrow(
      expect.objectContaining({
        failure: {
          code: 'api.invalid_input',
          details: {
            field: 'baseUrl',
            reason: 'invalid_url',
            expected: 'an absolute HTTP(S) URL without a query or fragment',
          },
        },
      }),
    );
  });

  test('reports an invalid API key as client input', async () => {
    const client = new AttestationClient({
      apiKey: 'invalid\nheader',
      baseUrl,
    });

    await expect(client.fetchGatewayAttestation()).rejects.toMatchObject({
      name: 'ApiError',
      failure: {
        code: 'api.invalid_input',
        details: {
          field: 'apiKey',
          reason: 'invalid_header_value',
          expected: 'an HTTP header value',
        },
      },
    });
  });

  test('uses configured headers when no direct API key is provided', async () => {
    const api = cloudFor(
      (request) =>
        jsonResponse(
          gatewayReport(requestNonce(request), { tls_cert_fingerprint: null }),
        ),
      {
        baseUrl,
        headers: { 'x-aggregator-token': 'browser-token' },
      },
    );

    await api.client.fetchGatewayAttestation();

    expect(api.request().headers.get('x-aggregator-token')).toBe(
      'browser-token',
    );
    expect(api.request().headers.get('authorization')).toBeNull();
  });

  test('uses a direct API key over a configured authorization header', async () => {
    const api = cloudFor(
      (request) =>
        jsonResponse(
          gatewayReport(requestNonce(request), { tls_cert_fingerprint: null }),
        ),
      {
        baseUrl,
        apiKey: 'direct-key',
        headers: {
          authorization: 'Bearer aggregator-token',
          'x-tenant-id': 'tenant-a',
        },
      },
    );

    await api.client.fetchGatewayAttestation();

    expect(api.request().headers.get('authorization')).toBe(
      'Bearer direct-key',
    );
    expect(api.request().headers.get('x-tenant-id')).toBe('tenant-a');
  });

  describe('model attestations', () => {
    test('preserves every model candidate', async () => {
      const selectedSigningAddress = `0x${'44'.repeat(20)}`;
      const otherSigningAddress = `0x${'55'.repeat(20)}`;
      const signature = modelSignature(selectedSigningAddress);
      const api = cloudFor((request) => {
        const clientNonce = requestNonce(request);
        return jsonResponse(
          modelReport(clientNonce, [
            cloudAttestation(clientNonce, {
              provider: 'near',
              signing_address: otherSigningAddress,
              report_data: '55'.repeat(64),
            }),
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
          provider: 'near',
          signingAlgo: signature.signer.signingAlgo,
          signingAddress: signature.signer.signingAddress,
        });
      expect(attestations).toHaveLength(2);
      expect(
        attestations.every(
          (candidate) => candidate.nonce === clientBinding.nonce,
        ),
      ).toBe(true);

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

    test('selects a verified model attestation by signer bytes', () => {
      const signature = modelSignature(`0x${'ab'.repeat(20)}`);
      const attestation = verifiedModelAttestation({
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

    test('does not treat a Chutes routing key as a provider-signature signer', () => {
      const chutes: VerifiedChutesModelAttestation = {
        provider: 'chutes',
        tcbStatus: 'UpToDate',
        advisoryIds: [],
        publicKey: Buffer.alloc(1184, 0x42).toString('base64'),
        spkiFingerprint: '33'.repeat(32),
        gpuEvidence: 'verified',
        deployment: {
          baseline: { name: 'chutes', version: '1' },
          mrTd: '00'.repeat(48),
          rtMr0: '00'.repeat(48),
          rtMr1: '00'.repeat(48),
          rtMr2: '00'.repeat(48),
          rtMr3: '00'.repeat(48),
        },
        deploymentProvenance: 'verified',
      };
      const near = verifiedModelAttestation();
      expect(
        findModelAttestationForSignature({
          attestations: [chutes, near],
          signature: modelSignature(),
        }),
      ).toBe(near);
      expect(() =>
        findModelAttestationForSignature({
          attestations: [chutes],
          signature: modelSignature(),
        }),
      ).toThrow(
        expect.objectContaining({
          name: 'ApiError',
          failure: { code: 'api.model_attestation_signer_not_found' },
        }),
      );
    });

    test('omits provider and signer filters unless explicitly requested', async () => {
      const api = cloudFor((request) =>
        jsonResponse(modelReport(requestNonce(request))),
      );

      const fetched = await api.client.fetchModelAttestations({
        model: 'canonical-model',
      });

      const query = new URL(api.request().url).searchParams;
      expect(query.get('model')).toBe('canonical-model');
      expect(query.has('provider')).toBe(false);
      expect(query.get('nonce')).toBe(fetched.clientBinding.nonce);
      expect(query.has('signing_algo')).toBe(false);
      expect(query.has('signing_address')).toBe(false);
      expect(fetched.attestations[0].provider).toBe('near');
    });

    test('maps all raw GPU evidence from a Chutes report without NEAR-only fields', async () => {
      let wire: ReturnType<typeof chutesAttestation> | undefined;
      const api = cloudFor((request) => {
        wire = chutesAttestation(requestNonce(request));
        return jsonResponse(modelReport(requestNonce(request), [wire]));
      });

      const fetched = await api.client.fetchModelAttestations({
        model: 'canonical-model',
        provider: 'chutes',
        signingAlgo: 'ed25519',
      });
      const [attestation] = fetched.attestations;

      expect(attestation).toEqual({
        provider: 'chutes',
        nonce: fetched.clientBinding.nonce,
        intelQuote: '01020304',
        certificate: wire?.certificate_b64,
        publicKey: wire?.e2e_pubkey,
        gpuEvidence: wire?.gpu_evidence,
        instanceId: 'chutes-instance-1',
      });
      expect(attestation.gpuEvidence).toHaveLength(8);
      expect(attestation).not.toHaveProperty('signer');
      expect(attestation).not.toHaveProperty('verified');
      const query = new URL(api.request().url).searchParams;
      expect(query.get('provider')).toBe('chutes');
      expect(query.get('signing_algo')).toBe('ed25519');
    });

    test('preserves the exact Chutes nonce and key strings used by quote binding', async () => {
      const api = cloudFor((request) =>
        jsonResponse(
          modelReport(requestNonce(request), [
            chutesAttestation(requestNonce(request).toUpperCase()),
          ]),
        ),
      );

      const fetched = await api.client.fetchModelAttestations({
        model: 'canonical-model',
        provider: 'chutes',
      });

      expect(fetched.attestations[0].nonce).toBe(
        fetched.clientBinding.nonce.toUpperCase(),
      );
      expect(fetched.attestations[0].publicKey).toBe(
        Buffer.alloc(1184, 0x42).toString('base64'),
      );
    });

    test('accepts provider-selected or mixed evidence when no provider is requested', async () => {
      const api = cloudFor((request) =>
        jsonResponse(
          modelReport(requestNonce(request), [
            cloudAttestation(requestNonce(request)),
            chutesAttestation(requestNonce(request)),
          ]),
        ),
      );
      const fetched = await api.client.fetchModelAttestations({
        model: 'canonical-model',
      });

      expect(fetched.attestations.map((entry) => entry.provider)).toEqual([
        'near',
        'chutes',
      ]);
      expect(new URL(api.request().url).searchParams.has('provider')).toBe(
        false,
      );
    });

    test.each(['near', 'chutes'] as const)(
      'rejects a response that does not respect the explicit %s provider filter',
      async (provider) => {
        const api = cloudFor((request) =>
          jsonResponse(
            modelReport(requestNonce(request), [
              provider === 'near'
                ? chutesAttestation(requestNonce(request))
                : cloudAttestation(requestNonce(request)),
            ]),
          ),
        );

        await expect(
          api.client.fetchModelAttestations({
            model: 'canonical-model',
            provider,
          }),
        ).rejects.toMatchObject({
          name: 'ApiError',
          failure: {
            code: 'api.invalid_response',
            details: {
              path: 'model_attestations[0].provider',
              expected: provider,
            },
          },
        });
      },
    );

    test.each([
      { field: 'quote_b64', value: 'not base64!', path: 'quote_b64' },
      { field: 'quote_b64', value: 'YR==', path: 'quote_b64' },
      { field: 'certificate_b64', value: '', path: 'certificate_b64' },
      { field: 'e2e_pubkey', value: 'YQ==', path: 'e2e_pubkey' },
      {
        field: 'e2e_pubkey',
        value: ` ${Buffer.alloc(1184).toString('base64')}`,
        path: 'e2e_pubkey',
      },
      { field: 'nonce', value: `0x${'ab'.repeat(32)}`, path: 'nonce' },
      { field: 'nonce', value: 'not-hex', path: 'nonce' },
      {
        field: 'gpu_evidence',
        value: [{ arch: 'HOPPER', certificate: 'YQ==', evidence: 'invalid' }],
        path: 'gpu_evidence[0].evidence',
      },
      {
        field: 'gpu_evidence',
        value: [{ arch: 'HOPPER', certificate: 'YQ==' }],
        path: 'gpu_evidence[0].evidence',
      },
      { field: 'gpu_evidence', value: 'not-an-array', path: 'gpu_evidence' },
      { field: 'provider', value: 'unknown', path: 'provider' },
    ])(
      'wraps malformed Chutes $field in ApiError ($path)',
      async ({ field, value, path }) => {
        const api = cloudFor((request) =>
          jsonResponse(
            modelReport(requestNonce(request), [
              chutesAttestation(requestNonce(request), { [field]: value }),
            ]),
          ),
        );

        await expect(
          api.client.fetchModelAttestations({
            model: 'canonical-model',
            provider: 'chutes',
          }),
        ).rejects.toMatchObject({
          name: 'ApiError',
          failure: {
            code: 'api.invalid_response',
            details: { path: `model_attestations[0].${path}` },
          },
        });
      },
    );

    test('rejects an invalid signer filter before requesting model evidence', async () => {
      const api = cloudFor(() => {
        throw new Error('The client must reject this before making a request');
      });

      await expect(
        api.client.fetchModelAttestations({
          model: 'canonical-model',
          signingAddress: 'not hexadecimal',
        }),
      ).rejects.toMatchObject({
        name: 'ApiError',
        failure: {
          code: 'api.invalid_input',
          details: {
            field: 'signingAddress',
            reason: 'invalid_hex',
          },
        },
      });
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
        provider: 'near',
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

    test('checks every model candidate nonce', async () => {
      const api = cloudFor((request) => {
        const clientNonce = requestNonce(request);
        return jsonResponse(
          modelReport(clientNonce, [
            cloudAttestation(clientNonce),
            cloudAttestation('44'.repeat(32)),
          ]),
        );
      });

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

    test('returns an empty model-attestation collection when Cloud API omits it', async () => {
      const api = cloudFor(() => jsonResponse({}));

      const fetched = await api.client.fetchModelAttestations({
        model: 'canonical-model',
      });

      expect(fetched.attestations).toEqual([]);
    });

    test('returns all model attestations when Cloud API returns multiple candidates', async () => {
      const api = cloudFor((request) => {
        const clientNonce = requestNonce(request);
        return jsonResponse(
          modelReport(clientNonce, [
            cloudAttestation(clientNonce),
            cloudAttestation(clientNonce),
          ]),
        );
      });

      const fetched = await api.client.fetchModelAttestations({
        model: 'canonical-model',
      });

      expect(fetched.attestations).toHaveLength(2);
      expect(
        fetched.attestations.every(
          (attestation) => attestation.nonce === fetched.clientBinding.nonce,
        ),
      ).toBe(true);
    });

    test.each([
      {
        label: 'a provider signer with no matching attestation',
        attestations: [verifiedModelAttestation()],
        signature: modelSignature(`0x${'44'.repeat(20)}`),
        failure: {
          code: 'api.model_attestation_signer_not_found',
        },
      },
      {
        label: 'multiple attestations for the same signer',
        attestations: [verifiedModelAttestation(), verifiedModelAttestation()],
        signature: modelSignature(),
        failure: {
          code: 'api.ambiguous_model_attestation_signer',
          details: { matchingCount: 2, totalCount: 2 },
        },
      },
      {
        label: 'a gateway signature',
        attestations: [verifiedModelAttestation()],
        signature: gatewaySignature(),
        failure: {
          code: 'api.invalid_input',
          details: {
            field: 'signature.kind',
            reason: 'unsupported_value',
            expected: 'provider_tee',
            actual: 'gateway',
          },
        },
      },
    ])('rejects $label', ({ attestations, signature, failure }) => {
      expect(() =>
        findModelAttestationForSignature({ attestations, signature }),
      ).toThrow(expect.objectContaining({ failure }));
    });

    test('reports malformed manually supplied signers as an API helper input error', () => {
      const signature = modelSignature('not hexadecimal');

      expect(() =>
        findModelAttestationForSignature({
          attestations: [verifiedModelAttestation()],
          signature,
        }),
      ).toThrow(
        expect.objectContaining({
          name: 'ApiError',
          failure: expect.objectContaining({
            code: 'api.invalid_input',
            details: expect.objectContaining({
              field: 'signature.signer.signingAddress',
              reason: 'invalid_hex',
            }),
          }),
        }),
      );
    });
  });

  describe('gateway attestations', () => {
    test('preserves the envelope OHTTP attestation on the Gateway evidence', async () => {
      const api = cloudFor((request) =>
        jsonResponse({
          ...gatewayReport(requestNonce(request), {
            tls_cert_fingerprint: null,
          }),
          ohttp_attestation: ohttpWireAttestation,
        }),
      );

      const { attestation } = await api.client.fetchGatewayAttestation();
      expect(attestation.ohttpAttestation).toEqual({
        signingAlgo: 'ed25519',
        signingKey: ohttpWireAttestation.signing_key,
        keyConfig: ohttpWireAttestation.key_config,
        signature: ohttpWireAttestation.signature,
      });
    });

    test.each([undefined, null])(
      'normalizes absent OHTTP Gateway metadata: %s',
      async (ohttpAttestation) => {
        const api = cloudFor((request) =>
          jsonResponse({
            ...gatewayReport(requestNonce(request), {
              tls_cert_fingerprint: null,
            }),
            ohttp_attestation: ohttpAttestation,
          }),
        );

        const { attestation } = await api.client.fetchGatewayAttestation();
        expect(attestation).not.toHaveProperty('ohttpAttestation');
      },
    );

    test.each([
      ['signing_algo', 'ecdsa'],
      ['signing_key', 'ab'],
      ['key_config', null],
      ['key_config', 'not-hex'],
      ['signature', undefined],
    ])(
      'rejects malformed OHTTP Gateway metadata at %s',
      async (field, value) => {
        const api = cloudFor((request) =>
          jsonResponse({
            ...gatewayReport(requestNonce(request), {
              tls_cert_fingerprint: null,
            }),
            ohttp_attestation: { ...ohttpWireAttestation, [field]: value },
          }),
        );

        await expect(
          api.client.fetchGatewayAttestation(),
        ).rejects.toMatchObject({
          name: 'ApiError',
          failure: {
            code: 'api.invalid_response',
            details: { path: `ohttp_attestation.${field}` },
          },
        });
      },
    );

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

    test('Node client defaults to TLS binding and can opt out', async () => {
      const capturedPeerRequests: boolean[] = [];
      class TestNodeClient extends NodeAttestationClient {
        protected override async requestGatewayAttestation(
          request: Request,
          capturePeerSpkiFingerprint: boolean,
        ) {
          capturedPeerRequests.push(capturePeerSpkiFingerprint);
          const tlsCertFingerprint = capturePeerSpkiFingerprint
            ? '33'.repeat(32)
            : null;
          return {
            response: jsonResponse(
              gatewayReport(requestNonce(request), {
                tls_cert_fingerprint: tlsCertFingerprint,
              }),
            ),
            ...(capturePeerSpkiFingerprint
              ? { peerSpkiFingerprint: '33'.repeat(32) }
              : {}),
          };
        }
      }

      const client = new TestNodeClient({ apiKey: 'test', baseUrl });
      const withTls = await client.fetchGatewayAttestation();
      const withoutTls = await client.fetchGatewayAttestation({
        includeSpkiFingerprint: false,
      });

      expect(capturedPeerRequests).toEqual([true, false]);
      expect(withTls.attestation.spkiFingerprint).toBe('33'.repeat(32));
      expect(withTls.clientBinding.spkiFingerprint).toBe('33'.repeat(32));
      expect(withoutTls.attestation.spkiFingerprint).toBeUndefined();
      expect(withoutTls.clientBinding.spkiFingerprint).toBeUndefined();
    });

    test('Node client supports no-TLS Gateway evidence from an HTTP endpoint', async () => {
      let receivedRequest: Request | undefined;
      jest
        .spyOn(globalThis, 'fetch')
        .mockImplementation(async (input, init) => {
          receivedRequest = new Request(input, init);
          return jsonResponse(
            gatewayReport(requestNonce(receivedRequest), {
              tls_cert_fingerprint: null,
            }),
          );
        });
      const client = new NodeAttestationClient({
        apiKey: 'test',
        baseUrl: 'http://cloud.example/v1',
      });

      const fetched = await client.fetchGatewayAttestation({
        includeSpkiFingerprint: false,
      });

      expect(fetched.attestation.spkiFingerprint).toBeUndefined();
      if (receivedRequest === undefined) {
        throw new Error('Expected an HTTP Gateway evidence request');
      }
      expect(
        new URL(receivedRequest.url).searchParams.get(
          'include_tls_fingerprint',
        ),
      ).toBe('false');
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

    test('reports an unavailable completion signature as an API error', async () => {
      const api = cloudFor(() =>
        jsonResponse({
          error_code: 'SIGNATURE_UNSUPPORTED',
          message: 'No provider signature',
        }),
      );

      await expect(
        api.client.fetchCompletionSignature({
          completionId: 'chat-1',
        }),
      ).rejects.toMatchObject({
        failure: {
          code: 'api.completion_signature_unavailable',
          details: {
            providerErrorCode: 'SIGNATURE_UNSUPPORTED',
            providerMessage: 'No provider signature',
          },
        },
      });
    });

    test('marks a 404 completion-signature response as retryable', async () => {
      const api = cloudFor(() => new Response('', { status: 404 }));

      await expect(
        api.client.fetchCompletionSignature({
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
