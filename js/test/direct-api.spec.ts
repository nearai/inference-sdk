import {
  DirectApiClient,
  DirectAttestationClient,
  type DirectAttestationHttpResponse,
} from '../src/core/direct-api';
import type {
  DirectAttestationClientOptions,
  NodeFetchDirectModelAttestationsParams,
} from '../src/types/direct-api';

const baseUrl = 'https://model.example/v1';
const signingAddress = '22'.repeat(32);
const spkiFingerprint = '33'.repeat(32);
const ohttpWireAttestation = {
  signing_algo: 'ed25519',
  signing_key: signingAddress,
  key_config: '010020',
  signature: '66'.repeat(64),
};

function attestation(nonce: string, instanceId: string) {
  return {
    model_name: 'provider-model',
    request_nonce: nonce,
    signing_algo: 'ed25519',
    signing_address: signingAddress,
    signing_public_key: '44'.repeat(32),
    intel_quote: 'aa',
    event_log: [],
    info: {
      instance_id: instanceId,
      tcb_info: { app_compose: '{}' },
    },
    report_data: '55'.repeat(64),
    nvidia_payload: 'gpu-evidence',
    tls_cert_fingerprint: null as string | null,
  };
}

function reportFor(request: Request) {
  const nonce = new URL(request.url).searchParams.get('nonce');
  if (nonce === null) {
    throw new Error('Expected a direct attestation nonce');
  }
  return {
    ...attestation(nonce, 'instance-a'),
    all_attestations: [
      attestation(nonce, 'instance-a'),
      attestation(nonce, 'instance-b'),
    ],
    compose_manager_attestation: { opaque: 'evidence' },
  };
}

function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), { status });
}

function directFor(
  response: (request: Request) => Response,
  options: DirectAttestationClientOptions = { baseUrl },
) {
  const requests: Request[] = [];
  jest.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const request = new Request(input, init);
    requests.push(request);
    return response(request);
  });
  return { client: new DirectAttestationClient(options), requests };
}

class CapturingDirectClient extends DirectApiClient {
  fetchModelAttestations({
    includeSpkiFingerprint = true,
    ...params
  }: NodeFetchDirectModelAttestationsParams = {}) {
    return this.fetchModelAttestationsWithOptions({
      ...params,
      includeSpkiFingerprint,
    });
  }

  protected override async requestAttestation(
    request: Request,
    capturePeerSpkiFingerprint: boolean,
  ): Promise<DirectAttestationHttpResponse> {
    return {
      response: await fetch(request),
      ...(capturePeerSpkiFingerprint
        ? { peerSpkiFingerprint: spkiFingerprint }
        : {}),
    };
  }
}

describe('DirectAttestationClient', () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  test('preserves OHTTP metadata on the response envelope without changing serving evidence', async () => {
    const api = directFor((request) =>
      jsonResponse({
        ...reportFor(request),
        ohttp_attestation: ohttpWireAttestation,
      }),
    );

    const result = await api.client.fetchModelAttestations();
    expect(result.ohttpAttestation).toEqual({
      signingAlgo: 'ed25519',
      signingKey: ohttpWireAttestation.signing_key,
      keyConfig: ohttpWireAttestation.key_config,
      signature: ohttpWireAttestation.signature,
    });
    expect(result.servingAttestation).toBe(result.attestations[0]);
    for (const attestation of result.attestations) {
      expect(attestation).not.toHaveProperty('ohttpAttestation');
    }
  });

  test.each([undefined, null])(
    'normalizes absent OHTTP direct metadata: %s',
    async (ohttpAttestation) => {
      const api = directFor((request) =>
        jsonResponse({
          ...reportFor(request),
          ohttp_attestation: ohttpAttestation,
        }),
      );

      const result = await api.client.fetchModelAttestations();
      expect(result).not.toHaveProperty('ohttpAttestation');
    },
  );

  test.each([
    ['signing_algo', 'ecdsa'],
    ['signing_key', 'ab'],
    ['key_config', null],
    ['key_config', 'not-hex'],
    ['signature', undefined],
  ])('rejects malformed OHTTP direct metadata at %s', async (field, value) => {
    const api = directFor((request) =>
      jsonResponse({
        ...reportFor(request),
        ohttp_attestation: { ...ohttpWireAttestation, [field]: value },
      }),
    );

    await expect(api.client.fetchModelAttestations()).rejects.toMatchObject({
      name: 'ApiError',
      failure: {
        code: 'api.invalid_response',
        details: { path: `ohttp_attestation.${field}` },
      },
    });
  });

  test('preserves model attestations with a shared signer and reuses identical serving evidence', async () => {
    const api = directFor((request) => {
      const report = reportFor(request);
      // Both supported tcb_info wire forms normalize to the same evidence.
      return jsonResponse({
        ...report,
        info: {
          ...report.info,
          tcb_info: JSON.stringify(report.info.tcb_info),
        },
      });
    });
    const { servingAttestation, attestations, clientBinding } =
      await api.client.fetchModelAttestations({
        signingAlgo: 'ed25519',
        signingAddress,
      });

    expect(attestations).toHaveLength(2);
    expect(servingAttestation).toBe(attestations[0]);
    expect(attestations.map((item) => item.instanceId)).toEqual([
      'instance-a',
      'instance-b',
    ]);
    expect(servingAttestation).toEqual({
      nonce: clientBinding.nonce,
      signer: { signingAlgo: 'ed25519', signingAddress },
      intelQuote: 'aa',
      eventLog: [],
      appCompose: '{}',
      signingPublicKey: '44'.repeat(32),
      reportedQuoteData: '55'.repeat(64),
      nvidiaPayload: 'gpu-evidence',
      modelName: 'provider-model',
      instanceId: 'instance-a',
    });
    const request = api.requests[0];
    const url = new URL(request.url);
    expect(url.pathname).toBe('/v1/attestation/report');
    expect(Object.fromEntries(url.searchParams)).toEqual({
      nonce: clientBinding.nonce,
      signing_algo: 'ed25519',
      signing_address: signingAddress,
      include_tls_fingerprint: 'false',
    });
    expect(request.headers.has('authorization')).toBe(false);
    expect(request.headers.has('x-no-aliasing')).toBe(false);
    expect(clientBinding).toEqual({
      nonce: expect.stringMatching(/^[a-f0-9]{64}$/),
    });

    const next = await api.client.fetchModelAttestations();
    expect(next.clientBinding.nonce).not.toBe(clientBinding.nonce);
  });

  test('requires a direct base URL at runtime', () => {
    const createClientWithoutBaseUrl = () => {
      // @ts-expect-error JavaScript callers can omit a required property.
      return new DirectAttestationClient({ apiKey: 'direct-key' });
    };

    expect(createClientWithoutBaseUrl).toThrow('[api.invalid_input]');
  });

  test('matches serving evidence regardless of nested event-log object key order', async () => {
    const api = directFor((request) => {
      const report = reportFor(request);
      return jsonResponse({
        ...report,
        event_log: [
          { imr: 3, measurement: { algorithm: 'sha384', digest: 'aa' } },
        ],
        all_attestations: [
          {
            ...report.all_attestations[0],
            event_log: [
              { measurement: { digest: 'aa', algorithm: 'sha384' }, imr: 3 },
            ],
          },
        ],
      });
    });

    const { servingAttestation, attestations } =
      await api.client.fetchModelAttestations();
    expect(servingAttestation).toBe(attestations[0]);
  });

  test.each([
    {
      change: 'changed event data',
      events: [{ digest: 'cc' }, { digest: 'bb' }],
    },
    {
      change: 'reordered events',
      events: [{ digest: 'bb' }, { digest: 'aa' }],
    },
  ])('rejects serving evidence with $change', async ({ events }) => {
    const api = directFor((request) => {
      const report = reportFor(request);
      return jsonResponse({
        ...report,
        event_log: [{ digest: 'aa' }, { digest: 'bb' }],
        all_attestations: [
          { ...report.all_attestations[0], event_log: events },
        ],
      });
    });

    await expect(api.client.fetchModelAttestations()).rejects.toMatchObject({
      failure: {
        code: 'api.invalid_response',
        details: { path: 'all_attestations' },
      },
    });
  });

  test('rejects a serving attestation absent from the complete attestation set', async () => {
    const api = directFor((request) =>
      jsonResponse({ ...reportFor(request), intel_quote: 'bb' }),
    );
    await expect(api.client.fetchModelAttestations()).rejects.toMatchObject({
      name: 'ApiError',
      failure: {
        code: 'api.invalid_response',
        details: { path: 'all_attestations' },
      },
    });
  });

  test.each([
    { label: 'serving entry', entries: [0] },
    { label: 'another entry', entries: [1] },
  ])('checks the fresh nonce in $label', async ({ entries }) => {
    const api = directFor((request) => {
      const report = reportFor(request);
      if (entries.includes(0)) {
        report.request_nonce = '00'.repeat(32);
      }
      for (const entry of entries.map(
        (index) => report.all_attestations[index],
      )) {
        entry.request_nonce = '00'.repeat(32);
      }
      return jsonResponse(report);
    });
    await expect(api.client.fetchModelAttestations()).rejects.toMatchObject({
      name: 'ApiError',
      failure: { code: 'api.nonce_mismatch' },
    });
  });

  test.each([undefined, []])(
    'rejects a missing or empty model-attestation array: %p',
    async (entries) => {
      const api = directFor((request) =>
        jsonResponse({ ...reportFor(request), all_attestations: entries }),
      );
      await expect(api.client.fetchModelAttestations()).rejects.toMatchObject({
        name: 'ApiError',
        failure: {
          code: 'api.invalid_response',
          details: { path: 'all_attestations' },
        },
      });
    },
  );

  test.each([
    { include: false, target: 'root' },
    { include: false, target: 'array' },
    { include: true, target: 'root' },
    { include: true, target: 'array' },
  ])(
    'requires TLS presence to match include=$include for $target',
    async ({ include, target }) => {
      directFor((request) => {
        const report = reportFor(request);
        for (const entry of [report, ...report.all_attestations]) {
          entry.tls_cert_fingerprint = include ? spkiFingerprint : null;
        }
        const entries =
          target === 'root'
            ? [report, report.all_attestations[0]]
            : [report.all_attestations[1]];
        for (const entry of entries) {
          entry.tls_cert_fingerprint = include ? null : spkiFingerprint;
        }
        return jsonResponse(report);
      });
      const client = new CapturingDirectClient({ baseUrl });
      await expect(
        client.fetchModelAttestations({ includeSpkiFingerprint: include }),
      ).rejects.toMatchObject({
        name: 'ApiError',
        failure: {
          code: 'api.invalid_response',
          details: {
            path: `${target === 'root' ? 'attestation' : 'all_attestations[1]'}.tls_cert_fingerprint`,
          },
        },
      });
    },
  );

  test('keeps TLS evidence and the independently observed peer binding', async () => {
    const api = directFor((request) => {
      const report = reportFor(request);
      for (const entry of [report, ...report.all_attestations]) {
        entry.tls_cert_fingerprint = spkiFingerprint;
      }
      return jsonResponse(report);
    });
    const client = new CapturingDirectClient({ baseUrl });
    const result = await client.fetchModelAttestations();
    expect(
      new URL(api.requests[0].url).searchParams.get('include_tls_fingerprint'),
    ).toBe('true');
    expect(result.clientBinding.spkiFingerprint).toBe(spkiFingerprint);
    expect(result.attestations.map((entry) => entry.spkiFingerprint)).toEqual([
      spkiFingerprint,
      spkiFingerprint,
    ]);
  });

  test.each([
    { apiKey: 'direct-key', expected: 'Bearer direct-key' },
    { apiKey: undefined, expected: 'Bearer proxy-token' },
  ])(
    'preserves configured authentication (apiKey=$apiKey)',
    async ({ apiKey, expected }) => {
      const api = directFor((request) => jsonResponse(reportFor(request)), {
        baseUrl,
        apiKey,
        headers: { Authorization: 'Bearer proxy-token', 'x-tenant': 'tenant' },
      });
      await api.client.fetchModelAttestations();
      expect(api.requests[0].headers.get('authorization')).toBe(expected);
      expect(api.requests[0].headers.get('x-tenant')).toBe('tenant');
    },
  );

  test.each([undefined, 'provider_tee'])(
    'maps direct signatures to provider_tee (wire kind=%s)',
    async (kind) => {
      const api = directFor(() =>
        jsonResponse({
          text: 'request:response',
          signature: '00',
          signing_address: signingAddress,
          signing_algo: 'ed25519',
          signature_kind: kind,
        }),
      );
      await expect(
        api.client.fetchCompletionSignature({
          completionId: 'chat/id',
          signingAlgo: 'ed25519',
        }),
      ).resolves.toEqual({
        kind: 'provider_tee',
        signedText: 'request:response',
        signature: '00',
        signer: { signingAlgo: 'ed25519', signingAddress },
      });
      expect(api.requests[0].url).toBe(
        `${baseUrl}/signature/chat%2Fid?signing_algo=ed25519`,
      );
    },
  );

  test('rejects explicit Gateway signatures', async () => {
    const api = directFor(() =>
      jsonResponse({
        text: 'request:response',
        signature: '00',
        signing_address: signingAddress,
        signing_algo: 'ed25519',
        signature_kind: 'gateway',
      }),
    );
    await expect(
      api.client.fetchCompletionSignature({ completionId: 'chat' }),
    ).rejects.toMatchObject({
      name: 'ApiError',
      failure: { code: 'api.invalid_response' },
    });
  });

  test('preserves unavailable-signature API errors', async () => {
    const api = directFor(() =>
      jsonResponse({ error_code: 'not_found', message: 'Not ready' }),
    );
    await expect(
      api.client.fetchCompletionSignature({ completionId: 'chat' }),
    ).rejects.toMatchObject({
      name: 'ApiError',
      failure: {
        code: 'api.completion_signature_unavailable',
        details: {
          providerErrorCode: 'not_found',
          providerMessage: 'Not ready',
        },
      },
    });
  });
});
