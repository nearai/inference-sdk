import {
  DirectApiClient,
  DirectAttestationClient,
  type DirectAttestationHttpResponse,
} from '../src/core/direct-api';
import type {
  DirectAttestationClientOptions,
  NodeFetchDirectAttestationReportParams,
} from '../src/types/direct-api';

const baseUrl = 'https://model.example/v1';
const signingAddress = '22'.repeat(32);
const spkiFingerprint = '33'.repeat(32);

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
  fetchAttestationReport({
    includeSpkiFingerprint = true,
    ...params
  }: NodeFetchDirectAttestationReportParams = {}) {
    return this.fetchAttestationReportWithOptions({
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

  test('preserves reports with a shared signer and reuses an identical root', async () => {
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
    const { report, clientBinding } = await api.client.fetchAttestationReport({
      signingAlgo: 'ed25519',
      signingAddress,
    });

    expect(report.attestations).toHaveLength(2);
    expect(report.attestation).toBe(report.attestations[0]);
    expect(report.attestations.map((item) => item.instanceId)).toEqual([
      'instance-a',
      'instance-b',
    ]);
    expect(report.attestation).toEqual({
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
    expect(report.composeManagerAttestation).toEqual({ opaque: 'evidence' });
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

    const next = await api.client.fetchAttestationReport();
    expect(next.clientBinding.nonce).not.toBe(clientBinding.nonce);
  });

  test('does not substitute a root with different evidence from the same instance', async () => {
    const api = directFor((request) =>
      jsonResponse({ ...reportFor(request), intel_quote: 'bb' }),
    );
    const { report } = await api.client.fetchAttestationReport();
    expect(report.attestation).not.toBe(report.attestations[0]);
    expect(report.attestation.intelQuote).toBe('bb');
    expect(report.attestations[0].intelQuote).toBe('aa');
  });

  test.each(['root', 0, 1] as const)(
    'checks the fresh nonce in report %s',
    async (target) => {
      const api = directFor((request) => {
        const report = reportFor(request);
        const entry =
          target === 'root' ? report : report.all_attestations[target];
        entry.request_nonce = '00'.repeat(32);
        return jsonResponse(report);
      });
      await expect(api.client.fetchAttestationReport()).rejects.toMatchObject({
        name: 'ApiError',
        failure: { code: 'api.nonce_mismatch' },
      });
    },
  );

  test.each([undefined, []])(
    'rejects a missing or empty report array: %p',
    async (entries) => {
      const api = directFor((request) =>
        jsonResponse({ ...reportFor(request), all_attestations: entries }),
      );
      await expect(api.client.fetchAttestationReport()).rejects.toMatchObject({
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
        const entry = target === 'root' ? report : report.all_attestations[1];
        entry.tls_cert_fingerprint = include ? null : spkiFingerprint;
        return jsonResponse(report);
      });
      const client = new CapturingDirectClient({ baseUrl });
      await expect(
        client.fetchAttestationReport({ includeSpkiFingerprint: include }),
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
    const result = await client.fetchAttestationReport();
    expect(
      new URL(api.requests[0].url).searchParams.get('include_tls_fingerprint'),
    ).toBe('true');
    expect(result.clientBinding.spkiFingerprint).toBe(spkiFingerprint);
    expect(
      result.report.attestations.map((entry) => entry.spkiFingerprint),
    ).toEqual([spkiFingerprint, spkiFingerprint]);
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
      await api.client.fetchAttestationReport();
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
