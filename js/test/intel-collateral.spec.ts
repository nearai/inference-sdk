import { Buffer } from 'node:buffer';
import { createServer, type Server } from 'node:http';
import { performance } from 'node:perf_hooks';
import { Quote, getCollateral, utils, verify } from '@phala/dcap-qvl';
import { createTdxQuoteVerifier, createVerificationContext } from '../src';
import { getIntelCollateral } from '../src/utils/intel-collateral';
import { createDeferred } from './fixtures';
import {
  collateralResponse,
  intelFixtureTime,
  intelQuoteBytes,
  quoteWithOtherFmspc,
} from './intel-fixtures';

describe('operation-scoped Intel collateral retrieval', () => {
  let server: Server;
  let base: string;
  let requests: string[];
  let respond: (url: string) => Response | Promise<Response>;

  beforeAll(async () => {
    server = createServer(async (request, response) => {
      const url = `${base}${request.url}`;
      requests.push(url);
      const fixture = await respond(url);
      response.writeHead(fixture.status, Object.fromEntries(fixture.headers));
      response.end(Buffer.from(await fixture.arrayBuffer()));
    });
    await new Promise<void>((resolve) =>
      server.listen(0, '127.0.0.1', resolve),
    );
    const address = server.address();
    if (!address || typeof address === 'string')
      throw new Error('No fixture address');
    base = `http://127.0.0.1:${address.port}`;
  });
  afterAll(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
  });
  beforeEach(() => {
    requests = [];
    respond = (url) => {
      const response = collateralResponse(url);
      // Match Cloud UI's existing proxy with HTTP caching explicitly disabled.
      response.headers.set('cache-control', 'no-store, no-transform');
      return response;
    };
    jest.spyOn(Date, 'now').mockReturnValue(intelFixtureTime);
  });
  afterEach(() => jest.restoreAllMocks());

  test('reduces three quote retrievals with two FMSPCs from twelve GETs to five', async () => {
    const quotes = [intelQuoteBytes, quoteWithOtherFmspc(), intelQuoteBytes];
    const baselineStarted = performance.now();
    const baseline = [];
    for (const quote of quotes) baseline.push(await getCollateral(base, quote));
    const baselineMs = performance.now() - baselineStarted;
    expect(requests).toHaveLength(12);
    expect(new Set(requests).size).toBe(5);
    requests = [];
    const retrieval = jest.fn(globalThis.fetch.bind(globalThis));
    const context = createVerificationContext({ fetch: retrieval });
    const started = performance.now();
    const optimized = await Promise.all(
      quotes
        .slice(0, 2)
        .map((quote) => getIntelCollateral(base, Quote.parse(quote), context)),
    );
    // Nested Compose Manager verification begins after its parent's quote.
    optimized.push(
      await getIntelCollateral(base, Quote.parse(quotes[2]), context),
    );
    expect(optimized).toEqual(baseline);
    expect(retrieval).toHaveBeenCalledTimes(5);
    expect(requests).toHaveLength(5);
    expect(new Set(requests).size).toBe(5);
    if (process.env.COLLATERAL_BENCHMARK === '1') {
      console.info(
        JSON.stringify({
          fixture:
            'three quotes, two FMSPCs; local HTTP, no browser/proxy caching',
          baseline: {
            quoteRetrievals: 3,
            resourceGetCalls: 12,
            networkRequests: 12,
            retrievalMs: baselineMs,
          },
          optimized: {
            quoteRetrievals: 3,
            resourceGetCalls: retrieval.mock.calls.length,
            networkRequests: requests.length,
            retrievalMs: performance.now() - started,
          },
        }),
      );
    }
  });

  test('preserves the complete real DCAP verdict and independently verifies reused material', async () => {
    const baseline = await getCollateral(base, intelQuoteBytes);
    const baselineStarted = performance.now();
    const expected = verify(intelQuoteBytes, baseline, intelFixtureTime / 1000);
    const baselineVerificationMs = performance.now() - baselineStarted;
    const context = createVerificationContext();
    const actual = await getIntelCollateral(
      base,
      Quote.parse(intelQuoteBytes),
      context,
    );
    expect(actual).toEqual(baseline);
    const verificationStarted = performance.now();
    const actualVerdict = verify(
      intelQuoteBytes,
      actual,
      intelFixtureTime / 1000,
    );
    const verificationMs = performance.now() - verificationStarted;
    expect(actualVerdict).toEqual(expected);
    if (process.env.COLLATERAL_BENCHMARK === '1') {
      console.info(
        JSON.stringify({
          fixture: 'signed DCAP fixture, fixed verification time',
          baselineVerificationMs,
          verificationMs,
          verdictsEqual: true,
        }),
      );
    }
    const verifier = createTdxQuoteVerifier({ pccsUrl: base, context });
    const first = await verifier(intelQuoteBytes.toString('hex'));
    const second = await verifier(intelQuoteBytes.toString('hex'));
    expect(second).toEqual(first);
    // A changed quote cannot borrow a successful verdict for the same collateral.
    const changed = Buffer.from(intelQuoteBytes);
    changed[100] ^= 1;
    await expect(verifier(changed.toString('hex'))).rejects.toMatchObject({
      failure: { code: 'quote.verification_failed' },
    });
    expect(requests).toHaveLength(8); // four baseline + four optimized, no verdict cache
  });

  test('keeps different PCK chains and different sources isolated', async () => {
    const context = createVerificationContext();
    const first = await getIntelCollateral(
      base,
      Quote.parse(intelQuoteBytes),
      context,
    );
    const other = Quote.parse(intelQuoteBytes);
    const chain = `${Buffer.from(other.rawCertChain()).toString('utf8')}\n`;
    jest.spyOn(other, 'rawCertChain').mockReturnValue(Buffer.from(chain));
    const second = await getIntelCollateral(base, other, context);
    expect(
      (second as typeof second & { pck_certificate_chain: string })
        .pck_certificate_chain,
    ).toBe(chain);
    expect(second).not.toEqual(first);
    expect(requests).toHaveLength(4);
    await getIntelCollateral(`${base}/other-source`, other, context);
    expect(requests).toHaveLength(8);
    await getIntelCollateral(base, other, createVerificationContext());
    expect(requests).toHaveLength(12);
  });

  test.each(['tcb-signature', 'qe-signature', 'pck-crl', 'root-crl'] as const)(
    'preserves real cryptographic failures for modified %s',
    async (modified) => {
      respond = async (url) => {
        const response = collateralResponse(url);
        const target =
          modified === 'tcb-signature'
            ? '/tcb'
            : modified === 'qe-signature'
              ? '/qe/identity'
              : modified === 'pck-crl'
                ? '/pckcrl'
                : '/rootcacrl';
        if (!new URL(url).pathname.endsWith(target)) return response;
        if (modified.endsWith('signature')) {
          const body = await response.json();
          body.signature = '00'.repeat(64);
          return new Response(JSON.stringify(body), {
            headers: response.headers,
          });
        }
        const body =
          modified === 'root-crl'
            ? Buffer.from(await response.text(), 'hex')
            : Buffer.from(await response.arrayBuffer());
        body[body.length - 1] ^= 1;
        return new Response(
          modified === 'root-crl' ? body.toString('hex') : body,
          { headers: response.headers },
        );
      };
      const baseline = await getCollateral(base, intelQuoteBytes);
      const actual = await getIntelCollateral(
        base,
        Quote.parse(intelQuoteBytes),
        createVerificationContext(),
      );
      expect(actual).toEqual(baseline);
      const failure = (collateral: typeof baseline) => {
        try {
          verify(intelQuoteBytes, collateral, intelFixtureTime / 1000);
        } catch (error) {
          return {
            name: (error as Error).name,
            message: (error as Error).message,
          };
        }
        throw new Error('Modified signed material unexpectedly accepted');
      };
      expect(failure(actual)).toEqual(failure(baseline));
      await expect(
        createTdxQuoteVerifier({ pccsUrl: base })(
          intelQuoteBytes.toString('hex'),
        ),
      ).rejects.toMatchObject({
        failure: {
          code: 'quote.verification_failed',
          details: { reason: 'verifier_error' },
        },
      });
    },
  );

  test('keeps encrypted-PPID certificate lookups independent and validates returned TCB', async () => {
    const original = Quote.parse(intelQuoteBytes);
    const pem = utils
      .extractCerts(Buffer.from(original.rawCertChain()))
      .map((der) => utils.derToPem(der, 'CERTIFICATE'));
    const cpusvn = Buffer.alloc(16, 7);
    let wrongTcb = false;
    respond = (url) => {
      if (!url.includes('/pckcert?')) return collateralResponse(url);
      const tcbm = Buffer.concat([
        cpusvn,
        Buffer.from([wrongTcb ? 2 : 1, 0]),
      ]).toString('hex');
      return new Response(pem[0], {
        headers: {
          'SGX-PCK-Certificate-Issuer-Chain': encodeURIComponent(
            pem.slice(1).join('\n'),
          ),
          'SGX-TCBm': tcbm,
        },
      });
    };
    const quote = Object.assign(Object.create(original) as Quote, {
      innerCertType: () => 3,
      encryptedPpidParams: () => ({
        qeid: Buffer.alloc(16),
        encryptedPpid: Buffer.alloc(384),
        cpusvn,
        pcesvn: 1,
        pceid: Buffer.alloc(2),
      }),
    });
    const context = createVerificationContext();
    await getIntelCollateral(base, quote, context);
    await getIntelCollateral(base, quote, context);
    expect(requests.filter((url) => url.includes('/pckcert?'))).toHaveLength(2);
    expect(requests).toHaveLength(6);
    wrongTcb = true;
    await expect(getIntelCollateral(base, quote, context)).rejects.toThrow(
      'TCB level mismatch',
    );
  });

  test('distinguishes SGX/TDX resources and CA type', async () => {
    const context = createVerificationContext();
    const quote = Quote.parse(intelQuoteBytes);
    await getIntelCollateral(base, quote, context);
    jest.spyOn(quote.header, 'isSgx').mockReturnValue(true);
    await getIntelCollateral(base, quote, context);
    expect(requests).toHaveLength(6); // shared PCK/root, distinct TCB/QE namespaces
    const issuerUtils = utils as typeof utils & {
      getCertIssuer(cert: Buffer): string;
    };
    jest
      .spyOn(issuerUtils, 'getCertIssuer')
      .mockReturnValue('Intel SGX PCK Processor CA');
    await getIntelCollateral(base, quote, context);
    expect(requests).toHaveLength(7);
    expect(requests.at(-1)).toContain('ca=processor&encoding=der');
  });

  test('starts independent downloads together and retains PCK error precedence', async () => {
    const allStarted = createDeferred<void>();
    const pckRelease = createDeferred<void>();
    let started = 0;
    respond = async (url) => {
      if (++started === 3) allStarted.resolve();
      if (url.includes('/pckcrl')) {
        await pckRelease.promise;
        return new Response(null, { status: 502 });
      }
      return new Response(null, { status: 503 });
    };
    const context = createVerificationContext();
    const request = getIntelCollateral(
      base,
      Quote.parse(intelQuoteBytes),
      context,
    );
    const failure = expect(request).rejects.toThrow(
      'Failed to fetch PCK CRL: 502',
    );
    await allStarted.promise;
    pckRelease.resolve();
    await failure;
    respond = collateralResponse;
    await expect(
      getIntelCollateral(base, Quote.parse(intelQuoteBytes), context),
    ).resolves.toBeDefined();
    expect(requests).toHaveLength(7);
  });

  test('an earlier failure is not delayed by stalled later downloads', async () => {
    const release = createDeferred<void>();
    const context = createVerificationContext({
      fetch: async (input) => {
        const url = String(input);
        if (url.includes('/pckcrl')) return new Response(null, { status: 502 });
        await release.promise;
        return collateralResponse(url);
      },
    });
    try {
      await expect(
        getIntelCollateral(base, Quote.parse(intelQuoteBytes), context),
      ).rejects.toThrow('Failed to fetch PCK CRL: 502');
    } finally {
      release.resolve();
    }
  });

  test('retains Root CRL fallback and retries the failed primary endpoint', async () => {
    jest.spyOn(utils, 'extractCrlUrl').mockReturnValue(`${base}/root.der`);
    respond = (url) =>
      url.endsWith('/rootcacrl')
        ? new Response(null, { status: 503 })
        : collateralResponse(url);
    const baseline = await getCollateral(base, intelQuoteBytes);
    requests = [];
    const context = createVerificationContext();
    expect(
      await getIntelCollateral(base, Quote.parse(intelQuoteBytes), context),
    ).toEqual(baseline);
    expect(requests).toHaveLength(5);
    await getIntelCollateral(base, Quote.parse(intelQuoteBytes), context);
    expect(requests).toHaveLength(6);
    expect(requests.filter((url) => url.endsWith('/root.der'))).toHaveLength(1);
  });

  test('does not reuse expired material or fall back to it when refresh fails', async () => {
    const context = createVerificationContext();
    await getIntelCollateral(base, Quote.parse(intelQuoteBytes), context);
    jest.mocked(Date.now).mockReturnValue(Date.parse('2025-07-20T00:00:00Z'));
    respond = (url) =>
      url.includes('/pckcrl')
        ? new Response(null, { status: 503 })
        : collateralResponse(url);
    await expect(
      getIntelCollateral(base, Quote.parse(intelQuoteBytes), context),
    ).rejects.toThrow('Failed to fetch PCK CRL: 503');
    expect(requests.filter((url) => url.includes('/pckcrl'))).toHaveLength(2);
  });

  test('honors HTTP freshness without renewing the lifetime on hits', async () => {
    respond = (url) => {
      const response = collateralResponse(url);
      response.headers.set('cache-control', 'max-age=10');
      return response;
    };
    const context = createVerificationContext();
    const run = () =>
      getIntelCollateral(base, Quote.parse(intelQuoteBytes), context);
    await run();
    jest.mocked(Date.now).mockReturnValue(intelFixtureTime + 9000);
    await run();
    expect(requests).toHaveLength(4);
    jest.mocked(Date.now).mockReturnValue(intelFixtureTime + 11000);
    await run();
    expect(requests).toHaveLength(8);
  });

  test('an aborted consumer does not cancel another quote waiting for the same material', async () => {
    const entered = createDeferred<void>();
    const release = createDeferred<void>();
    respond = async (url) => {
      if (url.includes('/pckcrl')) {
        entered.resolve();
        await release.promise;
      }
      return collateralResponse(url);
    };
    const context = createVerificationContext();
    const controller = new AbortController();
    const first = getIntelCollateral(
      base,
      Quote.parse(intelQuoteBytes),
      context,
      controller.signal,
    );
    const second = getIntelCollateral(
      base,
      Quote.parse(intelQuoteBytes),
      context,
    );
    const reason = new Error('Only this consumer stopped');
    const failure = expect(first).rejects.toBe(reason);
    await entered.promise;
    controller.abort(reason);
    await failure;
    release.resolve();
    await expect(second).resolves.toBeDefined();
    expect(requests).toHaveLength(4);
  });
});
