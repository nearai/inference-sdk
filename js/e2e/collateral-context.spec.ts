import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import * as browser from '../dist/index.js';
import * as node from '../dist/node.js';

const quote = readFileSync(
  new URL('../../go/internal/dcap/testdata/tdx_quote', import.meta.url),
).toString('hex');
const collateral = JSON.parse(
  readFileSync(
    new URL(
      '../../go/internal/dcap/testdata/tdx_quote_collateral.json',
      import.meta.url,
    ),
    'utf8',
  ),
) as Record<string, string>;

function response(url: string): Response {
  const path = new URL(url).pathname;
  const headers = new Headers({ 'cache-control': 'no-store, no-transform' });
  if (path.endsWith('/rootcacrl'))
    return new Response(collateral.root_ca_crl, { headers });
  if (path.endsWith('/pckcrl')) {
    headers.set(
      'SGX-PCK-CRL-Issuer-Chain',
      encodeURIComponent(collateral.pck_crl_issuer_chain),
    );
    return new Response(Buffer.from(collateral.pck_crl, 'hex'), { headers });
  }
  const tcb = path.endsWith('/tcb');
  assert.ok(tcb || path.endsWith('/qe/identity'));
  headers.set(
    tcb ? 'TCB-Info-Issuer-Chain' : 'SGX-Enclave-Identity-Issuer-Chain',
    encodeURIComponent(
      collateral[tcb ? 'tcb_info_issuer_chain' : 'qe_identity_issuer_chain'],
    ),
  );
  return new Response(
    JSON.stringify({
      [tcb ? 'tcbInfo' : 'enclaveIdentity']: JSON.parse(
        collateral[tcb ? 'tcb_info' : 'qe_identity'],
      ),
      signature:
        collateral[tcb ? 'tcb_info_signature' : 'qe_identity_signature'],
    }),
    { headers },
  );
}

for (const [name, owner, consumer] of [
  ['root to /node', browser, node],
  ['/node to root', node, browser],
] as const) {
  test(`published entry points share a context (${name})`, async (t) => {
    t.mock.method(Date, 'now', () => Date.parse('2025-06-20T12:00:00Z'));
    let gets = 0;
    const context = owner.createVerificationContext({
      fetch: async (input) => {
        gets++;
        return response(String(input));
      },
    });
    const firstVerifier = owner.createTdxQuoteVerifier({
      pccsUrl: 'https://fixture.test',
      context,
    });
    const secondVerifier = consumer.createTdxQuoteVerifier({
      pccsUrl: 'https://fixture.test',
    });
    const [first, second] = await Promise.all([
      firstVerifier(quote),
      secondVerifier(quote, { context }),
    ]);
    const third = await secondVerifier(quote, { context });
    assert.deepEqual(first, second);
    assert.deepEqual(second, third);
    assert.equal(first.tcbStatus, 'UpToDate');
    assert.equal(gets, 4);
    // Fetch is injected. No external requests or persistent caches participate.
  });
}
