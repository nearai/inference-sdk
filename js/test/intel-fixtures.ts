import { Buffer } from 'node:buffer';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { Quote, utils } from '@phala/dcap-qvl';

// Public signed DCAP fixtures already used by the Go SDK. Their material is
// valid at this recorded time, not at today's wall clock.
const fixtures = resolve(__dirname, '../../go/internal/dcap/testdata');
export const intelQuoteBytes = readFileSync(resolve(fixtures, 'tdx_quote'));
export const intelCollateral = JSON.parse(
  readFileSync(resolve(fixtures, 'tdx_quote_collateral.json'), 'utf8'),
) as Record<string, string>;
export const intelFixtureTime = Date.parse('2025-06-20T12:00:00Z');

export function collateralResponse(url: string): Response {
  const path = new URL(url, 'https://fixture.test').pathname;
  if (path.endsWith('/pckcrl'))
    return new Response(Buffer.from(intelCollateral.pck_crl, 'hex'), {
      headers: {
        'SGX-PCK-CRL-Issuer-Chain': encodeURIComponent(
          intelCollateral.pck_crl_issuer_chain,
        ),
      },
    });
  if (path.endsWith('/tcb'))
    return new Response(
      JSON.stringify({
        tcbInfo: JSON.parse(intelCollateral.tcb_info),
        signature: intelCollateral.tcb_info_signature,
      }),
      {
        headers: {
          'TCB-Info-Issuer-Chain': encodeURIComponent(
            intelCollateral.tcb_info_issuer_chain,
          ),
        },
      },
    );
  if (path.endsWith('/qe/identity'))
    return new Response(
      JSON.stringify({
        enclaveIdentity: JSON.parse(intelCollateral.qe_identity),
        signature: intelCollateral.qe_identity_signature,
      }),
      {
        headers: {
          'SGX-Enclave-Identity-Issuer-Chain': encodeURIComponent(
            intelCollateral.qe_identity_issuer_chain,
          ),
        },
      },
    );
  if (path.endsWith('/rootcacrl'))
    return new Response(intelCollateral.root_ca_crl);
  if (path.endsWith('/root.der') || path.endsWith('/IntelSGXRootCA.der'))
    return new Response(Buffer.from(intelCollateral.root_ca_crl, 'hex'));
  throw new Error(`Unexpected fixture request: ${url}`);
}

/** Synthetic second hardware identity for retrieval accounting, not a valid signature. */
export function quoteWithOtherFmspc(): Buffer {
  const quote = Quote.parse(intelQuoteBytes);
  const chain = Buffer.from(quote.rawCertChain()).toString('utf8');
  const leaf = utils.extractCerts(Buffer.from(chain))[0];
  const original = Buffer.from('b0c06f000000', 'hex');
  const offset = leaf.indexOf(original);
  if (offset < 0) throw new Error('Fixture FMSPC not found');
  Buffer.from('90c06f000000', 'hex').copy(leaf, offset);
  const encoded = leaf.toString('base64');
  let index = 0;
  const changed = chain.replace(
    /(-----BEGIN CERTIFICATE-----)([\s\S]*?)(-----END CERTIFICATE-----)/,
    (_match, begin, body: string, end) =>
      begin + body.replace(/[A-Za-z0-9+/=]/g, () => encoded[index++]) + end,
  );
  const result = Buffer.from(intelQuoteBytes);
  Buffer.from(changed).copy(result, result.indexOf(Buffer.from(chain)));
  return result;
}
