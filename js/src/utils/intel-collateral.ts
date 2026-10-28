import { Buffer } from 'buffer';
import { type Collateral, type Quote, utils } from '@phala/dcap-qvl';
import { collateralCache } from '../core/verification-context';
import type { VerificationContext } from '../types/verification-context';
import {
  type IntelMaterialKind,
  materialExpiry,
  waitForConsumer,
} from './intel-collateral-cache';

const INTEL_PCS_URL = 'https://api.trustedservices.intel.com';

/**
 * Resource selection and assembly follow @phala/dcap-qvl 0.7.0's collateral
 * contract. Only public fragments are shared; PCK chains remain quote-specific.
 */
export async function getIntelCollateral(
  pccsUrl: string,
  quote: Quote,
  context: VerificationContext,
  signal?: AbortSignal,
): Promise<Collateral> {
  const cache = collateralCache(context);
  const base = pccsUrl
    .replace(/\/$/, '')
    .replace(/\/(?:sgx|tdx)\/certification\/v4$/, '');
  const pckChain = await waitForConsumer(
    getPckChain(base, quote, cache.fetch),
    signal,
  );
  const certs = utils.extractCerts(Buffer.from(pckChain));
  if (certs.length === 0) throw new Error('Empty certificate chain');
  const fmspc = Buffer.from(utils.getFmspc(utils.getIntelExtension(certs[0])))
    .toString('hex')
    .toUpperCase();
  // These helpers exist in 0.7.0's public runtime exports but are missing from
  // its declarations. Keep the compatibility types local to the adapter.
  const issuer = (
    utils as typeof utils & {
      getCertIssuer(cert: Buffer): string;
    }
  ).getCertIssuer(certs[0]);
  const ca = issuer.includes('Intel SGX PCK Processor CA')
    ? 'processor'
    : issuer.includes('Intel SGX PCK Platform CA')
      ? 'platform'
      : 'processor';
  const tee = quote.header.isSgx() ? 'sgx' : 'tdx';

  const get = (
    kind: IntelMaterialKind,
    url: string,
    label: string,
    issuerHeaders: readonly string[] = [],
  ) =>
    cache.get(
      JSON.stringify([base, kind, url]),
      async () => {
        const started = Date.now();
        const response = await cache.fetch(url);
        if (!response.ok)
          throw new Error(`Failed to fetch ${label}: ${response.status}`);
        const issuerChain =
          issuerHeaders.length === 0
            ? ''
            : getIssuerChain(response, issuerHeaders);
        const body = Buffer.from(await response.arrayBuffer());
        return {
          body,
          issuerChain,
          expiresAt: materialExpiry(
            kind,
            body,
            issuerChain,
            response.headers,
            started,
          ),
          size: body.byteLength + Buffer.byteLength(issuerChain),
        };
      },
      signal,
    );

  // Independent downloads run concurrently. Consume failures in the original
  // PCK -> TCB -> QE -> Root order, irrespective of network completion order.
  const pck = get(
    'pck',
    `${base}/sgx/certification/v4/pckcrl?ca=${ca}&encoding=der`,
    'PCK CRL',
    ['SGX-PCK-CRL-Issuer-Chain'],
  );
  const tcb = get(
    'tcb',
    `${base}/${tee}/certification/v4/tcb?fmspc=${fmspc}`,
    'TCB info',
    ['SGX-TCB-Info-Issuer-Chain', 'TCB-Info-Issuer-Chain'],
  );
  const qe = get(
    'qe',
    `${base}/${tee}/certification/v4/qe/identity?update=standard`,
    'QE identity',
    ['SGX-Enclave-Identity-Issuer-Chain'],
  );
  const root = qe.then(async (identity) => {
    if (!base.startsWith(INTEL_PCS_URL)) {
      try {
        const url = `${base}/sgx/certification/v4/rootcacrl`;
        const result = await get('root-hex', url, url);
        return Buffer.from(result.body.toString('utf8'), 'hex');
      } catch {
        signal?.throwIfAborted();
        // Match DCAP's fallback to the QE issuer's CRL distribution point.
      }
    }
    const chain = utils.extractCerts(Buffer.from(identity.issuerChain));
    if (chain.length === 0)
      throw new Error('No certificates found in QE identity issuer chain');
    const url = utils.extractCrlUrl(chain[chain.length - 1]);
    if (!url)
      throw new Error(
        'Could not find CRL distribution point in root certificate',
      );
    return (await get('root-der', url, url)).body;
  });
  // Observe every parallel failure immediately, then await in source order.
  // An early PCK failure must not wait for a stalled later download.
  for (const request of [pck, tcb, qe, root]) void request.catch(() => {});
  const pckResult = await pck;
  const tcbResult = await tcb;
  const qeResult = await qe;
  const rootResult = await root;
  const tcbJson = JSON.parse(tcbResult.body.toString('utf8'));
  const qeJson = JSON.parse(qeResult.body.toString('utf8'));
  // Each caller gets fresh arrays and its own PCK chain, including callers that
  // share FMSPC. No quote-derived Collateral object enters the cache.
  return {
    pck_crl_issuer_chain: pckResult.issuerChain,
    pck_crl: Array.from(pckResult.body),
    root_ca_crl: Array.from(rootResult),
    tcb_info_issuer_chain: tcbResult.issuerChain,
    tcb_info: JSON.stringify(tcbJson.tcbInfo),
    tcb_info_signature: Array.from(Buffer.from(tcbJson.signature, 'hex')),
    qe_identity_issuer_chain: qeResult.issuerChain,
    qe_identity: JSON.stringify(qeJson.enclaveIdentity),
    qe_identity_signature: Array.from(Buffer.from(qeJson.signature, 'hex')),
    pck_certificate_chain: pckChain,
  } as Collateral;
}

function getIssuerChain(response: Response, names: readonly string[]): string {
  let cause: unknown;
  for (const name of names) {
    try {
      const value = response.headers.get(name);
      if (!value) throw new Error(`Missing ${name}`);
      return decodeURIComponent(value);
    } catch (error) {
      cause = error;
    }
  }
  throw cause;
}

type PpidParams = {
  qeid: Uint8Array;
  encryptedPpid: Uint8Array;
  cpusvn: Uint8Array;
  pcesvn: number;
  pceid: Uint8Array;
};

async function getPckChain(
  base: string,
  quote: Quote,
  fetch: typeof globalThis.fetch,
): Promise<string> {
  const parsed = quote as Quote & {
    innerCertType(): number;
    encryptedPpidParams(): PpidParams;
  };
  const certType = parsed.innerCertType();
  if (certType === 5) return Buffer.from(quote.rawCertChain()).toString('utf8');
  if (certType !== 2 && certType !== 3)
    throw new Error(`Unsupported certification data type: ${certType}`);
  const params = parsed.encryptedPpidParams();
  const hex = (value: Uint8Array) =>
    Buffer.from(value).toString('hex').toUpperCase();
  const svn = Buffer.alloc(2);
  svn.writeUInt16LE(params.pcesvn);
  const url = `${base}/sgx/certification/v4/pckcert?qeid=${hex(params.qeid)}&encrypted_ppid=${hex(params.encryptedPpid)}&cpusvn=${hex(params.cpusvn)}&pcesvn=${hex(svn)}&pceid=${hex(params.pceid)}`;
  // Platform-specific certificate lookups are deliberately not shared.
  const response = await fetch(url);
  if (!response.ok)
    throw new Error(
      `Failed to fetch PCK certificate from ${url}: ${response.status}`,
    );
  const tcbm = response.headers.get('SGX-TCBm');
  if (tcbm) {
    const bytes = Buffer.from(tcbm, 'hex');
    if (bytes.length < 18)
      throw new Error(
        `SGX-TCBm header too short: expected 18 bytes, got ${bytes.length}`,
      );
    if (
      !bytes.subarray(0, 16).equals(Buffer.from(params.cpusvn)) ||
      bytes.readUInt16LE(16) !== params.pcesvn
    ) {
      throw new Error(
        'TCB level mismatch: PCCS returned a certificate for a different platform TCB',
      );
    }
  }
  const issuerChain = getIssuerChain(response, [
    'SGX-PCK-Certificate-Issuer-Chain',
  ]);
  return `${await response.text()}\n${issuerChain}`;
}
