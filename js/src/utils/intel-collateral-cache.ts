import { Buffer } from 'buffer';
import { AsnParser } from '@peculiar/asn1-schema';
import { Certificate, CertificateList } from '@peculiar/asn1-x509';
import { utils } from '@phala/dcap-qvl';

export type IntelMaterialKind = 'pck' | 'tcb' | 'qe' | 'root-hex' | 'root-der';
export type IntelMaterial = {
  readonly body: Buffer;
  readonly issuerChain: string;
  readonly expiresAt: number;
  readonly size: number;
};

const MAX_ENTRIES = 64;
const MAX_BYTES = 8 * 1024 * 1024;

/** Bounded operation-local storage. A failed or stale download is never a fallback. */
export class IntelCollateralCache {
  private readonly completed = new Map<string, IntelMaterial>();
  private readonly pending = new Map<string, Promise<IntelMaterial>>();
  private bytes = 0;

  constructor(readonly fetch: typeof globalThis.fetch) {}

  async get(
    key: string,
    download: () => Promise<IntelMaterial>,
    signal?: AbortSignal,
  ): Promise<IntelMaterial> {
    signal?.throwIfAborted();
    const cached = this.completed.get(key);
    if (cached !== undefined) {
      this.completed.delete(key);
      this.bytes -= cached.size;
      if (cached.expiresAt > Date.now()) {
        this.retain(key, cached);
        return cached;
      }
    }
    const existing = this.pending.get(key);
    if (existing !== undefined) {
      const material = await waitForConsumer(existing, signal);
      // The operation, or even this waiter, may outlive the material's validity.
      if (material.expiresAt > Date.now()) return material;
      return this.get(key, download, signal);
    }
    // Saturation bypasses storage rather than evicting somebody's pending I/O.
    if (this.pending.size >= MAX_ENTRIES) {
      return waitForConsumer(download(), signal);
    }
    const request = download()
      .then((material) => {
        this.retain(key, material);
        return material;
      })
      .finally(() => {
        if (this.pending.get(key) === request) this.pending.delete(key);
      });
    this.pending.set(key, request);
    return waitForConsumer(request, signal);
  }

  private retain(key: string, material: IntelMaterial): void {
    if (material.expiresAt <= Date.now() || material.size > MAX_BYTES) return;
    while (
      this.completed.size >= MAX_ENTRIES ||
      this.bytes + material.size > MAX_BYTES
    ) {
      const oldest = this.completed.entries().next().value;
      if (oldest === undefined) break;
      this.completed.delete(oldest[0]);
      this.bytes -= oldest[1].size;
    }
    this.completed.set(key, material);
    this.bytes += material.size;
  }
}

export function waitForConsumer<T>(
  request: Promise<T>,
  signal?: AbortSignal,
): Promise<T> {
  if (signal === undefined) return request;
  return new Promise((resolve, reject) => {
    const abort = () => reject(signal.reason);
    // Register handlers even for an already-aborted consumer: the shared promise
    // must remain observed, and another consumer may still need its result.
    request
      .then(resolve, reject)
      .finally(() => signal.removeEventListener('abort', abort));
    if (signal.aborted) abort();
    else signal.addEventListener('abort', abort, { once: true });
  });
}

/** Freshness only determines reuse. DCAP still authenticates every supplied byte. */
export function materialExpiry(
  kind: IntelMaterialKind,
  body: Buffer,
  issuerChain: string,
  headers: Headers,
  started: number,
): number {
  try {
    const now = Date.now();
    let issued: number;
    let next: number;
    if (kind === 'tcb' || kind === 'qe') {
      const raw = JSON.parse(body.toString('utf8'));
      const material = kind === 'tcb' ? raw.tcbInfo : raw.enclaveIdentity;
      if (
        typeof raw.signature !== 'string' ||
        !/^(?:[\da-f]{2})+$/i.test(raw.signature)
      )
        return 0;
      issued = Date.parse(material.issueDate);
      next = Date.parse(material.nextUpdate);
    } else {
      let der = body;
      if (kind === 'root-hex') {
        const hex = body.toString('utf8');
        if (!/^(?:[\da-f]{2})+$/i.test(hex)) return 0;
        der = Buffer.from(hex, 'hex');
      }
      const crl = AsnParser.parse(der, CertificateList).tbsCertList;
      issued = crl.thisUpdate.getTime().getTime();
      next = crl.nextUpdate?.getTime().getTime() ?? NaN;
    }
    if (
      !Number.isFinite(issued) ||
      !Number.isFinite(next) ||
      issued > now ||
      next <= issued
    )
      return 0;
    let expiresAt = next;
    if (issuerChain !== '') {
      const certs = utils.extractCerts(Buffer.from(issuerChain));
      if (certs.length === 0) return 0;
      for (const der of certs) {
        const validity = AsnParser.parse(der, Certificate).tbsCertificate
          .validity;
        if (validity.notBefore.getTime().getTime() > now) return 0;
        expiresAt = Math.min(expiresAt, validity.notAfter.getTime().getTime());
      }
    }
    const control = headers.get('cache-control') ?? '';
    // This is ownership of public material within one operation, not an HTTP
    // cache. Proxies may send no-store/no-cache to disable browser caching;
    // those flags must not force each quote to download the same material.
    // Explicit freshness deadlines still shorten the material's validity.
    if (headers.get('vary')?.trim() === '*') return 0;
    const age = Number(headers.get('age') ?? 0) * 1000;
    const date = headers.get('date');
    const sentAt = date === null ? started : Date.parse(date);
    if (!Number.isFinite(age) || age < 0 || !Number.isFinite(sentAt)) return 0;
    const currentAge = Math.max(age, started - sentAt, 0);
    for (const directive of control.split(',')) {
      if (!/^\s*max-age\s*(?:=|$)/i.test(directive)) continue;
      const match = /^\s*max-age\s*=\s*(?:"(\d+)"|(\d+))\s*$/i.exec(directive);
      if (match === null) return 0;
      const maxAge = Number(match[1] ?? match[2]);
      if (!Number.isSafeInteger(maxAge)) return 0;
      expiresAt = Math.min(expiresAt, started + maxAge * 1000 - currentAge);
    }
    const expires = headers.get('expires');
    if (expires !== null) expiresAt = Math.min(expiresAt, Date.parse(expires));
    return Number.isFinite(expiresAt) ? expiresAt : 0;
  } catch {
    // Preserve the verifier's original failure for malformed material, without
    // retaining a bad response after the service recovers.
    return 0;
  }
}
