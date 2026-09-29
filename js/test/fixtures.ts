import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import type { ModelAttestation } from '../src';
import type { VerifiedTdxQuote } from '../src/types/verification';

export const nonce = '11'.repeat(32);
export const signingAddress = `0x${'22'.repeat(20)}`;
export const tlsFingerprint = '33'.repeat(32);
export const appCompose =
  '{"services":{"model":"example@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}';

type Deferred<T> = {
  promise: Promise<T>;
  resolve: (value: T | PromiseLike<T>) => void;
  reject: (reason?: unknown) => void;
};

export function createDeferred<T>(): Deferred<T> {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

export function sha256(value: Uint8Array | string): Buffer {
  return createHash('sha256').update(value).digest();
}

export function sha384(value: Uint8Array): Buffer {
  return createHash('sha384').update(value).digest();
}

/** A quote using the Gateway TLS report-data layout. */
export function createGatewayTlsQuote(
  overrides: Partial<VerifiedTdxQuote> = {},
): VerifiedTdxQuote {
  const runtimeDigest = Buffer.alloc(48);
  const rtmr3 = sha384(Buffer.concat([Buffer.alloc(48), runtimeDigest]));
  const reportData = Buffer.concat([
    sha256(
      Buffer.concat([
        Buffer.from(signingAddress.slice(2), 'hex'),
        Buffer.from(tlsFingerprint, 'hex'),
      ]),
    ),
    Buffer.from(nonce, 'hex'),
  ]);
  const mrConfigId = Buffer.concat([
    Buffer.from([0x01]),
    sha256(appCompose),
    Buffer.alloc(15),
  ]);

  return {
    tcbStatus: 'UpToDate',
    advisoryIds: [],
    debugEnabled: false,
    reportData,
    mrConfigId,
    rtMr3: rtmr3,
    ...overrides,
  };
}

/** A Cloud model quote using the signer-and-nonce report-data layout. */
export function createModelQuote(
  overrides: Partial<VerifiedTdxQuote> = {},
): VerifiedTdxQuote {
  return createGatewayTlsQuote({
    reportData: Buffer.concat([
      Buffer.from(signingAddress.slice(2), 'hex'),
      Buffer.alloc(12),
      Buffer.from(nonce, 'hex'),
    ]),
    ...overrides,
  });
}

export function createModelAttestation(
  overrides: Partial<ModelAttestation> = {},
): ModelAttestation {
  return {
    nonce,
    signer: { signingAlgo: 'ecdsa', signingAddress },
    intelQuote: 'aa',
    eventLog: [
      {
        digest: '00'.repeat(48),
        event_type: 0,
        event: 'compose-hash',
        event_payload: 'beef',
        imr: 3,
      },
    ],
    appCompose,
    ...overrides,
  };
}
