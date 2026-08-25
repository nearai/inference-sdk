import { createHash } from 'crypto';
import { NearModelAttestation } from '../src/types/attestation-model';
import { VerifiedTdxQuote } from '../src/types/verification';

export const nonce = '11'.repeat(32);
export const signingAddress = `0x${'22'.repeat(20)}`;
export const tlsFingerprint = '33'.repeat(32);
export const appCompose =
  '{"services":{"model":"example@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}';

export function sha256(value: Uint8Array | string): Buffer {
  return createHash('sha256').update(value).digest();
}

export function sha384(value: Uint8Array): Buffer {
  return createHash('sha384').update(value).digest();
}

export function createQuote(
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

export function createNearModelAttestation(
  overrides: Partial<NearModelAttestation> = {},
): NearModelAttestation {
  return {
    request_nonce: nonce,
    signing_algo: 'ecdsa',
    signing_address: signingAddress,
    intel_quote: 'aa',
    event_log: [
      {
        digest: '00'.repeat(48),
        event_type: 0,
        event: 'compose-hash',
        event_payload: 'beef',
        imr: 3,
      },
    ],
    info: {
      tcb_info: {
        app_compose: appCompose,
      },
    },
    tls_cert_fingerprint: tlsFingerprint,
    ...overrides,
  };
}
