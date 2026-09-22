import { Buffer } from 'node:buffer';
import type {
  ChutesMeasurementBaseline,
  ChutesModelAttestation,
} from '../src/types/attestation-chutes';
import type { TdxQuoteVerificationResult } from '../src/types/verification';
import { CHUTES_MEASUREMENT_BASELINES } from '../src/utils/chutes-measurements';
import { sha256 } from './fixtures';

// Public synthetic certificate, not a live Chutes node or private credential:
// https://github.com/nearai/cloud-api/blob/a9df6f2cc63d567a011641eb9bbaf393c0ef81aa/crates/inference_providers/src/attested/chutes/testdata/synthetic_cert.b64
export const CHUTES_TEST_CERTIFICATE =
  'MIIBkjCCATegAwIBAgIUCztzQSIp3e6fi54DR/JJMk8/hl8wCgYIKoZIzj0EAwIwHjEcMBoGA1UEAwwTY2h1dGVzLXRlc3QtZml4dHVyZTAeFw0yNjA2MTAxMTUwMDRaFw0zNjA2MDcxMTUwMDRaMB4xHDAaBgNVBAMME2NodXRlcy10ZXN0LWZpeHR1cmUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARLNDNBEPGi7xCqNN1DMF8xwzy59Vq/gTqT+G0nC9+Ysnl4fiKXv79OaI8L4BytOxwdJoA+jmKRL55l+vxoKhkPo1MwUTAdBgNVHQ4EFgQUL623ulJuNEKiARko4edhF0sLvUAwHwYDVR0jBBgwFoAUL623ulJuNEKiARko4edhF0sLvUAwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNJADBGAiEA83F6hMt2GiPuOTUNR+KXBUWG9eM8HtuCYAtIqMoRicsCIQC2qSlueROT5oGVGERIRYYqtthW1qCFPGZDWJcCNHOYmg==';
export const CHUTES_TEST_SPKI_FINGERPRINT =
  'e7c25815d0d940fea893d56984e131788afa6e931920093c9c2896fb04dea0da';
export const CHUTES_TEST_NONCE = 'aB'.repeat(32);
export const CHUTES_TEST_PUBLIC_KEY = Buffer.alloc(1184, 42).toString('base64');
export const CHUTES_TEST_BASELINE = CHUTES_MEASUREMENT_BASELINES[0];

export function createChutesAttestation(
  overrides: Partial<ChutesModelAttestation> = {},
): ChutesModelAttestation {
  return {
    provider: 'chutes',
    nonce: CHUTES_TEST_NONCE,
    intelQuote: 'aa',
    certificate: CHUTES_TEST_CERTIFICATE,
    publicKey: CHUTES_TEST_PUBLIC_KEY,
    gpuEvidence: Array.from({ length: 8 }, (_, index) => ({
      arch: 'HOPPER',
      certificate: Buffer.from(`gpu-cert-${index}`).toString('base64'),
      evidence: Buffer.from(`gpu-evidence-${index}`).toString('base64'),
    })),
    instanceId: 'synthetic-instance',
    ...overrides,
  };
}

type CreateChutesQuoteParams = {
  readonly overrides?: Partial<TdxQuoteVerificationResult>;
  readonly baseline?: ChutesMeasurementBaseline;
  readonly binding?: Pick<ChutesModelAttestation, 'nonce' | 'publicKey'>;
};

/** Replace only the external DCAP verifier while retaining real binding hashes. */
export function createChutesQuote({
  overrides = {},
  baseline = CHUTES_TEST_BASELINE,
  binding = {
    nonce: CHUTES_TEST_NONCE,
    publicKey: CHUTES_TEST_PUBLIC_KEY,
  },
}: CreateChutesQuoteParams = {}): TdxQuoteVerificationResult {
  return {
    tcbStatus: 'UpToDate',
    advisoryIds: [],
    debugEnabled: false,
    reportData: Buffer.concat([
      sha256(binding.nonce + binding.publicKey),
      Buffer.from(CHUTES_TEST_SPKI_FINGERPRINT, 'hex'),
    ]),
    mrConfigId: Buffer.alloc(48),
    mrTd: Buffer.from(baseline.mrTd, 'hex'),
    rtMr0: Buffer.from(baseline.rtMr0, 'hex'),
    rtMr1: Buffer.from(baseline.rtMr1, 'hex'),
    rtMr2: Buffer.from(baseline.rtMr2, 'hex'),
    rtMr3: Buffer.from(baseline.rtMr3, 'hex'),
    ...overrides,
  };
}
