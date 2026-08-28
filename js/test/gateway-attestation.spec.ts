import { Buffer } from 'node:buffer';
import { verifyGatewayAttestation } from '../src';
import type { GatewayAttestation } from '../src';
import {
  createModelAttestation,
  createQuote,
  nonce,
  tlsFingerprint,
} from './fixtures';

function createGatewayAttestation(
  overrides: Partial<GatewayAttestation> = {},
): GatewayAttestation {
  const quote = createQuote();
  return {
    ...createModelAttestation(),
    reportedQuoteData: Buffer.from(quote.reportData).toString('hex'),
    ...overrides,
    declaredSpkiFingerprint:
      overrides.declaredSpkiFingerprint ?? tlsFingerprint,
  };
}

describe('gateway attestation verification', () => {
  test('binds gateway evidence to the caller-observed peer SPKI', async () => {
    const result = await verifyGatewayAttestation({
      attestation: createGatewayAttestation(),
      clientBinding: { nonce, peerSpkiFingerprint: tlsFingerprint },
      verifiers: { quote: async () => createQuote() },
    });

    expect(result).toMatchObject({
      tcbStatus: 'UpToDate',
      tlsBinding: { kind: 'peer', spkiFingerprint: tlsFingerprint },
      deploymentProvenance: 'not_checked',
    });
    expect('gpuEvidence' in result).toBe(false);
  });

  test('verifies the quote-bound Gateway TLS key without a peer observation', async () => {
    const result = await verifyGatewayAttestation({
      attestation: createGatewayAttestation(),
      clientBinding: { nonce },
      verifiers: { quote: async () => createQuote() },
    });

    expect(result.tlsBinding).toEqual({
      kind: 'attested',
      spkiFingerprint: tlsFingerprint,
    });
  });

  test('rejects gateway evidence when the live TLS peer differs', async () => {
    await expect(
      verifyGatewayAttestation({
        attestation: createGatewayAttestation(),
        clientBinding: { nonce, peerSpkiFingerprint: '44'.repeat(32) },
        verifiers: { quote: async () => createQuote() },
      }),
    ).rejects.toMatchObject({
      failure: {
        code: 'binding.spki_fingerprint_mismatch',
      },
    });
  });

  test('rejects gateway report data that contradicts the verified quote', async () => {
    await expect(
      verifyGatewayAttestation({
        attestation: createGatewayAttestation({
          reportedQuoteData: 'ff'.repeat(64),
        }),
        clientBinding: { nonce, peerSpkiFingerprint: tlsFingerprint },
        verifiers: { quote: async () => createQuote() },
      }),
    ).rejects.toMatchObject({
      failure: {
        code: 'binding.report_data_mismatch',
        details: { source: 'reportedQuoteData' },
      },
    });
  });
});
