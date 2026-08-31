import { Buffer } from 'node:buffer';
import { verifyGatewayAttestation } from '../src';
import type { GatewayAttestation, MeasuredDeployment } from '../src';
import {
  appCompose,
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
  });

  test('requires a peer observation by default', async () => {
    await expect(
      verifyGatewayAttestation({
        attestation: createGatewayAttestation(),
        clientBinding: { nonce },
        verifiers: { quote: async () => createQuote() },
      }),
    ).rejects.toMatchObject({
      failure: { code: 'policy.peer_tls_binding_required' },
    });
  });

  test('allows a browser to disable peer TLS verification explicitly', async () => {
    const result = await verifyGatewayAttestation({
      attestation: createGatewayAttestation(),
      clientBinding: { nonce },
      policy: { verifyPeerTlsBinding: false },
      verifiers: { quote: async () => createQuote() },
    });

    expect(result.tlsBinding).toEqual({
      kind: 'attested',
      spkiFingerprint: tlsFingerprint,
    });
  });

  test('does not inspect a peer fingerprint when peer TLS verification is disabled', async () => {
    const result = await verifyGatewayAttestation({
      attestation: createGatewayAttestation(),
      clientBinding: { nonce, peerSpkiFingerprint: '44'.repeat(32) },
      policy: { verifyPeerTlsBinding: false },
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

  test('applies an explicit Gateway TCB policy', async () => {
    await expect(
      verifyGatewayAttestation({
        attestation: createGatewayAttestation(),
        clientBinding: { nonce, peerSpkiFingerprint: tlsFingerprint },
        policy: { acceptedTcbStatuses: ['OutOfDate'] },
        verifiers: { quote: async () => createQuote() },
      }),
    ).rejects.toMatchObject({
      failure: {
        code: 'policy.tcb_status_not_allowed',
        details: { actual: 'UpToDate', accepted: ['OutOfDate'] },
      },
    });
  });

  test('passes gateway measurements to a deployment verifier', async () => {
    const verifiedDeployments: MeasuredDeployment[] = [];
    const result = await verifyGatewayAttestation({
      attestation: createGatewayAttestation(),
      clientBinding: { nonce, peerSpkiFingerprint: tlsFingerprint },
      verifiers: {
        quote: async () => createQuote(),
        deployment: async (deployment) => {
          verifiedDeployments.push(deployment);
        },
      },
    });

    expect(verifiedDeployments).toEqual([
      { appCompose, runtimeMeasurements: {} },
    ]);
    expect(result.deploymentProvenance).toBe('verified');
  });

  test('normalizes a rejected gateway deployment verifier', async () => {
    await expect(
      verifyGatewayAttestation({
        attestation: createGatewayAttestation(),
        clientBinding: { nonce, peerSpkiFingerprint: tlsFingerprint },
        verifiers: {
          quote: async () => createQuote(),
          deployment: async () => {
            throw new Error('deployment rejected');
          },
        },
      }),
    ).rejects.toMatchObject({
      failure: { code: 'provenance.verification_failed' },
    });
  });
});
