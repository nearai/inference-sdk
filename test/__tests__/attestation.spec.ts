import { initContext } from '../context';
import { fetchAttestationReport } from '../common';
import * as crypto from 'crypto';
import {
  isGatewayAttestationReportVerified,
  isModelAttestationReportVerified,
  verifyGatewayAttestation,
  verifyModelAttestation,
} from '../../src';

describe('attestation', () => {
  const context = initContext();

  test('gateway attestation and model attestations', async () => {
    const requestNonce = crypto.randomBytes(32).toString('hex');

    const report = await fetchAttestationReport(
      context.apiUrl,
      context.apiKey,
      context.model,
      requestNonce,
    );

    const gatewayVerification = await verifyGatewayAttestation(
      report.gateway_attestation,
    );

    expect(
      isGatewayAttestationReportVerified(gatewayVerification, requestNonce),
    ).toBe(true);

    for (const modelAttestation of report.model_attestations) {
      const modelVerification = await verifyModelAttestation(modelAttestation);

      expect(
        isModelAttestationReportVerified(
          modelVerification,
          requestNonce,
          modelAttestation.signing_address,
        ),
      ).toBe(true);
    }
  });
});
