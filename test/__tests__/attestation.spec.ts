import { initContext } from '../context';
import { fetchAttestationReport } from '../common';
import * as crypto from 'node:crypto';
import {
  isGatewayAttestationReportVerified,
  isModelAttestationReportVerified,
  verifyGatewayAttestation,
  verifyModelAttestation,
} from '../../src';

describe('attestation', () => {
  const context = initContext();

  test('attestation', async () => {
    const requestNonce = crypto.randomBytes(32).toString('hex');

    const report = await fetchAttestationReport(
      context.apiUrl,
      context.apiKey,
      context.model,
      requestNonce,
    );
    
    const gatewayVerification = await verifyGatewayAttestation(report.gateway_attestation);

    expect(
      isGatewayAttestationReportVerified(gatewayVerification, requestNonce)
    ).toBe(true);

    for (const model_attestation of report.model_attestations) {
      const modelVerification = await verifyModelAttestation(model_attestation);

      expect(
        isModelAttestationReportVerified(modelVerification, requestNonce, model_attestation.signing_address),
      ).toBe(true);
    }
  })
});
