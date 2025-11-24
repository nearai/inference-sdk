import { initContext } from '../context';
import { fetchAttestationReport, fetchDomainAttestation } from '../common';
import * as crypto from 'crypto';
import {
  verifyDomainAttestation,
  verifyGatewayAttestation,
  verifyModelAttestation,
} from '../../src';

describe('attestations', () => {
  const context = initContext();

  test('gateway attestation and model attestations ecdsa', async () => {
    const requestNonce = crypto.randomBytes(32).toString('hex');

    const report = await fetchAttestationReport({
      apiUrl: context.apiUrl,
      apiKey: context.apiKey,
      params: {
        model: context.model,
        signingAlgo: 'ecdsa',
        requestNonce,
      },
    });

    expect(report.gateway_attestation.signing_algo).toEqual('ecdsa');
    await verifyGatewayAttestation(report.gateway_attestation, requestNonce);

    for (const modelAttestation of report.model_attestations ?? []) {
      expect(modelAttestation.signing_algo).toEqual('ecdsa');
      await verifyModelAttestation(modelAttestation, requestNonce);
    }
  });

  test('gateway attestation and model attestations ed25519', async () => {
    const requestNonce = crypto.randomBytes(32).toString('hex');

    const report = await fetchAttestationReport({
      apiUrl: context.apiUrl,
      apiKey: context.apiKey,
      params: {
        model: context.model,
        signingAlgo: 'ed25519',
        requestNonce,
      },
    });

    expect(report.gateway_attestation.signing_algo).toEqual('ed25519');
    await verifyGatewayAttestation(report.gateway_attestation, requestNonce);

    for (const modelAttestation of report.model_attestations ?? []) {
      expect(modelAttestation.signing_algo).toEqual('ed25519');
      await verifyModelAttestation(modelAttestation, requestNonce);
    }
  });

  test('domain attestation', async () => {
    const attestation = await fetchDomainAttestation(context.baseApiUrl);
    await verifyDomainAttestation(attestation);
  });
});
