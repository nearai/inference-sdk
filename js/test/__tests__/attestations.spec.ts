import { initContext } from '../context';
import {
  fetchAttestationReport,
  fetchDomainAttestation,
  generateRequestNonce,
} from '../common';
import {
  SigningAlgo,
  verifyDomainAttestation,
  verifyGatewayAttestation,
  verifyModelAttestation,
} from '../../src';
import { Context } from '../types';

describe('attestations', () => {
  const context = initContext();

  test('gateway attestation and model attestations ecdsa', async () => {
    await testGatewayAttestationAndModelAttestations(context, 'ecdsa');
  });

  test('gateway attestation and model attestations ed25519', async () => {
    await testGatewayAttestationAndModelAttestations(context, 'ed25519');
  });

  test('domain attestation', async () => {
    const attestation = await fetchDomainAttestation(context.baseApiUrl);
    await verifyDomainAttestation(attestation);
  });
});

async function testGatewayAttestationAndModelAttestations(
  context: Context,
  signingAlgo: SigningAlgo,
) {
  const requestNonce = generateRequestNonce();

  const report = await fetchAttestationReport({
    apiUrl: context.apiUrl,
    apiKey: context.apiKey,
    params: {
      model: context.model,
      requestNonce,
      signingAlgo,
    },
  });

  expect(report.gateway_attestation.request_nonce).toEqual(requestNonce);
  expect(report.gateway_attestation.signing_algo).toEqual(signingAlgo);

  await verifyGatewayAttestation(report.gateway_attestation);

  for (const modelAttestation of report.model_attestations ?? []) {
    expect(modelAttestation.request_nonce).toEqual(requestNonce);
    expect(modelAttestation.signing_algo).toEqual(signingAlgo);

    await verifyModelAttestation(modelAttestation);
  }
}
