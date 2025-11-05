import { GatewayAttestation } from './attestation-gateway';

export type ModelAttestation = {
  signing_address: string;
  intel_quote: string;
  nvidia_payload: string;
  request_nonce: string;
};

export type AttestationReport = ModelAttestation & {
  gateway_attestation: GatewayAttestation;
  model_attestations: ModelAttestation[];
};
