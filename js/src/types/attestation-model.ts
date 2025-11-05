import { NvidiaGpuVerification } from './nvidia';
import { IntelTdxVerification } from './intel';
import { GatewayAttestation } from './attestation-gateway';

export type ModelAttestationVerification = {
  intel: IntelTdxVerification;
  nvidia: NvidiaGpuVerification;
};

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
