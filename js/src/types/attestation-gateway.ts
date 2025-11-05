import { IntelTdxVerification } from './intel';

export type GatewayAttestationVerification = {
  intel: IntelTdxVerification;
};

export type GatewayAttestation = {
  intel_quote: string;
  request_nonce: string;
};
