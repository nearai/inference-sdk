import { TcbInfo } from './attestation-common';

export type GatewayAttestation = {
  signing_address?: string;
  intel_quote: string;
  info: {
    tcb_info: string | TcbInfo;
  };
};
