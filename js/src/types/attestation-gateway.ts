import { TcbInfo } from './attestation-common';

export type GatewayAttestation = {
  intel_quote: string;
  info: {
    tcb_info: string | TcbInfo;
  };
};
