import { SigningAlgo, TcbInfo } from './attestation-common';

export type GatewayAttestation = {
  request_nonce: string;
  signing_algo?: SigningAlgo;
  signing_address?: string;
  intel_quote: string;
  info: {
    tcb_info: string | TcbInfo;
  };
  vpc: {
    vpc_server_app_id: string;
    vpc_hostname: string;
  };
};
