import { DstackAttestation } from './attestation-common';
import { NearModelAttestation } from './attestation-model';

export type VpcInfo = {
  vpc_server_app_id?: string;
  vpc_hostname?: string;
};

/** Cloud API gateway evidence. VPC data is intentionally optional. */
export type GatewayAttestation = DstackAttestation & {
  report_data: string;
  vpc?: VpcInfo;
};

/** Wire response from `/v1/attestation/report`. */
export type NearAiCloudAttestationReport = {
  gateway_attestation: GatewayAttestation;
  model_attestations?: NearModelAttestation[];
  tls_certificate?: string;
  ohttp_key_config?: string;
  ohttp_attestation?: unknown;
};
