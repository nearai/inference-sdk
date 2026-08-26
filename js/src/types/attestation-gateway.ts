import { DstackAttestation } from './attestation-common';
import { NearModelAttestation } from './attestation-model';

export type VpcInfo = {
  vpc_server_app_id?: string;
  vpc_hostname?: string;
};

/**
 * Decoded gateway wire evidence. Pass this to `verifyGatewayAttestation`
 * together with a TLS peer fingerprint observed on the same connection.
 * VPC data is intentionally optional.
 */
export type GatewayAttestation = DstackAttestation & {
  report_data: string;
  vpc?: VpcInfo;
};

/**
 * Decoded wire response from `/v1/attestation/report`. Its contents are not
 * verified by parsing. `tls_certificate`, `ohttp_key_config`, and
 * `ohttp_attestation` are retained for callers, but are outside the SDK's
 * current model and gateway verification claims.
 */
export type NearAiCloudAttestationReport = {
  gateway_attestation: GatewayAttestation;
  model_attestations?: NearModelAttestation[];
  tls_certificate?: string;
  ohttp_key_config?: string;
  ohttp_attestation?: unknown;
};
