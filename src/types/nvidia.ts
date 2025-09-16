import { JWTPayload } from "jose";

export type NvidiaGpuVerificationRaw = [
  ['JWT', string],
  Record<string, string>,
];

export type NvidiaGpuVerification = {
  JWT: NvidiaJwtPayload,
  GPU: Record<string, NvidiaGpuJwtPayload>
}

export type NvidiaJwtPayload = {
  'x-nvidia-ver': string;
  'x-nvidia-overall-att-result': boolean;
} & JWTPayload

export type NvidiaGpuJwtPayload = {
  'x-nvidia-gpu-attestation-report-parsed': boolean,
  'x-nvidia-gpu-attestation-report-signature-verified': boolean,
  'x-nvidia-gpu-attestation-report-cert-chain-validated': boolean,
  'x-nvidia-gpu-attestation-report-nonce-match': boolean,

  'x-nvidia-gpu-driver-version': string,
  'x-nvidia-gpu-driver-rim-fetched': boolean,
  'x-nvidia-gpu-driver-rim-measurements-available': boolean,
  'x-nvidia-gpu-driver-rim-signature-verified': boolean,
  'x-nvidia-gpu-driver-rim-cert-validated': boolean,
  'x-nvidia-gpu-driver-rim-schema-validated': boolean,

  'x-nvidia-gpu-vbios-version': string,
  'x-nvidia-gpu-vbios-rim-fetched': boolean,
  'x-nvidia-gpu-vbios-rim-measurements-available': boolean,
  'x-nvidia-gpu-vbios-rim-signature-verified': boolean,
  'x-nvidia-gpu-vbios-rim-cert-validated': boolean,
  'x-nvidia-gpu-vbios-rim-schema-validated': boolean,
  'x-nvidia-gpu-vbios-index-no-conflict': boolean,

  'x-nvidia-gpu-arch-check': boolean,

  'x-nvidia-attestation-warning': string | null,
} & JWTPayload;
