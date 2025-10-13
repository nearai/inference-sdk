import { JWTPayload } from 'jose';

export type NvidiaGpuVerificationRaw = [
  ['JWT', string],
  Record<string, string>,
];

export type NvidiaGpuVerification = {
  JWT: JWTPayload;
  GPU: Record<string, JWTPayload>;
};
