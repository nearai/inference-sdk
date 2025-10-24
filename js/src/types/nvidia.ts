import { JwtPayload } from './common';

export type NvidiaGpuVerificationRaw = [
  ['JWT', string],
  Record<string, string>,
];

export type NvidiaGpuVerification = {
  JWT: JwtPayload;
  GPU: Record<string, JwtPayload>;
};
