import { JwtPayload } from './common';

export type NvidiaGpuVerificationDataRaw = [
  ['JWT', string],
  Record<string, string>,
];

export type NvidiaGpuVerificationData = {
  JWT: JwtPayload;
  GPU: Record<string, JwtPayload>;
};
