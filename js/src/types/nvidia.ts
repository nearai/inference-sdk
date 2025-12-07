export type NvidiaGpuVerificationDataRaw = [
  ['JWT', string],
  Record<string, string>,
];

export type NvidiaGpuVerificationData = {
  JWT: Record<string, unknown>;
  GPU: Record<string, Record<string, unknown>>;
};
