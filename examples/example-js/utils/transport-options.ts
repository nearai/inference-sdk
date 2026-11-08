import type { SigningAlgo } from '@nearai/inference-sdk/node';

// OHTTP authenticates its key configuration with Ed25519.
export function transportOptions() {
  const signingAlgo = (process.env.NEARAI_SIGNING_ALGO ??
    'ed25519') as SigningAlgo;
  const ohttp = process.env.NEARAI_OHTTP === 'true';
  if (ohttp) {
    if (signingAlgo !== 'ed25519') throw new Error('OHTTP requires Ed25519');
    return { signingAlgo, ohttp } as const;
  }
  return { signingAlgo, ohttp } as const;
}
