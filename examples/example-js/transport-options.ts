import type { SigningAlgo } from '@nearai/inference-sdk/node';

// OHTTP authenticates its key configuration with Ed25519.
export function transportOptions(signingAlgo: SigningAlgo) {
  if (process.env.NEARAI_OHTTP === 'true') {
    if (signingAlgo !== 'ed25519') throw new Error('OHTTP requires Ed25519');
    return { signingAlgo, ohttp: true } as const;
  }
  return { signingAlgo, ohttp: false } as const;
}
