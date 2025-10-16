import { INTEL_TDX_VERIFIER_API_URL } from './consts';
import { IntelTdxVerification } from '../types/intel';

export function isIntelTdxVerified(
  verification: IntelTdxVerification,
): boolean {
  return verification.success && verification.quote.verified;
}

export async function verifyIntelTdx(
  quote: string,
): Promise<IntelTdxVerification> {
  const response = await fetch(INTEL_TDX_VERIFIER_API_URL, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      accept: 'application/json',
    },
    body: JSON.stringify({ hex: quote }),
  });

  if (!response.ok) {
    throw Error(`Verify Intel TDX failed with status code ${response.status}`);
  }

  return await response.json();
}
