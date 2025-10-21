import { INTEL_TDX_VERIFIER_API_URL } from './consts';
import { IntelTdxVerification } from '../types/intel';
import { hexToBuffer } from './common';

export function isIntelTdxVerified(
  verification: IntelTdxVerification,
  signingAddress: string,
  requestNonce: string,
): boolean {
  return (
    verification.success &&
    verification.quote.verified &&
    isReportDataVerified(
      verification.quote.body.reportdata,
      signingAddress,
      requestNonce,
    )
  );
}

function isReportDataVerified(
  reportData: string,
  signingAddress: string,
  requestNonce: string,
): boolean {
  const reportDataRaw = hexToBuffer(reportData);
  const signingAddressRaw = hexToBuffer(signingAddress);

  const embeddedAddress = reportDataRaw.subarray(0, 32);
  const embeddedNonce = reportDataRaw.subarray(32);

  const addressVerified = embeddedAddress.equals(
    Buffer.concat([
      signingAddressRaw,
      Buffer.alloc(32 - signingAddressRaw.length, 0),
    ]),
  );
  const nonceVerified = embeddedNonce.equals(hexToBuffer(requestNonce));

  return addressVerified && nonceVerified;
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
