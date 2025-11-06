import { hexToBuffer } from '../utils/common';
import { VerificationError } from '../utils/errors';

export function verifyIntelQuoteReportDataForAttestationReport(
  reportData: string,
  requestNonce: string,
  signingAddress: string,
) {
  const reportDataRaw = hexToBuffer(reportData);
  const signingAddressRaw = hexToBuffer(signingAddress);

  const embeddedAddress = reportDataRaw.subarray(0, 32);
  const embeddedNonce = reportDataRaw.subarray(32);

  const signingAddressVerified = embeddedAddress.equals(
    Buffer.concat([
      signingAddressRaw,
      Buffer.alloc(32 - signingAddressRaw.length, 0),
    ]),
  );

  if (!signingAddressVerified) {
    throw new VerificationError('Signing address mismatching');
  }

  const requestNonceVerified = embeddedNonce.equals(hexToBuffer(requestNonce));

  if (!requestNonceVerified) {
    throw new VerificationError('Request nonce mismatching');
  }
}
