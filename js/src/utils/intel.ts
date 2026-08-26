import { getCollateral, verify } from '@phala/dcap-qvl';
import { TcbStatus, VerifiedTdxQuote } from '../types/verification';
import { getIntelPccsApiUrl, hexToBuffer } from './common';
import { VerificationError } from './errors';

/**
 * Verify an Intel TDX quote using DCAP and expose only the measurements needed
 * by the provider-agnostic verification core.
 */
export async function verifyDcapQuote(
  quote: string,
): Promise<VerifiedTdxQuote> {
  const quoteBytes = hexToBuffer(quote);

  let collateral;
  try {
    collateral = await getCollateral(getIntelPccsApiUrl(), quoteBytes);
  } catch (cause) {
    throw new VerificationError('Failed to get Intel collateral', cause);
  }

  let verifiedReport;
  try {
    verifiedReport = verify(
      quoteBytes,
      collateral,
      Math.floor(Date.now() / 1000),
    );
  } catch (cause) {
    throw new VerificationError('Failed to verify Intel TDX quote', cause);
  }

  const td10 = verifiedReport.report.asTd10();
  if (!td10) {
    throw new VerificationError(
      'Verified quote does not contain a TD10 report',
    );
  }

  return {
    tcbStatus: parseTcbStatus(verifiedReport.status),
    advisoryIds: [...verifiedReport.advisory_ids],
    debugEnabled: (td10.tdAttributes[0] & 0x01) !== 0,
    reportData: td10.reportData,
    mrConfigId: td10.mrConfigId,
    rtMr3: td10.rtMr3,
  };
}

function parseTcbStatus(status: string): TcbStatus {
  return Object.values(TcbStatus).includes(status as TcbStatus)
    ? (status as TcbStatus)
    : TcbStatus.Unknown;
}
