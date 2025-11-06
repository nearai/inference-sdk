import { INTEL_PCCS_API_URL, INTEL_TDX_VERIFIER_API_URL } from './consts';
import { IntelTdxVerificationData } from '../types/intel';
import { hexToBuffer } from './common';
import { getDcapQvlUtils } from './dcap-qvl';
import { VerificationError } from './errors';

export async function fetchIntelTdxVerificationData(
  quote: string,
): Promise<IntelTdxVerificationData> {
  return fetchIntelTdxVerificationDataFromPccs(quote);
}

async function fetchIntelTdxVerificationDataFromPccs(
  quote: string,
): Promise<IntelTdxVerificationData> {
  const { jsVerify, jsGetCollateral } = await getDcapQvlUtils();

  const quoteRaw = hexToBuffer(quote);

  let collateral;

  try {
    collateral = await jsGetCollateral(INTEL_PCCS_API_URL, quoteRaw);
  } catch (e: unknown) {
    throw new VerificationError('Failed to get collateral', e);
  }

  let verificationDataRaw;

  try {
    verificationDataRaw = jsVerify(
      quoteRaw,
      collateral,
      BigInt(Math.floor(Date.now() / 1000)),
    );
  } catch (e: unknown) {
    throw new VerificationError('Failed to verify Intel quote', e);
  }

  const td10 = verificationDataRaw?.report?.TD10
    ? verificationDataRaw.report.TD10
    : {};
  if (!td10.report_data || typeof td10.report_data !== 'string') {
    throw new VerificationError('Bad report_data');
  }
  if (!td10.mr_config_id || typeof td10.mr_config_id !== 'string') {
    throw new VerificationError('Bad mr_config_id');
  }

  const reportData: string = td10.report_data;
  const mrConfig: string = td10.mr_config_id;

  const status: string | undefined =
    typeof verificationDataRaw?.status === 'string'
      ? verificationDataRaw.status
      : undefined;
  const verifiedFromStatus = status ? status === 'UpToDate' : false;
  const verified = verifiedFromStatus || !!verificationDataRaw?.quote?.verified;

  return {
    quote: {
      body: {
        reportdata: reportData,
        mrconfig: mrConfig,
      },
      verified,
    },
  };
}

// eslint-disable-next-line @typescript-eslint/no-unused-vars
async function fetchIntelTdxVerificationDataFromVerifier(
  quote: string,
): Promise<IntelTdxVerificationData> {
  const response = await fetch(INTEL_TDX_VERIFIER_API_URL, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
    },
    body: JSON.stringify({ hex: quote }),
  });

  if (!response.ok) {
    throw new VerificationError(
      `Failed to fetch Intel TDX verification data with status code ${response.status}`,
    );
  }

  return await response.json();
}
