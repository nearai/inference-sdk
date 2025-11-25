import { INTEL_PCCS_API_URL, INTEL_TDX_VERIFIER_API_URL } from './consts';
import { IntelTdxVerificationData } from '../types/intel';
import { hexToBuffer } from './common';
import { VerificationError } from './errors';
import { getCollateral, verify } from '@phala/dcap-qvl';

export async function fetchIntelTdxVerificationData(
  quote: string,
): Promise<IntelTdxVerificationData> {
  return fetchIntelTdxVerificationDataFromPccs(quote);
}

async function fetchIntelTdxVerificationDataFromPccs(
  quote: string,
): Promise<IntelTdxVerificationData> {
  const quoteRaw = hexToBuffer(quote);

  let collateral;

  try {
    collateral = await getCollateral(INTEL_PCCS_API_URL, quoteRaw);
  } catch (e: unknown) {
    throw new VerificationError('Failed to get collateral', e);
  }

  let verificationDataRaw;

  try {
    verificationDataRaw = verify(
      quoteRaw,
      collateral,
      Math.floor(Date.now() / 1000),
    );
  } catch (e: unknown) {
    throw new VerificationError('Failed to verify Intel quote', e);
  }

  const td10 = verificationDataRaw.report.asTd10();

  if (!td10) {
    throw new VerificationError('Bad report data');
  }

  const reportData = Buffer.from(td10.reportData);
  const mrConfig = Buffer.from(td10.mrConfigId);

  const status: string | undefined =
    typeof verificationDataRaw?.status === 'string'
      ? verificationDataRaw.status
      : undefined;

  const verified = status ? status === 'UpToDate' : false;

  return {
    quote: {
      body: {
        reportdata: `0x${reportData.toString('hex')}`,
        mrconfig: `0x${mrConfig.toString('hex')}`,
      },
      verified,
    },
  };
}

/* eslint-disable-next-line @typescript-eslint/no-unused-vars */
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

  return response.json();
}
