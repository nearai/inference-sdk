import { INTEL_PCCS_API_URL, INTEL_TDX_VERIFIER_API_URL } from './consts';
import { IntelTdxVerification } from '../types/intel';
import { hexToBuffer } from './common';
import { getDcapQvlUtils } from './dcap-qvl';
import { VerificationError } from './errors';
import { Buffer } from 'buffer';

export function assertIntelTdxVerified(
  verification: IntelTdxVerification,
  requestNonce: string,
  signingAddress: string,
) {
  if (!verification.quote.verified) {
    throw new VerificationError('Failed to verify Intel quote');
  }

  assertReportDataVerified(
    verification.quote.body.reportdata,
    requestNonce,
    signingAddress,
  );
}

function assertReportDataVerified(
  reportData: string,
  requestNonce: string,
  signingAddress: string,
) {
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

  if (!addressVerified) {
    throw new VerificationError('Signing address mismatching');
  }

  const nonceVerified = embeddedNonce.equals(hexToBuffer(requestNonce));

  if (!nonceVerified) {
    throw new VerificationError('Request nonce mismatching');
  }
}

export async function verifyIntelTdx(
  quote: string,
): Promise<IntelTdxVerification> {
  return verifyIntelTdxLocal(quote);
}

async function verifyIntelTdxLocal(
  quote: string,
): Promise<IntelTdxVerification> {
  const { jsVerify, jsGetCollateral } = await getDcapQvlUtils();

  const quoteRaw = hexToBuffer(quote);

  let collateral;

  try {
    collateral = await jsGetCollateral(INTEL_PCCS_API_URL, quoteRaw);
  } catch (e: unknown) {
    throw new VerificationError(`Failed to get collateral: ${e}`);
  }

  let verificationRaw;

  try {
    verificationRaw = jsVerify(
      quoteRaw,
      collateral,
      BigInt(Math.floor(Date.now() / 1000)),
    );
  } catch (e: unknown) {
    throw new VerificationError(`Failed to verify Intel TDX: ${e}`);
  }

  const td10 = verificationRaw?.report?.TD10 ? verificationRaw.report.TD10 : {};
  if (!td10.report_data || typeof td10.report_data !== 'string') {
    throw new VerificationError('Bad report_data');
  }
  if (!td10.mr_config_id || typeof td10.mr_config_id !== 'string') {
    throw new VerificationError('Bad mr_config_id');
  }

  const reportData: string = td10.report_data;
  const mrConfig: string = td10.mr_config_id;

  const status: string | undefined =
    typeof verificationRaw?.status === 'string'
      ? verificationRaw.status
      : undefined;
  const verifiedFromStatus = status ? status === 'UpToDate' : false;
  const verified = verifiedFromStatus || !!verificationRaw?.quote?.verified;

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
async function verifyIntelTdxRemote(
  quote: string,
): Promise<IntelTdxVerification> {
  const response = await fetch(INTEL_TDX_VERIFIER_API_URL, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
    },
    body: JSON.stringify({ hex: quote }),
  });

  if (!response.ok) {
    throw new VerificationError(
      `Failed to verify Intel TDX with status code ${response.status}`,
    );
  }

  return await response.json();
}
