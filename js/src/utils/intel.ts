import { INTEL_PCCS_API_URL, INTEL_TDX_VERIFIER_API_URL } from './consts';
import { IntelTdxVerification } from '../types/intel';
import { hexToBuffer } from './common';
import { js_verify, js_get_collateral } from '@phala/dcap-qvl-node';

export function isIntelTdxVerified(
  verification: IntelTdxVerification,
  requestNonce: string,
  signingAddress: string,
): boolean {
  return (
    verification.quote.verified &&
    isReportDataVerified(
      verification.quote.body.reportdata,
      requestNonce,
      signingAddress,
    )
  );
}

export async function verifyIntelTdx(
  quote: string,
): Promise<IntelTdxVerification> {
  return verifyIntelTdxLocal(quote);
}

export async function verifyIntelTdxLocal(
  quote: string,
): Promise<IntelTdxVerification> {
  const quoteRaw = hexToBuffer(quote);

  let collateral;

  try {
    collateral = await js_get_collateral(INTEL_PCCS_API_URL, quoteRaw);
  } catch {
    throw Error('Failed to get collateral');
  }

  const verificationRaw = js_verify(
    quoteRaw,
    collateral,
    BigInt(Math.floor(Date.now() / 1000)),
  );

  const td10 = verificationRaw?.report?.TD10 ? verificationRaw.report.TD10 : {};
  if (!td10.report_data || typeof td10.report_data !== 'string') {
    throw Error('Failed to verify intel tdx: bad report_data');
  }
  if (!td10.mr_config_id || typeof td10.mr_config_id !== 'string') {
    throw Error('Failed to verify intel tdx: bad mr_config_id');
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

export async function verifyIntelTdxRemote(
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
    throw Error(`Verify Intel TDX failed with status code ${response.status}`);
  }

  return await response.json();
}

function isReportDataVerified(
  reportData: string,
  requestNonce: string,
  signingAddress: string,
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
