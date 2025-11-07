import { hexToBuffer } from '../utils/common';
import { VerificationError } from '../utils/errors';
import { SIGSTORE_SEARCH_API_URL } from '../utils/consts';
import { TcbInfo } from '../types/attestation-common';

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

export function getComposeFromTcbInfo(tcbInfo: string | TcbInfo): string {
  if (typeof tcbInfo === 'string') {
    try {
      tcbInfo = JSON.parse(tcbInfo);
    } catch {
      throw new VerificationError('Invalid tcb info');
    }
  }
  return (tcbInfo as TcbInfo).app_compose;
}

export async function verifyCompose(compose: string) {
  const links = getSigstoreLinksFromCompose(compose);
  for (const link of links) {
    await verifySigstoreLink(link);
  }
}

function getSigstoreLinksFromCompose(compose: string): string[] {
  const digestsIter = compose
    .matchAll(/@sha256:([0-9a-f]{64})/g)
    .map(([, digest]) => digest);
  const digests = Array.from(new Set(digestsIter));
  return digests.map(
    (digest) => `${SIGSTORE_SEARCH_API_URL}/?hash=sha256:${digest}`,
  );
}

async function verifySigstoreLink(link: string) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 10_000);

  let res;

  try {
    res = await fetch(link, {
      method: 'HEAD',
      redirect: 'follow',
      signal: controller.signal,
    });
  } catch (e: unknown) {
    throw new VerificationError(`Verify sigstore link ${link} timeout`, e);
  } finally {
    clearTimeout(timeoutId);
  }

  if (res.status >= 400) {
    throw new VerificationError(
      `Failed to verify sigstore link ${link} with status code ${res.status}`,
    );
  }
}
