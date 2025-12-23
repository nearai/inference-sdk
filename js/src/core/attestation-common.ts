import { hexToBuffer } from '../utils/common';
import { VerificationError } from '../utils/errors';
import { SIGSTORE_SEARCH_API_URL, TIMEOUT } from '../utils/consts';
import { TcbInfo } from '../types/attestation-common';
import { Buffer } from 'buffer';
import { fetchTimeout } from '../utils/fetch';

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

export async function verifyCompose(
  compose: string,
  imageNamesOfSigstoreHash: string[],
) {
  const hashes = getSigstoreHashesFromCompose(
    compose,
    imageNamesOfSigstoreHash,
  );
  for (const hash of hashes) {
    await verifySigstoreHash(hash);
  }
}

function getSigstoreHashesFromCompose(
  compose: string,
  imageNamesOfSigstoreHash: string[],
): string[] {
  const names = new Set(imageNamesOfSigstoreHash);

  const digestsIter = compose
    .matchAll(/([^@\s]+)@sha256:([0-9a-f]{64})/g)
    .filter(([, name]) => names.has(name))
    .map(([, , digest]) => digest);

  const digests = new Set(digestsIter);

  if (digests.size === 0) {
    throw new VerificationError('No sigstore hash matches in compose');
  }

  return Array.from(digests);
}

async function verifySigstoreHash(hash: string) {
  const response = await fetchTimeout(SIGSTORE_SEARCH_API_URL, TIMEOUT, {
    method: 'POST',
    body: JSON.stringify({
      hash,
    }),
    headers: {
      'content-type': 'application/json',
    },
  });

  if (!response.ok) {
    throw new VerificationError(
      `Failed to verify sigstore hash with status code ${response.status}`,
    );
  }

  const outputs: string[] = await response.json();

  if (outputs.length === 0) {
    throw new VerificationError(`Invalid sigstore hash ${hash}`);
  }
}
