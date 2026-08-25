import { TcbInfo } from '../types/attestation-common';
import { VerificationError } from '../utils/errors';
import { hexToBuffer, requireByteLength, sha256, utf8 } from '../utils/common';

/** Validate freshness at the untrusted JSON layer before inspecting the quote. */
export function verifyReportedNonce(
  reportedNonce: string,
  expectedNonce: string,
): void {
  const expected = requireByteLength(expectedNonce, 32, 'expectedNonce');
  const reported = requireByteLength(reportedNonce, 32, 'request_nonce');

  if (!reported.equals(expected)) {
    throw new VerificationError('request_nonce does not match expectedNonce');
  }
}

/**
 * Verify the strict NEAR report-data layout held inside an Intel-signed quote:
 *
 * - bytes 0..32: SHA-256(signing_address_bytes || TLS SPKI fingerprint bytes)
 * - bytes 32..64: caller's 32-byte nonce
 */
export async function verifyStrictReportDataBinding(input: {
  reportData: Uint8Array;
  expectedNonce: string;
  signingAddress: string;
  reportedTlsCertFingerprint: string | null | undefined;
  peerTlsCertFingerprint: string;
}): Promise<string> {
  const reportData = Buffer.from(input.reportData);
  if (reportData.length !== 64) {
    throw new VerificationError(
      `quote report_data must be 64 bytes, got ${reportData.length}`,
    );
  }

  const expectedNonce = requireByteLength(
    input.expectedNonce,
    32,
    'expectedNonce',
  );
  if (!reportData.subarray(32, 64).equals(expectedNonce)) {
    throw new VerificationError('quote report_data nonce mismatch');
  }

  if (!input.reportedTlsCertFingerprint) {
    throw new VerificationError(
      'attestation is missing tls_cert_fingerprint; strict TLS binding is required',
    );
  }

  const reportedFingerprint = requireByteLength(
    input.reportedTlsCertFingerprint,
    32,
    'tls_cert_fingerprint',
  );
  const peerFingerprint = requireByteLength(
    input.peerTlsCertFingerprint,
    32,
    'peerTlsCertFingerprint',
  );
  if (!reportedFingerprint.equals(peerFingerprint)) {
    throw new VerificationError(
      'attestation TLS fingerprint does not match the peer TLS connection',
    );
  }

  const signingAddress = hexToBuffer(input.signingAddress);
  const expectedBinding = await sha256(
    Buffer.concat([signingAddress, reportedFingerprint]),
  );
  if (!reportData.subarray(0, 32).equals(expectedBinding)) {
    throw new VerificationError(
      'quote report_data signing/TLS binding mismatch',
    );
  }

  return reportedFingerprint.toString('hex');
}

/**
 * Verify the model-report binding returned through the Cloud API. A client is
 * not connected to the upstream model endpoint, so this checks the quote's
 * signer/fingerprint/nonce binding but deliberately does not claim a
 * client-to-model TLS connection binding. NEAR reports use the strict
 * fingerprint form even when the client cannot observe that upstream
 * connection itself.
 */
export async function verifyCloudModelReportDataBinding(input: {
  reportData: Uint8Array;
  expectedNonce: string;
  signingAddress: string;
  reportedTlsCertFingerprint: string | null | undefined;
}): Promise<string> {
  const reportData = Buffer.from(input.reportData);
  if (reportData.length !== 64) {
    throw new VerificationError(
      `quote report_data must be 64 bytes, got ${reportData.length}`,
    );
  }
  const expectedNonce = requireByteLength(
    input.expectedNonce,
    32,
    'expectedNonce',
  );
  if (!reportData.subarray(32, 64).equals(expectedNonce)) {
    throw new VerificationError('quote report_data nonce mismatch');
  }

  if (!input.reportedTlsCertFingerprint) {
    throw new VerificationError(
      'attestation is missing tls_cert_fingerprint; strict NEAR binding is required',
    );
  }
  const signingAddress = hexToBuffer(input.signingAddress);
  const fingerprint = requireByteLength(
    input.reportedTlsCertFingerprint,
    32,
    'tls_cert_fingerprint',
  );
  const expectedBinding = await sha256(
    Buffer.concat([signingAddress, fingerprint]),
  );
  if (!reportData.subarray(0, 32).equals(expectedBinding)) {
    throw new VerificationError(
      'quote report_data signing/TLS binding mismatch',
    );
  }
  return fingerprint.toString('hex');
}

/** Pull the raw compose string without normalizing or serializing it again. */
export function getRawAppCompose(tcbInfo: string | TcbInfo): string {
  let parsed: unknown = tcbInfo;
  if (typeof parsed === 'string') {
    try {
      parsed = JSON.parse(parsed);
    } catch (cause) {
      throw new VerificationError('info.tcb_info is not valid JSON', cause);
    }
  }

  if (
    !parsed ||
    typeof parsed !== 'object' ||
    !('app_compose' in parsed) ||
    typeof parsed.app_compose !== 'string'
  ) {
    throw new VerificationError('info.tcb_info.app_compose is missing');
  }

  return parsed.app_compose;
}

/**
 * dstack prefixes SHA-256(raw app_compose UTF-8) with version byte 0x01 in
 * MRCONFIGID. The rest of MRCONFIGID is reserved and is not re-serialized.
 */
export async function verifyAppComposeMrConfigBinding(
  appCompose: string,
  mrConfigId: Uint8Array,
): Promise<void> {
  const mrConfig = Buffer.from(mrConfigId);
  if (mrConfig.length < 33) {
    throw new VerificationError(
      `quote MRCONFIGID must contain a version byte and SHA-256, got ${mrConfig.length} bytes`,
    );
  }
  if (mrConfig[0] !== 0x01) {
    throw new VerificationError('quote MRCONFIGID has an unsupported version');
  }

  const composeHash = await sha256(utf8(appCompose));
  if (!mrConfig.subarray(1, 33).equals(composeHash)) {
    throw new VerificationError(
      'raw app_compose does not match quote MRCONFIGID',
    );
  }
}

/** Extract image digests for an optional caller-supplied provenance verifier. */
export function extractImageDigests(appCompose: string): string[] {
  const digests = new Set<string>();
  for (const match of appCompose.matchAll(/@sha256:([0-9a-fA-F]{64})/g)) {
    digests.add(match[1].toLowerCase());
  }
  return [...digests];
}

export function verifyAdvertisedReportData(
  advertisedReportData: string | undefined,
  quoteReportData: Uint8Array,
): void {
  if (advertisedReportData === undefined) {
    return;
  }
  let advertised: Buffer;
  try {
    advertised = requireByteLength(
      advertisedReportData,
      64,
      'reported report_data',
    );
  } catch (cause) {
    throw new VerificationError(
      'reported report_data must be a 64-byte hex string',
      cause,
    );
  }
  if (!advertised.equals(Buffer.from(quoteReportData))) {
    throw new VerificationError(
      'reported report_data does not match the Intel-verified quote',
    );
  }
}
