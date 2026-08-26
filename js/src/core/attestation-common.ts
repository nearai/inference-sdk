import { TcbInfo } from '../types/attestation-common';
import {
  GatewayReportDataBinding,
  ModelReportDataBinding,
} from '../types/verification';
import { VerificationError } from '../utils/errors';
import { hexToBuffer, requireByteLength, sha256, utf8 } from '../utils/common';

/** Validate freshness at the untrusted JSON layer before inspecting the quote. */
export function verifyReportedNonce(
  reportedNonce: string,
  expectedNonce: string,
  source:
    | 'request_nonce'
    | 'quote_report_data'
    | 'nvidia_payload' = 'request_nonce',
): void {
  const expected = requireByteLength(expectedNonce, 32, 'expectedNonce');
  const reported = requireByteLength(
    reportedNonce,
    32,
    source === 'nvidia_payload' ? 'nvidia_payload.nonce' : 'request_nonce',
  );

  if (!reported.equals(expected)) {
    throw new VerificationError({
      phase: 'binding',
      code: 'binding.nonce_mismatch',
      details: { source },
    });
  }
}

/**
 * Verify the strict NEAR report-data layout held inside an Intel-signed quote:
 *
 * - bytes 0..32: SHA-256(signing_address_bytes || TLS SPKI fingerprint bytes)
 * - bytes 32..64: caller's 32-byte nonce
 */
export async function verifyGatewayReportDataBinding(input: {
  reportData: Uint8Array;
  expectedNonce: string;
  signingAddress: string;
  reportedTlsCertFingerprint: string | null | undefined;
  peerTlsCertFingerprint: string;
}): Promise<GatewayReportDataBinding> {
  const reportData = Buffer.from(input.reportData);
  if (reportData.length !== 64) {
    throw new VerificationError({
      phase: 'binding',
      code: 'binding.report_data_invalid',
      details: {
        source: 'quote_report_data',
        reason: 'wrong_length',
        expectedBytes: 64,
        actualBytes: reportData.length,
      },
    });
  }

  const expectedNonce = requireByteLength(
    input.expectedNonce,
    32,
    'expectedNonce',
  );
  if (!reportData.subarray(32, 64).equals(expectedNonce)) {
    throw new VerificationError({
      phase: 'binding',
      code: 'binding.nonce_mismatch',
      details: { source: 'quote_report_data' },
    });
  }

  if (!input.reportedTlsCertFingerprint) {
    throw new VerificationError({
      phase: 'binding',
      code: 'binding.tls_fingerprint_missing',
      details: { target: 'gateway' },
    });
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
    throw new VerificationError({
      phase: 'binding',
      code: 'binding.tls_fingerprint_mismatch',
      details: { source: 'peer_tls_connection' },
    });
  }

  const signingAddress = hexToBuffer(input.signingAddress, 'signing_address');
  const expectedBinding = await sha256(
    Buffer.concat([signingAddress, reportedFingerprint]),
  );
  if (!reportData.subarray(0, 32).equals(expectedBinding)) {
    throw new VerificationError({
      phase: 'binding',
      code: 'binding.report_data_mismatch',
      details: { source: 'signer_tls_binding' },
    });
  }

  return {
    kind: 'signer_peer_tls_nonce',
    tlsCertFingerprint: reportedFingerprint.toString('hex'),
  };
}

/**
 * Verify the model-report binding returned through the Cloud API. A client is
 * not connected to the upstream model endpoint, so a successful check never
 * claims client-to-model TLS binding. Both model layouts bind the signer and
 * nonce; when the report declares a TLS fingerprint, it is additionally bound
 * inside the quote but is not a client-observed peer certificate.
 */
export async function verifyCloudModelReportDataBinding(input: {
  reportData: Uint8Array;
  expectedNonce: string;
  signingAddress: string;
  reportedTlsCertFingerprint: string | null | undefined;
}): Promise<ModelReportDataBinding> {
  const reportData = Buffer.from(input.reportData);
  if (reportData.length !== 64) {
    throw new VerificationError({
      phase: 'binding',
      code: 'binding.report_data_invalid',
      details: {
        source: 'quote_report_data',
        reason: 'wrong_length',
        expectedBytes: 64,
        actualBytes: reportData.length,
      },
    });
  }
  const expectedNonce = requireByteLength(
    input.expectedNonce,
    32,
    'expectedNonce',
  );
  if (!reportData.subarray(32, 64).equals(expectedNonce)) {
    throw new VerificationError({
      phase: 'binding',
      code: 'binding.nonce_mismatch',
      details: { source: 'quote_report_data' },
    });
  }

  const signingAddress = hexToBuffer(input.signingAddress, 'signing_address');
  if (
    input.reportedTlsCertFingerprint !== undefined &&
    input.reportedTlsCertFingerprint !== null
  ) {
    const fingerprint = requireByteLength(
      input.reportedTlsCertFingerprint,
      32,
      'tls_cert_fingerprint',
    );
    const expectedBinding = await sha256(
      Buffer.concat([signingAddress, fingerprint]),
    );
    if (!reportData.subarray(0, 32).equals(expectedBinding)) {
      throw new VerificationError({
        phase: 'binding',
        code: 'binding.report_data_mismatch',
        details: { source: 'signer_tls_binding' },
      });
    }
    return {
      kind: 'signer_declared_tls_nonce',
      tlsCertFingerprint: fingerprint.toString('hex'),
    };
  }

  const expectedBinding = Buffer.alloc(32);
  signingAddress.copy(expectedBinding);
  if (!reportData.subarray(0, 32).equals(expectedBinding)) {
    throw new VerificationError({
      phase: 'binding',
      code: 'binding.report_data_mismatch',
      details: { source: 'signer_binding' },
    });
  }
  return { kind: 'signer_nonce' };
}

/** Pull the raw compose string without normalizing or serializing it again. */
export function getRawAppCompose(tcbInfo: string | TcbInfo): string {
  let parsed: unknown = tcbInfo;
  if (typeof parsed === 'string') {
    try {
      parsed = JSON.parse(parsed);
    } catch (cause) {
      throw new VerificationError(
        {
          phase: 'measurement',
          code: 'measurement.app_compose_invalid',
          details: { reason: 'invalid_json' },
        },
        { cause },
      );
    }
  }

  if (
    !parsed ||
    typeof parsed !== 'object' ||
    !('app_compose' in parsed) ||
    typeof parsed.app_compose !== 'string'
  ) {
    throw new VerificationError({
      phase: 'measurement',
      code: 'measurement.app_compose_invalid',
      details: { reason: 'missing' },
    });
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
    throw new VerificationError({
      phase: 'measurement',
      code: 'measurement.mrconfigid_invalid',
      details: {
        reason: 'wrong_length',
        minimumBytes: 33,
        actualBytes: mrConfig.length,
      },
    });
  }
  if (mrConfig[0] !== 0x01) {
    throw new VerificationError({
      phase: 'measurement',
      code: 'measurement.mrconfigid_invalid',
      details: { reason: 'unsupported_version', version: mrConfig[0] },
    });
  }

  const composeHash = await sha256(utf8(appCompose));
  if (!mrConfig.subarray(1, 33).equals(composeHash)) {
    throw new VerificationError({
      phase: 'measurement',
      code: 'measurement.app_compose_mrconfigid_mismatch',
      details: {},
    });
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
    advertised = hexToBuffer(advertisedReportData, 'reported report_data');
  } catch (cause) {
    throw new VerificationError(
      {
        phase: 'binding',
        code: 'binding.report_data_invalid',
        details: {
          source: 'advertised_report_data',
          reason: 'invalid_hex',
          expectedBytes: 64,
        },
      },
      { cause },
    );
  }
  if (advertised.length !== 64) {
    throw new VerificationError({
      phase: 'binding',
      code: 'binding.report_data_invalid',
      details: {
        source: 'advertised_report_data',
        reason: 'wrong_length',
        expectedBytes: 64,
        actualBytes: advertised.length,
      },
    });
  }
  if (!advertised.equals(Buffer.from(quoteReportData))) {
    throw new VerificationError({
      phase: 'binding',
      code: 'binding.report_data_mismatch',
      details: { source: 'advertised_report_data' },
    });
  }
}
