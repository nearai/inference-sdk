import { Buffer } from 'buffer';
import type { GatewayTlsBinding, ModelTlsBinding } from '../types/verification';
import { VerificationError } from '../utils/errors';
import { hexToBuffer, requireByteLength, sha256, utf8 } from '../utils/common';

/**
 * Reject an inconsistent wire report early. This JSON field is untrusted;
 * freshness is established only when the Intel-signed report data contains the
 * same caller nonce.
 */
export function verifyReportedNonce(
  reportedNonce: string,
  nonce: string,
  source:
    | 'attestationNonce'
    | 'quoteReportData'
    | 'nvidiaPayload' = 'attestationNonce',
): void {
  const expected = requireByteLength(nonce, 32, 'nonce');
  const reported = requireByteLength(
    reportedNonce,
    32,
    source === 'nvidiaPayload' ? 'nvidiaPayload.nonce' : 'attestation.nonce',
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
 * - bytes [0, 32): SHA-256(signer address bytes || TLS SPKI fingerprint)
 * - bytes [32, 64): caller's 32-byte nonce
 *
 * The first half becomes a gateway endpoint binding only after the report's
 * fingerprint is compared with the peer SPKI observed by the caller on that
 * same TLS connection.
 */
export async function verifyGatewayReportDataBinding(input: {
  reportData: Uint8Array;
  nonce: string;
  signingAddress: string;
  reportedSpkiFingerprint: string | null | undefined;
  peerSpkiFingerprint: string;
}): Promise<GatewayTlsBinding> {
  const reportData = Buffer.from(input.reportData);
  if (reportData.length !== 64) {
    throw new VerificationError({
      phase: 'binding',
      code: 'binding.report_data_invalid',
      details: {
        source: 'quoteReportData',
        reason: 'wrong_length',
        expectedBytes: 64,
        actualBytes: reportData.length,
      },
    });
  }

  const expectedNonce = requireByteLength(input.nonce, 32, 'nonce');
  if (!reportData.subarray(32, 64).equals(expectedNonce)) {
    throw new VerificationError({
      phase: 'binding',
      code: 'binding.nonce_mismatch',
      details: { source: 'quoteReportData' },
    });
  }

  if (!input.reportedSpkiFingerprint) {
    throw new VerificationError({
      phase: 'binding',
      code: 'binding.spki_fingerprint_missing',
    });
  }

  const reportedFingerprint = requireByteLength(
    input.reportedSpkiFingerprint,
    32,
    'attestation.declaredSpkiFingerprint',
  );
  const peerFingerprint = requireByteLength(
    input.peerSpkiFingerprint,
    32,
    'peerSpkiFingerprint',
  );
  if (!reportedFingerprint.equals(peerFingerprint)) {
    throw new VerificationError({
      phase: 'binding',
      code: 'binding.spki_fingerprint_mismatch',
      details: { source: 'peer_tls_connection' },
    });
  }

  const signingAddress = hexToBuffer(input.signingAddress, 'signer.address');
  const expectedBinding = await sha256(
    Buffer.concat([signingAddress, reportedFingerprint]),
  );
  if (!reportData.subarray(0, 32).equals(expectedBinding)) {
    throw new VerificationError({
      phase: 'binding',
      code: 'binding.report_data_mismatch',
      details: { source: 'signerTlsBinding' },
    });
  }

  return {
    kind: 'peer',
    spkiFingerprint: reportedFingerprint.toString('hex'),
  };
}

/**
 * Verify the model-report binding returned through the Cloud API. A client is
 * not connected to the upstream model endpoint, so a successful check never
 * claims client-to-model TLS binding. Both model layouts bind the signer and
 * nonce; when the report declares a TLS fingerprint, it is additionally bound
 * inside the quote but is not a client-observed peer certificate.
 *
 * - bytes [32, 64) always contain the caller nonce.
 * - Without `declaredSpkiFingerprint`, bytes [0, 32) are the signing address
 *   zero-padded to 32 bytes.
 * - With `declaredSpkiFingerprint`, bytes [0, 32) are
 *   SHA-256(signing address || declared fingerprint).
 *
 * Presence of the fingerprint selects the latter layout. Never downgrade a
 * report that declares a fingerprint to the legacy signer-only layout.
 */
export async function verifyCloudModelReportDataBinding(input: {
  reportData: Uint8Array;
  nonce: string;
  signingAddress: string;
  reportedSpkiFingerprint: string | null | undefined;
}): Promise<ModelTlsBinding> {
  const reportData = Buffer.from(input.reportData);
  if (reportData.length !== 64) {
    throw new VerificationError({
      phase: 'binding',
      code: 'binding.report_data_invalid',
      details: {
        source: 'quoteReportData',
        reason: 'wrong_length',
        expectedBytes: 64,
        actualBytes: reportData.length,
      },
    });
  }
  const expectedNonce = requireByteLength(input.nonce, 32, 'nonce');
  if (!reportData.subarray(32, 64).equals(expectedNonce)) {
    throw new VerificationError({
      phase: 'binding',
      code: 'binding.nonce_mismatch',
      details: { source: 'quoteReportData' },
    });
  }

  const signingAddress = hexToBuffer(input.signingAddress, 'signer.address');
  if (
    input.reportedSpkiFingerprint !== undefined &&
    input.reportedSpkiFingerprint !== null
  ) {
    const fingerprint = requireByteLength(
      input.reportedSpkiFingerprint,
      32,
      'attestation.declaredSpkiFingerprint',
    );
    const expectedBinding = await sha256(
      Buffer.concat([signingAddress, fingerprint]),
    );
    if (!reportData.subarray(0, 32).equals(expectedBinding)) {
      throw new VerificationError({
        phase: 'binding',
        code: 'binding.report_data_mismatch',
        details: { source: 'signerTlsBinding' },
      });
    }
    return {
      kind: 'declared',
      spkiFingerprint: fingerprint.toString('hex'),
    };
  }

  // Legacy Cloud model layout is a zero-padded signer, not a hash. Keep it
  // separate from the declared-fingerprint layout above.
  const expectedBinding = Buffer.alloc(32);
  signingAddress.copy(expectedBinding);
  if (!reportData.subarray(0, 32).equals(expectedBinding)) {
    throw new VerificationError({
      phase: 'binding',
      code: 'binding.report_data_mismatch',
      details: { source: 'signerBinding' },
    });
  }
  return { kind: 'none' };
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
    });
  }
}

/**
 * Cross-check the optional JSON `report_data` copy against the authenticated
 * Intel quote. The quote remains the trust source; this rejects incoherent
 * wire evidence without treating the JSON field as independently trusted.
 */
export function verifyAdvertisedReportData(
  advertisedReportData: string | undefined,
  quoteReportData: Uint8Array,
): void {
  if (advertisedReportData === undefined) {
    return;
  }
  let advertised: Buffer;
  try {
    advertised = hexToBuffer(
      advertisedReportData,
      'attestation.reportedQuoteData',
    );
  } catch (cause) {
    throw new VerificationError(
      {
        phase: 'binding',
        code: 'binding.report_data_invalid',
        details: {
          source: 'reportedQuoteData',
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
        source: 'reportedQuoteData',
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
      details: { source: 'reportedQuoteData' },
    });
  }
}
