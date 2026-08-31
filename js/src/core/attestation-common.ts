import { Buffer } from 'buffer';
import { hexToBuffer, requireByteLength, sha256, utf8 } from '../utils/common';
import { VerificationError } from '../utils/errors';

type NonceSource = 'attestationNonce' | 'quoteReportData' | 'nvidiaPayload';

type VerifyReportedNonceParams = {
  reportedNonce: string;
  nonce: string;
  source?: NonceSource;
};

type VerifyReportDataBindingWithTlsFingerprintParams = {
  reportData: Uint8Array;
  nonce: string;
  signingAddress: string;
  reportedTlsSpkiFingerprint?: string;
  peerTlsSpkiFingerprint: string;
};

type VerifyReportDataBindingParams = {
  reportData: Uint8Array;
  nonce: string;
  signingAddress: string;
};

/**
 * Reject an inconsistent wire report early. This JSON field is untrusted;
 * freshness is established only when the Intel-signed report data contains the
 * same caller nonce.
 */
export function verifyReportedNonce({
  reportedNonce,
  nonce,
  source = 'attestationNonce',
}: VerifyReportedNonceParams): void {
  const expected = requireByteLength({
    value: nonce,
    byteLength: 32,
    label: 'nonce',
  });
  const reported = requireByteLength({
    value: reportedNonce,
    byteLength: 32,
    label:
      source === 'nvidiaPayload' ? 'nvidiaPayload.nonce' : 'attestation.nonce',
  });

  if (!reported.equals(expected)) {
    throw new VerificationError({
      code: 'binding.nonce_mismatch',
      details: { source },
    });
  }
}

/**
 * Verify the signer-and-TLS report-data layout held inside an Intel-signed
 * quote:
 *
 * - bytes [0, 32): SHA-256(signing-address bytes || TLS SPKI fingerprint)
 * - bytes [32, 64): caller's 32-byte nonce
 *
 * The first half binds the Gateway signing key and TLS key. The returned
 * fingerprint is valid only when it also matches the caller-observed TLS peer.
 */
export async function verifyReportDataBindingWithTlsFingerprint(
  input: VerifyReportDataBindingWithTlsFingerprintParams,
): Promise<string> {
  const reportData = verifyQuoteReportDataNonce({
    reportData: input.reportData,
    nonce: input.nonce,
  });
  if (input.reportedTlsSpkiFingerprint === undefined) {
    throw new VerificationError({ code: 'policy.tls_binding_required' });
  }
  const reportedFingerprint = requireByteLength({
    value: input.reportedTlsSpkiFingerprint,
    byteLength: 32,
    label: 'attestation.tlsSpkiFingerprint',
  });

  const signingAddress = hexToBuffer(
    input.signingAddress,
    'signer.signingAddress',
  );
  const expectedBinding = await sha256(
    Buffer.concat([signingAddress, reportedFingerprint]),
  );
  if (!reportData.subarray(0, 32).equals(expectedBinding)) {
    throw new VerificationError({
      code: 'binding.report_data_mismatch',
      details: { source: 'signerTlsBinding' },
    });
  }

  const peerFingerprint = requireByteLength({
    value: input.peerTlsSpkiFingerprint,
    byteLength: 32,
    label: 'clientBinding.peerSpkiFingerprint',
  });
  if (!reportedFingerprint.equals(peerFingerprint)) {
    throw new VerificationError({
      code: 'binding.spki_fingerprint_mismatch',
    });
  }

  return reportedFingerprint.toString('hex');
}

/**
 * Verify the signer-and-nonce report-data layout used when TLS binding is not
 * requested. The first half is the signing address zero-padded to 32 bytes;
 * the second half is the caller nonce.
 */
export function verifyReportDataBinding({
  reportData: rawReportData,
  nonce,
  signingAddress: rawSigningAddress,
}: VerifyReportDataBindingParams): void {
  const reportData = verifyQuoteReportDataNonce({
    reportData: rawReportData,
    nonce,
  });
  const signingAddress = hexToBuffer(
    rawSigningAddress,
    'signer.signingAddress',
  );
  const expectedBinding = Buffer.alloc(32);
  signingAddress.copy(expectedBinding);
  if (!reportData.subarray(0, 32).equals(expectedBinding)) {
    throw new VerificationError({
      code: 'binding.report_data_mismatch',
      details: { source: 'signerBinding' },
    });
  }
}

type VerifyQuoteReportDataNonceParams = {
  reportData: Uint8Array;
  nonce: string;
};

function verifyQuoteReportDataNonce({
  reportData: rawReportData,
  nonce,
}: VerifyQuoteReportDataNonceParams): Buffer {
  const reportData = Buffer.from(rawReportData);
  if (reportData.length !== 64) {
    throw new VerificationError({
      code: 'binding.report_data_invalid',
      details: {
        source: 'quoteReportData',
        reason: 'wrong_length',
        expectedBytes: 64,
        actualBytes: reportData.length,
      },
    });
  }
  const expectedNonce = requireByteLength({
    value: nonce,
    byteLength: 32,
    label: 'nonce',
  });
  if (!reportData.subarray(32, 64).equals(expectedNonce)) {
    throw new VerificationError({
      code: 'binding.nonce_mismatch',
      details: { source: 'quoteReportData' },
    });
  }
  return reportData;
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
      code: 'measurement.mrconfigid_invalid',
      details: { reason: 'unsupported_version', version: mrConfig[0] },
    });
  }

  const composeHash = await sha256(utf8(appCompose));
  if (!mrConfig.subarray(1, 33).equals(composeHash)) {
    throw new VerificationError({
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
      code: 'binding.report_data_mismatch',
      details: { source: 'reportedQuoteData' },
    });
  }
}
