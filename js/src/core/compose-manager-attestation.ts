import { Buffer } from 'buffer';
import type {
  ComposeManagerAttestation,
  VerifiedComposeManagerAttestation,
} from '../types/compose-manager';
import type {
  AttestationPolicy,
  TdxQuoteVerifier,
} from '../types/verification';
import { requireByteLength, sha256, utf8 } from '../utils/common';
import { VerificationError } from '../utils/errors';
import {
  verifyAdvertisedReportData,
  verifyAppComposeMrConfigBinding,
  verifyQuoteReportDataNonce,
  verifyReportedNonce,
} from './attestation-common';
import { verifyTdxQuote } from './dstack-attestation';
import { verifyAndReplayRtmr3 } from './event-log';

type VerifyComposeManagerAttestationParams = {
  attestation: ComposeManagerAttestation;
  appCompose: string;
  nonce: string;
  policy?: AttestationPolicy;
  tdxQuoteVerifier?: TdxQuoteVerifier;
};

/**
 * Authenticate the action log and its freshness. Matching appCompose binds the
 * two reports to the same measured configuration, not a unique CVM instance.
 * Action entries are deployment requests, not successful/current-state claims.
 */
export async function verifyComposeManagerAttestation({
  attestation,
  appCompose,
  nonce,
  policy,
  tdxQuoteVerifier,
}: VerifyComposeManagerAttestationParams): Promise<VerifiedComposeManagerAttestation> {
  verifyReportedNonce({
    reportedNonce: attestation.nonce,
    nonce,
    source: 'composeManagerAttestation',
  });
  const quote = await verifyTdxQuote({
    intelQuote: attestation.intelQuote,
    policy,
    verifier: tdxQuoteVerifier,
  });
  verifyAdvertisedReportData(attestation.reportedQuoteData, quote.reportData);
  const reportData = verifyQuoteReportDataNonce({
    reportData: quote.reportData,
    nonce,
  });

  // Keep unknown string-valued action fields in the hash. The wire schema
  // preserves them; dropping them during domain mapping would change the log.
  // Serialize sorted entries directly: JSON.stringify(object) would reorder
  // integer-like keys numerically, unlike the server's lexical key order.
  const actionsJson = `[${attestation.actions
    .map((action) => {
      const fields = Object.entries(action)
        .sort(([left], [right]) => Buffer.compare(utf8(left), utf8(right)))
        .map(
          ([key, value]) => `${JSON.stringify(key)}:${JSON.stringify(value)}`,
        );
      return `{${fields.join(',')}}`;
    })
    .join(',')}]`;
  const actionsHash = await sha256(utf8(actionsJson));
  const reportedHash = requireByteLength({
    value: attestation.actionsHash,
    byteLength: 32,
    label: 'composeManagerAttestation.actionsHash',
  });
  if (
    !actionsHash.equals(reportedHash) ||
    !reportData.subarray(0, 32).equals(actionsHash)
  ) {
    throw new VerificationError({
      code: 'binding.compose_manager_actions_mismatch',
    });
  }

  await verifyAppComposeMrConfigBinding(appCompose, quote.mrConfigId);
  const runtimeMeasurements = await verifyAndReplayRtmr3(
    attestation.eventLog,
    quote.rtMr3,
  );
  return {
    actions: attestation.actions,
    tcbStatus: quote.tcbStatus,
    advisoryIds: quote.advisoryIds,
    runtimeMeasurements,
  };
}
