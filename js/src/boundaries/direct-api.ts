import * as v from 'valibot';
import {
  DirectApiAttestationReportSchema,
  DirectApiCompletionSignatureResultSchema,
} from '../schemas';
import type { CompletionSignature } from '../types/chat';
import type {
  DirectApiModelAttestation,
  DirectAttestationReport,
  DirectModelAttestation,
} from '../types/direct-api';
import {
  mapCompletionSignature,
  invalidCloudApiResponse,
  mapModelAttestation,
} from './cloud-api';

/** Decode the provider's flattened root report and its complete report array. */
export function decodeDirectAttestationReport(
  value: unknown,
): DirectAttestationReport {
  const parsed = v.safeParse(DirectApiAttestationReportSchema, value);
  if (!parsed.success) {
    throw invalidCloudApiResponse({
      issue: parsed.issues[0],
      fallbackPath: 'direct attestation report',
    });
  }
  const response = parsed.output;
  const root = mapDirectAttestation(response, 'attestation');
  const attestations = response.all_attestations.map((attestation, index) =>
    mapDirectAttestation(attestation, `all_attestations[${index}]`),
  );
  const serializedRoot = JSON.stringify(root);
  // Reuse identical root evidence, but do not collapse array entries based on
  // signer or instance: either can be shared by distinct reports.
  const attestation =
    attestations.find(
      (candidate) => JSON.stringify(candidate) === serializedRoot,
    ) ?? root;
  return {
    attestation,
    attestations,
    ...(response.compose_manager_attestation === undefined
      ? {}
      : { composeManagerAttestation: response.compose_manager_attestation }),
  };
}

/** This endpoint's signatures are provider_tee, independent of signed text. */
export function decodeDirectCompletionSignature(
  value: unknown,
): CompletionSignature {
  const parsed = v.safeParse(DirectApiCompletionSignatureResultSchema, value);
  if (!parsed.success) {
    throw invalidCloudApiResponse({
      issue: parsed.issues[0],
      fallbackPath: 'signature',
    });
  }
  return mapCompletionSignature(
    'error_code' in parsed.output
      ? parsed.output
      : { ...parsed.output, signature_kind: 'provider_tee' },
  );
}

function mapDirectAttestation(
  attestation: DirectApiModelAttestation,
  label: string,
): DirectModelAttestation {
  return {
    ...mapModelAttestation(attestation, label),
    modelName: attestation.model_name,
    ...(attestation.info.instance_id === undefined
      ? {}
      : { instanceId: attestation.info.instance_id }),
    ...(attestation.tls_cert_fingerprint === undefined
      ? {}
      : { spkiFingerprint: attestation.tls_cert_fingerprint }),
  };
}
