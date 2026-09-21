import * as v from 'valibot';
import {
  DirectApiAttestationReportSchema,
  DirectApiCompletionSignatureResultSchema,
} from '../schemas';
import type { CompletionSignature } from '../types/chat';
import type {
  DirectApiModelAttestation,
  DirectModelAttestations,
  DirectModelAttestation,
} from '../types/direct-api';
import {
  mapCompletionSignature,
  invalidCloudApiResponse,
  mapModelAttestation,
  mapOhttpAttestation,
} from './cloud-api';

/** Decode the serving attestation and its complete model-attestation array. */
export function decodeDirectModelAttestations(
  value: unknown,
): DirectModelAttestations {
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
  const serializedRoot = serializeAttestation(root);
  // The top-level report identifies the endpoint that answered this request.
  // The complete serving set must contain that same evidence; do not infer it
  // from a shared signer or instance ID.
  const servingAttestation = attestations.find(
    (candidate) => serializeAttestation(candidate) === serializedRoot,
  );
  if (servingAttestation === undefined) {
    throw invalidCloudApiResponse({
      path: 'all_attestations',
      expected: 'array containing the top-level attestation',
      value: response.all_attestations,
    });
  }
  return {
    servingAttestation,
    attestations,
    ...(response.ohttp_attestation === undefined
      ? {}
      : { ohttpAttestation: mapOhttpAttestation(response.ohttp_attestation) }),
  };
}

// Object key order is not evidence. Preserve array order and string contents.
function serializeAttestation(attestation: DirectModelAttestation): string {
  return JSON.stringify(attestation, (_key, value: unknown) => {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) {
      return value;
    }
    return Object.fromEntries(
      Object.entries(value).sort(([left], [right]) =>
        left < right ? -1 : left > right ? 1 : 0,
      ),
    );
  });
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
