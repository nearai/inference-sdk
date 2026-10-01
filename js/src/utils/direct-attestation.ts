import type { DirectModelAttestation } from '../types/direct-api';

/** Match the full report, not its object reference or a shared signing identity. */
export function findDirectModelAttestationIndex(
  attestations: readonly DirectModelAttestation[],
  servingAttestation: DirectModelAttestation,
): number {
  const serializedServingAttestation = serializeAttestation(servingAttestation);
  return attestations.findIndex(
    (candidate) =>
      serializeAttestation(candidate) === serializedServingAttestation,
  );
}

// Object key order is not evidence. Preserve array order and string contents.
function serializeAttestation(attestation: DirectModelAttestation): string {
  // Compose Manager is envelope metadata added to the serving model report;
  // it is not part of the individual report in all_attestations.
  const { composeManagerAttestation: _manager, ...modelReport } = attestation;
  return JSON.stringify(modelReport, (_key, value: unknown) => {
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
