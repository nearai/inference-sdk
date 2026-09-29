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
