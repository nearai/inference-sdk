import type { SigningIdentity } from '../types/attestation-common';
import type {
  VerifiedGatewayAttestation,
  VerifiedModelAttestation,
} from '../types/verification';
import { inputError } from '../utils/input';

// A verified result is also an in-memory capability. Keeping the authenticated
// signer outside the public object prevents a fabricated or later-mutated
// structural value from being accepted by response verification.
const modelSigners = new WeakMap<object, SigningIdentity>();
const gatewaySigners = new WeakMap<object, SigningIdentity>();

type Unbranded<T> = {
  [Key in keyof T as Key extends symbol ? never : Key]: T[Key];
};

type UnbrandedVerifiedAttestation =
  | Unbranded<VerifiedModelAttestation>
  | Unbranded<VerifiedGatewayAttestation>;

export function markVerifiedModelAttestation(
  attestation: Unbranded<VerifiedModelAttestation>,
): VerifiedModelAttestation {
  const verified = freezeVerifiedAttestation(
    attestation,
  ) as VerifiedModelAttestation;
  modelSigners.set(verified, copySigner(verified.signer));
  return verified;
}

export function markVerifiedGatewayAttestation(
  attestation: Unbranded<VerifiedGatewayAttestation>,
): VerifiedGatewayAttestation {
  const verified = freezeVerifiedAttestation(
    attestation,
  ) as VerifiedGatewayAttestation;
  gatewaySigners.set(verified, copySigner(verified.signer));
  return verified;
}

export function requireVerifiedModelSigner(value: unknown): SigningIdentity {
  return requireVerifiedSigner(
    modelSigners,
    value,
    'a result returned by verifyModelAttestation',
  );
}

export function requireVerifiedGatewaySigner(value: unknown): SigningIdentity {
  return requireVerifiedSigner(
    gatewaySigners,
    value,
    'a result returned by verifyGatewayAttestation',
  );
}

function requireVerifiedSigner(
  signers: WeakMap<object, SigningIdentity>,
  value: unknown,
  expected: string,
): SigningIdentity {
  if (!value || typeof value !== 'object') {
    throw inputError('attestation', 'unverified_attestation', { expected });
  }
  const signer = signers.get(value);
  if (!signer) {
    throw inputError('attestation', 'unverified_attestation', { expected });
  }
  return copySigner(signer);
}

function copySigner(signer: SigningIdentity): SigningIdentity {
  return Object.freeze({
    algorithm: signer.algorithm,
    address: signer.address,
  });
}

function freezeVerifiedAttestation<T extends UnbrandedVerifiedAttestation>(
  attestation: T,
): T {
  return Object.freeze({
    ...attestation,
    signer: copySigner(attestation.signer),
    advisoryIds: Object.freeze([...attestation.advisoryIds]),
    deployment: Object.freeze({
      ...attestation.deployment,
      runtimeMeasurements: Object.freeze({
        ...attestation.deployment.runtimeMeasurements,
      }),
    }),
    tlsBinding: Object.freeze({ ...attestation.tlsBinding }),
  }) as T;
}
