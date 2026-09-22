import type {
  DirectModelAttestation,
  FetchedDirectModelAttestations,
} from './direct-api';
import type {
  GatewayTlsBinding,
  ModelAttestationPolicy,
  ModelAttestationVerifiers,
  ModelClientBinding,
  VerifiedNearModelAttestation,
} from './verification';

export type VerifyDirectModelAttestationParams = {
  readonly attestation: DirectModelAttestation;
  readonly clientBinding: ModelClientBinding;
  readonly policy?: ModelAttestationPolicy;
  readonly verifiers?: ModelAttestationVerifiers;
};

/** One model attestation, independently verified without observing its TLS peer. */
export type VerifiedDirectModelAttestation = VerifiedNearModelAttestation & {
  /** Metadata, not a model-name claim authenticated by the quote. */
  readonly modelName: string;
  /** Instance metadata, when supplied by the endpoint. */
  readonly instanceId?: string;
  /** Quote-authenticated SPKI fingerprint; not necessarily the observed TLS peer. */
  readonly spkiFingerprint?: string;
};

export type VerifyDirectModelAttestationsParams =
  FetchedDirectModelAttestations & {
    readonly policy?: ModelAttestationPolicy;
    readonly verifiers?: ModelAttestationVerifiers;
  };

/** TLS identity of the direct endpoint that returned the attestation. */
export type DirectTlsBinding = GatewayTlsBinding;

/** Every supplied model attestation passed, plus the serving endpoint's TLS binding. */
export type VerifiedDirectModelAttestations = {
  /** The verified serving entry from the complete attestation set. */
  readonly servingAttestation: VerifiedDirectModelAttestation;
  readonly attestations: readonly VerifiedDirectModelAttestation[];
  /** Only the serving attestation is compared with the TLS peer of this request. */
  readonly tlsBinding: DirectTlsBinding;
  /** Quote-authenticated SPKI fingerprints from every returned model attestation. */
  readonly spkiFingerprints: readonly string[];
};
