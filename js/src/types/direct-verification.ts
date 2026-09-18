import type {
  DirectAttestationReport,
  DirectClientBinding,
  DirectModelAttestation,
} from './direct-api';
import type {
  GatewayTlsBinding,
  ModelAttestationPolicy,
  ModelAttestationVerifiers,
  ModelClientBinding,
  VerifiedModelAttestation,
} from './verification';

export type VerifyDirectModelAttestationParams = {
  readonly attestation: DirectModelAttestation;
  readonly clientBinding: ModelClientBinding;
  readonly policy?: ModelAttestationPolicy;
  readonly verifiers?: ModelAttestationVerifiers;
};

/** One model report, independently verified without observing its TLS peer. */
export type VerifiedDirectModelAttestation = VerifiedModelAttestation & {
  /** Report metadata, not a model-name claim authenticated by the quote. */
  readonly modelName: string;
  /** Report metadata identifying the instance, when supplied by the endpoint. */
  readonly instanceId?: string;
  /** Quote-authenticated SPKI fingerprint; not necessarily the observed TLS peer. */
  readonly spkiFingerprint?: string;
};

export type VerifyDirectAttestationReportParams = {
  readonly report: DirectAttestationReport;
  readonly clientBinding: DirectClientBinding;
  readonly policy?: ModelAttestationPolicy;
  readonly verifiers?: ModelAttestationVerifiers;
};

/** TLS identity of the direct endpoint that returned the report. */
export type DirectTlsBinding = GatewayTlsBinding;

/** Every supplied model report passed, plus the serving endpoint's TLS binding. */
export type VerifiedDirectAttestationReport = {
  readonly attestation: VerifiedDirectModelAttestation;
  readonly attestations: readonly VerifiedDirectModelAttestation[];
  /** Only the top-level report is compared with the TLS peer of this request. */
  readonly tlsBinding: DirectTlsBinding;
};
