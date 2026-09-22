import type { Awaitable } from './shared';
import type {
  AttestationPolicy,
  GpuEvidenceVerifier,
  ModelClientBinding,
  TcbStatus,
  TdxQuoteVerifier,
} from './verification';

/** Raw NVIDIA evidence for one GPU; the challenge is derived by the verifier. */
export type ChutesGpuEvidence = {
  readonly certificate: string;
  readonly evidence: string;
  readonly arch: string;
};

/** Chutes evidence returned by the NEAR AI Gateway, not a dstack report. */
export type ChutesModelAttestation = {
  readonly provider: 'chutes';
  readonly nonce: string;
  /** Raw Intel TDX quote, normalized to hexadecimal by the HTTP boundary. */
  readonly intelQuote: string;
  /** Standard base64 DER certificate whose SPKI is bound into report data. */
  readonly certificate: string;
  /** Standard base64 ML-KEM-768 routing key; preserve its exact text. */
  readonly publicKey: string;
  readonly gpuEvidence: readonly ChutesGpuEvidence[];
  readonly instanceId?: string;
};

/** Hexadecimal registers authenticated by the Intel-signed quote. */
export type ChutesMeasurements = {
  readonly mrTd: string;
  readonly rtMr0: string;
  readonly rtMr1: string;
  readonly rtMr2: string;
  readonly rtMr3: string;
};

export type ChutesMeasurementBaseline = ChutesMeasurements & {
  readonly name: string;
  readonly version: string;
};

/** VM baseline identity; this does not attest model weights or a model workload. */
export type ChutesMeasuredDeployment = ChutesMeasurements & {
  readonly baseline: {
    readonly name: string;
    readonly version: string;
  };
};

export type ChutesAttestationPolicy = AttestationPolicy & {
  /**
   * Caller-trusted VM baselines. Defaults to the SDK's pinned snapshot of the
   * Gateway's vetted Chutes baselines. An empty list rejects every deployment.
   */
  readonly baselines?: readonly ChutesMeasurementBaseline[];
};

export type ChutesDeploymentVerifier = (
  deployment: ChutesMeasuredDeployment,
) => Awaitable<void>;

export type ChutesAttestationVerifiers = {
  readonly tdxQuote?: TdxQuoteVerifier;
  readonly gpuEvidence?: GpuEvidenceVerifier;
  /** Additional policy after the authenticated registers match a baseline. */
  readonly deployment?: ChutesDeploymentVerifier;
};

export type VerifyChutesModelAttestationParams = {
  readonly attestation: ChutesModelAttestation;
  readonly clientBinding: ModelClientBinding;
  readonly policy?: ChutesAttestationPolicy;
  readonly verifiers?: ChutesAttestationVerifiers;
};

export type VerifiedChutesModelAttestation = {
  readonly provider: 'chutes';
  readonly tcbStatus: TcbStatus;
  readonly advisoryIds: readonly string[];
  /** Quote-bound routing key, not an Ed25519/ECDSA response-signing key. */
  readonly publicKey: string;
  /** Quote-authenticated certificate SPKI hash; not a live TLS peer check. */
  readonly spkiFingerprint: string;
  readonly gpuEvidence: 'verified';
  readonly deployment: ChutesMeasuredDeployment;
  /** The authenticated registers matched the trusted baseline policy. */
  readonly deploymentProvenance: 'verified';
};
