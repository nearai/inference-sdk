import type { Buffer } from 'buffer';
import type { GatewayAttestation } from './attestation-gateway';
import type { ModelAttestation } from './attestation-model';
import type { CompletionSignature } from './chat';
import type { SigningIdentity } from './attestation-common';
import type { Awaitable } from './shared';

export type TcbStatus =
  | 'UpToDate'
  | 'SWHardeningNeeded'
  | 'ConfigurationNeeded'
  | 'ConfigurationAndSWHardeningNeeded'
  | 'OutOfDate'
  | 'OutOfDateConfigurationNeeded'
  | 'Revoked'
  | 'Unknown';

export type RuntimeMeasurements = {
  readonly osImageHash?: string;
  readonly composeHash?: string;
};

export type MeasuredDeployment = {
  readonly appCompose: string;
  readonly runtimeMeasurements: RuntimeMeasurements;
};

/** Facts returned by a quote verifier before SDK policy and binding checks. */
export type QuoteVerificationResult = {
  tcbStatus: TcbStatus;
  advisoryIds: readonly string[];
  debugEnabled: boolean;
  reportData: Uint8Array;
  mrConfigId: Uint8Array;
  rtMr3: Uint8Array;
};

export type QuoteVerifier = (
  quote: string,
) => Awaitable<QuoteVerificationResult>;

export type NvidiaEvidenceVerifier = (payload: string) => Awaitable<void>;

export type DeploymentVerifier = (
  deployment: MeasuredDeployment,
) => Awaitable<void>;

export type AttestationPolicy = {
  readonly acceptedTcbStatuses?: readonly TcbStatus[];
};

export type ModelAttestationPolicy = AttestationPolicy & {
  readonly gpuEvidence?: 'if-present' | 'required';
};

export type AttestationVerifiers = {
  readonly quote?: QuoteVerifier;
  readonly deployment?: DeploymentVerifier;
};

export type ModelAttestationVerifiers = AttestationVerifiers & {
  readonly nvidia?: NvidiaEvidenceVerifier;
};

export type VerifyModelAttestationInput = {
  readonly attestation: ModelAttestation;
  readonly nonce: string;
  readonly policy?: ModelAttestationPolicy;
  readonly verifiers?: ModelAttestationVerifiers;
};

export type VerifyGatewayAttestationInput = {
  readonly attestation: GatewayAttestation;
  readonly nonce: string;
  readonly peerSpkiFingerprint: string;
  readonly policy?: AttestationPolicy;
  readonly verifiers?: AttestationVerifiers;
};

/** Measurements extracted from an authenticated quote and normalized to Buffers. */
export type VerifiedTdxQuote = Omit<
  QuoteVerificationResult,
  'reportData' | 'mrConfigId' | 'rtMr3'
> & {
  reportData: Buffer;
  mrConfigId: Buffer;
  rtMr3: Buffer;
};

/** TLS information authenticated for a model report. */
export type ModelTlsBinding =
  | { readonly kind: 'none' }
  | {
      /** This is server-declared evidence, not a client-observed model peer. */
      readonly kind: 'declared';
      readonly spkiFingerprint: string;
    };

/** TLS information authenticated for gateway evidence. */
export type GatewayTlsBinding = {
  /** The declared fingerprint matched the caller-supplied TLS peer. */
  readonly kind: 'peer';
  readonly spkiFingerprint: string;
};

export type GpuEvidenceStatus = 'not_provided' | 'verified';
export type DeploymentProvenanceStatus = 'not_checked' | 'verified';

/** Measurements and identity established by a successful attestation check. */
export type VerifiedAttestationEvidence = {
  /** Verified signer that a later response signature must match. */
  readonly signer: Readonly<SigningIdentity>;
  /** Intel TDX TCB status accepted under the applied policy. */
  readonly tcbStatus: TcbStatus;
  readonly advisoryIds: readonly string[];
  /** Deployment measurements authenticated by MRCONFIGID and RTMR3. */
  readonly deployment: MeasuredDeployment;
  /**
   * `verified` only when a caller-supplied deployment verifier ran and
   * accepted the measured deployment. A failed verifier always throws.
   */
  readonly deploymentProvenance: DeploymentProvenanceStatus;
};

/** Result returned by a successful `verifyModelAttestation` call. */
export type VerifiedModelAttestation = VerifiedAttestationEvidence & {
  readonly tlsBinding: ModelTlsBinding;
  /** A supplied NVIDIA payload was verified, or the CVM did not provide one. */
  readonly gpuEvidence: GpuEvidenceStatus;
};

/** Result returned by a successful `verifyGatewayAttestation` call. */
export type VerifiedGatewayAttestation = VerifiedAttestationEvidence & {
  /** The quote-bound fingerprint matched the caller-supplied TLS peer. */
  readonly tlsBinding: GatewayTlsBinding;
};

export type VerifyModelResponseInput = {
  readonly requestBody: Uint8Array;
  readonly responseBody: Uint8Array;
  readonly signature: CompletionSignature;
  /** Model-attestation result whose signer must match `signature`. */
  readonly attestation: VerifiedModelAttestation;
};

export type VerifyGatewayResponseInput = {
  readonly requestBody: Uint8Array;
  readonly responseBody: Uint8Array;
  readonly signature: CompletionSignature;
  /** Gateway-attestation result whose signer must match `signature`. */
  readonly attestation: VerifiedGatewayAttestation;
};
