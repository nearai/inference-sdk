import type { Buffer } from 'buffer';
import type { SigningIdentity } from './attestation-common';
import type {
  MeasuredDeployment,
  QuoteVerificationResult,
  TcbStatus,
  VerifyGatewayResponseFields,
  VerifyModelResponseFields,
} from '../schemas';

export type {
  AttestationPolicy,
  AttestationVerifiers,
  Awaitable,
  DeploymentVerifier,
  MeasuredDeployment,
  ModelAttestationPolicy,
  ModelAttestationVerifiers,
  NvidiaEvidenceVerifier,
  QuoteVerificationResult,
  QuoteVerifier,
  RuntimeMeasurements,
  TcbStatus,
  VerifyGatewayAttestationInput,
  VerifyModelAttestationInput,
} from '../schemas';

declare const verifiedModelAttestationBrand: unique symbol;
declare const verifiedGatewayAttestationBrand: unique symbol;

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
  /** The declared fingerprint matched the client-observed peer. */
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

/**
 * Immutable in-memory result of `verifyModelAttestation`. Pass this exact
 * object to `verifyModelResponse`; re-verify raw evidence after a process or
 * serialization boundary.
 */
export type VerifiedModelAttestation = VerifiedAttestationEvidence & {
  readonly [verifiedModelAttestationBrand]: true;
  readonly tlsBinding: ModelTlsBinding;
  /** A supplied NVIDIA payload was verified, or the CVM did not provide one. */
  readonly gpuEvidence: GpuEvidenceStatus;
};

/**
 * Immutable in-memory result of `verifyGatewayAttestation`. Pass this exact
 * object to `verifyGatewayResponse`; re-verify raw evidence after a process
 * or serialization boundary.
 */
export type VerifiedGatewayAttestation = VerifiedAttestationEvidence & {
  readonly [verifiedGatewayAttestationBrand]: true;
  /** The quote-bound fingerprint matched the completion's observed TLS peer. */
  readonly tlsBinding: GatewayTlsBinding;
};

export type VerifyModelResponseInput = Omit<
  VerifyModelResponseFields,
  'attestation'
> & {
  /** Model evidence whose verified signer must match `signature`. */
  attestation: VerifiedModelAttestation;
};

export type VerifyGatewayResponseInput = Omit<
  VerifyGatewayResponseFields,
  'attestation'
> & {
  /** Gateway evidence whose verified signer must match `signature`. */
  attestation: VerifiedGatewayAttestation;
};
