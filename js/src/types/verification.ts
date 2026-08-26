import type { Buffer } from 'buffer';
import type { GatewayAttestation } from './attestation-gateway';
import type { ModelAttestation } from './attestation-model';
import type { SigningIdentity } from './attestation-common';
import type { CompletionBytes, CompletionSignature } from './chat';

declare const verifiedModelAttestationBrand: unique symbol;
declare const verifiedGatewayAttestationBrand: unique symbol;

/** Intel TDX TCB statuses returned by DCAP verification. */
export type TcbStatus =
  | 'UpToDate'
  | 'SWHardeningNeeded'
  | 'ConfigurationNeeded'
  | 'ConfigurationAndSWHardeningNeeded'
  | 'OutOfDate'
  | 'OutOfDateConfigurationNeeded'
  | 'Revoked'
  | 'Unknown';

/** Measurements an Intel quote verifier derives from an authenticated quote. */
export type QuoteVerificationResult = {
  /** TCB status produced by Intel quote verification. */
  tcbStatus: TcbStatus;
  /** Intel advisory IDs accompanying `tcbStatus`. */
  advisoryIds: string[];
  /** Whether the authenticated quote has debug enabled. */
  debugEnabled: boolean;
  /** Intel-signed 64-byte report-data field. */
  reportData: Uint8Array;
  /** Intel MRCONFIGID measurement. */
  mrConfigId: Uint8Array;
  /** Intel RTMR3 measurement replayed against the dstack event log. */
  rtMr3: Uint8Array;
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

/**
 * Trust boundary for Intel TDX quote verification. An implementation must
 * authenticate the quote and derive every returned measurement from that
 * authenticated quote. Byte fields accept `Uint8Array` and are normalized to
 * `Buffer` inside the SDK. Resolving means the quote is trusted; reject or
 * throw for every other outcome.
 */
export type QuoteVerifier = (quote: string) => Promise<QuoteVerificationResult>;

/**
 * Trust boundary for NVIDIA GPU evidence. Resolve only after the supplied
 * payload satisfies the verifier's complete acceptance policy; reject or
 * throw for malformed, unavailable, or rejected evidence.
 */
export type NvidiaEvidenceVerifier = (payload: string) => Promise<void>;

/** Runtime values extracted while replaying the Intel-verified RTMR3 log. */
export type RuntimeMeasurements = {
  /** Runtime `os-image-hash` event payload, when present. */
  readonly osImageHash?: string;
  /** Runtime `compose-hash` event payload, when present. */
  readonly composeHash?: string;
};

/** Deployment data authenticated by the quote and measured event log. */
export type MeasuredDeployment = {
  /** Original compose text whose UTF-8 bytes were bound to MRCONFIGID. */
  readonly appCompose: string;
  /** Canonical image digests such as `sha256:<64 lowercase hex characters>`. */
  readonly imageDigests: readonly string[];
  /** Measurements extracted while replaying the verified RTMR3 log. */
  readonly runtimeMeasurements: RuntimeMeasurements;
};

/**
 * Caller-defined deployment acceptance policy. Resolve only when the supplied
 * measured deployment is acceptable; reject or throw otherwise.
 */
export type DeploymentVerifier = (
  deployment: MeasuredDeployment,
) => Promise<void>;

/** Policy shared by model and gateway attestation verification. */
export type AttestationPolicy = {
  /** Defaults to `UpToDate` and `OutOfDate`. */
  acceptedTcbStatuses?: readonly TcbStatus[];
};

/** Extra policy available only while verifying model evidence. */
export type ModelAttestationPolicy = AttestationPolicy & {
  /** Require NVIDIA evidence, or verify it when present (the default). */
  gpuEvidence?: 'if-present' | 'required';
};

/** Custom trust roots shared by model and gateway verification. */
export type AttestationVerifiers = {
  /** Uses the built-in Intel DCAP verifier when omitted. */
  quote?: QuoteVerifier;
  /** Supplying this verifier makes deployment acceptance a required check. */
  deployment?: DeploymentVerifier;
};

/** Custom trust roots available only while verifying model evidence. */
export type ModelAttestationVerifiers = AttestationVerifiers & {
  /** Uses NVIDIA NRAS for present evidence when omitted. */
  nvidia?: NvidiaEvidenceVerifier;
};

/** Verify NEAR model evidence returned through the Cloud API. */
export type VerifyModelAttestationInput = {
  attestation: ModelAttestation;
  /**
   * A fresh caller-generated, caller-retained 32-byte hex nonce. It is bound
   * into the verified Intel quote and prevents replay of an older report.
   */
  nonce: string;
  policy?: ModelAttestationPolicy;
  verifiers?: ModelAttestationVerifiers;
};

/** Verify gateway evidence and its binding to a client-observed TLS peer. */
export type VerifyGatewayAttestationInput = {
  attestation: GatewayAttestation;
  /** Fresh caller-generated, caller-retained nonce for this report request. */
  nonce: string;
  policy?: AttestationPolicy;
  verifiers?: AttestationVerifiers;
  /**
   * SHA-256 SPKI fingerprint observed from the same TLS connection used for
   * the report and the client-visible gateway response. Do not copy
   * `attestation.declaredSpkiFingerprint` here: that would only compare the
   * report with itself. Browser `fetch` cannot provide this peer certificate.
   */
  peerSpkiFingerprint: string;
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
  readonly signer: SigningIdentity;
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
  /** The quote-bound fingerprint matched a peer on the caller's TLS socket. */
  readonly tlsBinding: GatewayTlsBinding;
};

export type VerifyModelResponseInput = CompletionBytes & {
  /** Signature for the exact completion bytes. */
  signature: CompletionSignature;
  /** Model evidence whose verified signer must match `signature`. */
  attestation: VerifiedModelAttestation;
};

export type VerifyGatewayResponseInput = CompletionBytes & {
  /** Gateway signature for the exact completion bytes. */
  signature: CompletionSignature;
  /** Gateway evidence whose verified signer must match `signature`. */
  attestation: VerifiedGatewayAttestation;
};
