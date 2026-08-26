import type { Buffer } from 'buffer';
import type { GatewayAttestation } from './attestation-gateway';
import type { NearModelAttestation } from './attestation-model';
import type { SigningAlgo } from './attestation-common';
import type {
  CompletionBytes,
  GatewaySignature,
  ProviderTeeSignature,
} from './chat';

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

/** Measurements extracted from an Intel-verified TDX quote, normalized to Buffers. */
export type VerifiedTdxQuote = {
  /** TCB status produced by Intel quote verification. */
  tcbStatus: TcbStatus;
  /** Intel advisory IDs accompanying `tcbStatus`. */
  advisoryIds: string[];
  /** Whether the authenticated quote has debug enabled. */
  debugEnabled: boolean;
  /** Intel-signed 64-byte report-data field. */
  reportData: Buffer;
  /** Intel MRCONFIGID measurement. */
  mrConfigId: Buffer;
  /** Intel RTMR3 measurement replayed against the dstack event log. */
  rtMr3: Buffer;
};

/**
 * Trust boundary for Intel TDX quote verification. An implementation must
 * authenticate the quote and derive every returned measurement from that
 * authenticated quote. Byte fields in the result are Buffers. Resolving means
 * the quote is trusted; reject or throw for every other outcome.
 */
export type QuoteVerifier = {
  verify(quote: string): Promise<VerifiedTdxQuote>;
};

/**
 * Trust boundary for NVIDIA GPU evidence. Resolve only after the supplied
 * payload satisfies the verifier's complete acceptance policy; reject or
 * throw for malformed, unavailable, or rejected evidence.
 */
export type GpuVerifier = {
  verify(nvidiaPayload: string): Promise<void>;
};

/** Runtime values extracted while replaying the Intel-verified RTMR3 log. */
export type VerifiedRuntimeMeasurements = {
  /** Runtime `os-image-hash` event payload, when present. */
  osImageHash?: string;
  /** Runtime `compose-hash` event payload, when present. */
  composeHash?: string;
};

/**
 * Caller-defined deployment provenance policy. The SDK supplies the measured
 * compose bytes, image digests, and RTMR3 values, but never turns a registry
 * lookup into a provenance verdict. Resolve only when the supplied deployment
 * satisfies the caller's policy; reject or throw otherwise.
 */
export type ProvenanceVerifier = {
  verify(input: {
    appCompose: string;
    imageDigests: string[];
    runtimeMeasurements: VerifiedRuntimeMeasurements;
  }): Promise<void>;
};

export type NearVerificationPolicy = {
  /** Defaults to `UpToDate` and `OutOfDate`. */
  allowedTcbStatuses?: readonly TcbStatus[];
  /** Defaults to false so CPU-only CVMs remain verifiable. */
  requireGpuEvidence?: boolean;
  /**
   * Require a caller-supplied provenance verifier before reporting a successful
   * result. Defaults to false because the SDK has no embedded allowlist for a
   * particular NEAR deployment.
   */
  requireDeploymentProvenance?: boolean;
};

type BaseVerificationInput = {
  /**
   * A fresh caller-generated, caller-retained 32-byte hex nonce. It is bound
   * into the verified Intel quote and prevents replay of an older report.
   */
  expectedNonce: string;
  /** Uses Intel DCAP verification when omitted. */
  quoteVerifier?: QuoteVerifier;
  /** Applies deployment policy after quote and measurement verification. */
  provenanceVerifier?: ProvenanceVerifier;
  /** Narrows the default acceptance policy where required by the caller. */
  policy?: NearVerificationPolicy;
};

/** Verify NEAR model evidence returned through the Cloud API. */
export type VerifyNearModelAttestationInput = BaseVerificationInput & {
  attestation: NearModelAttestation;
  /** Uses NVIDIA NRAS when model GPU evidence is present and this is omitted. */
  gpuVerifier?: GpuVerifier;
};

/** Verify gateway evidence and its binding to a client-observed TLS peer. */
export type VerifyGatewayAttestationInput = BaseVerificationInput & {
  attestation: GatewayAttestation;
  /**
   * SHA-256 SPKI fingerprint observed from the same TLS connection used for
   * the report and the client-visible gateway response. Do not copy
   * `attestation.tls_cert_fingerprint` here: that would only compare the
   * report with itself. Browser `fetch` cannot provide this peer certificate.
   */
  peerTlsCertFingerprint: string;
};

/**
 * How the Intel-signed report data binds the verified signer and nonce. Any
 * fingerprint in a successful result is normalized 32-byte SHA-256 SPKI hex.
 */
export type ReportDataBinding =
  | {
      /** Quote binds the signer and fresh nonce, with no TLS claim. */
      kind: 'signer_nonce';
    }
  | {
      /** Quote additionally binds a TLS fingerprint declared in the report. */
      kind: 'signer_declared_tls_nonce';
      tlsCertFingerprint: string;
    }
  | {
      /**
       * The quote-bound TLS fingerprint matched a fingerprint observed on the
       * same peer connection.
       */
      kind: 'signer_peer_tls_nonce';
      tlsCertFingerprint: string;
    };

/**
 * Report-data layouts a model verifier can return. Neither variant is a
 * client-observed model TLS peer binding.
 */
export type ModelReportDataBinding = Extract<
  ReportDataBinding,
  { kind: 'signer_nonce' | 'signer_declared_tls_nonce' }
>;

/** The only report-data layout a gateway verifier can return. */
export type GatewayReportDataBinding = Extract<
  ReportDataBinding,
  { kind: 'signer_peer_tls_nonce' }
>;

/**
 * Measurements returned after quote, nonce, report-data, RTMR3, and policy
 * checks succeed. This common shape does not on its own claim expected NEAR
 * deployment provenance; see `provenanceVerified`.
 */
export type VerifiedDstackAttestation<
  TReportDataBinding extends ReportDataBinding = ReportDataBinding,
> = {
  /** Verified signer that a later response signature must match. */
  signingAddress: string;
  /** Algorithm used by the verified signer and a later response signature. */
  signingAlgo: SigningAlgo;
  /** The quote report-data layout that was verified for this evidence. */
  reportDataBinding: TReportDataBinding;
  /** Intel TDX TCB status accepted under the applied policy. */
  tcbStatus: TcbStatus;
  advisoryIds: string[];
  /** Original compose string whose UTF-8 bytes were bound to MRCONFIGID. */
  appCompose: string;
  /**
   * Digests syntactically extracted from the verified compose string. They are
   * input to caller provenance policy, not registry or image provenance
   * verdicts from this SDK.
   */
  imageDigests: string[];
  /** Measurements extracted from replay of the verified RTMR3 event log. */
  runtimeMeasurements: VerifiedRuntimeMeasurements;
  /**
   * Whether a caller-supplied deployment provenance policy was applied and
   * satisfied. `false` means no such verifier ran; it is not a rejection.
   */
  provenanceVerified: boolean;
  /**
   * Present only when GPU evidence was supplied and successfully verified;
   * absence is not a `false` GPU verdict.
   */
  gpuVerified?: true;
};

export type VerifiedNearModelAttestation =
  VerifiedDstackAttestation<ModelReportDataBinding> & {
    kind: 'near_model';
  };

export type VerifiedGatewayAttestation =
  VerifiedDstackAttestation<GatewayReportDataBinding> & {
    kind: 'gateway';
  };

export type VerifyProviderTeeResponseInput = CompletionBytes & {
  /**
   * Must be the `provider_tee` signature for the exact completion bytes. The
   * request body must be UTF-8 JSON with a non-empty top-level `model` field.
   */
  signature: ProviderTeeSignature;
  /** Model evidence whose verified signer must match `signature`. */
  verifiedModelAttestation: VerifiedNearModelAttestation;
};

export type VerifyGatewayResponseInput = CompletionBytes & {
  /** Must be the `gateway` signature for the exact completion bytes. */
  signature: GatewaySignature;
  /** Gateway evidence whose verified signer must match `signature`. */
  verifiedGatewayAttestation: VerifiedGatewayAttestation;
};

/** Scope of a successfully verified response signature. */
export type VerifiedResponseSignature = {
  /** `model_tee` identifies model-serving evidence; `gateway` does not. */
  scope: 'model_tee' | 'gateway';
  signingAddress: string;
  signingAlgo: SigningAlgo;
};
