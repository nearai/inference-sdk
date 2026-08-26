export {
  DEFAULT_NEAR_AI_CLOUD_BASE_URL,
  NearAiCloudClient,
  NO_ALIASING_HEADER,
} from './core/cloud-api';
export type {
  FetchCompletionSignatureInput,
  FetchGatewayAttestationInput,
  FetchModelAttestationInput,
  NearAiCloudFetch,
  NearAiCloudClientOptions,
} from './core/cloud-api';

export { verifyModelAttestation } from './core/attestation-model';
export { verifyGatewayAttestation } from './core/attestation-gateway';
export { verifyGatewayResponse, verifyModelResponse } from './core/chat';

export { generateNonce } from './utils/common';

export type {
  AttestationEventLog,
  AttestationEvidence,
  SigningAlgorithm,
  SigningIdentity,
} from './types/attestation-common';
export type { GatewayAttestation } from './types/attestation-gateway';
export type { ModelAttestation } from './types/attestation-model';
export type {
  CompletionBytes,
  CompletionSignature,
  CompletionSignatureKind,
  CompletionSignatureLookup,
  SignatureUnavailable,
} from './types/chat';
export type {
  AttestationPolicy,
  AttestationVerifiers,
  Awaitable,
  DeploymentProvenanceStatus,
  DeploymentVerifier,
  GatewayTlsBinding,
  GpuEvidenceStatus,
  MeasuredDeployment,
  ModelAttestationPolicy,
  ModelAttestationVerifiers,
  ModelTlsBinding,
  NvidiaEvidenceVerifier,
  QuoteVerifier,
  QuoteVerificationResult,
  RuntimeMeasurements,
  TcbStatus,
  VerifiedAttestationEvidence,
  VerifiedGatewayAttestation,
  VerifiedModelAttestation,
  VerifyGatewayAttestationInput,
  VerifyGatewayResponseInput,
  VerifyModelAttestationInput,
  VerifyModelResponseInput,
} from './types/verification';

export {
  ApiError,
  isVerificationError,
  VerificationError,
} from './utils/errors';
export type {
  ApiFailure,
  VerificationErrorCode,
  VerificationFailure,
  VerificationErrorOptions,
  VerificationPhase,
} from './utils/errors';
