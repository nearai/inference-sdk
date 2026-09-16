export {
  DEFAULT_NEAR_AI_CLOUD_BASE_URL,
  findModelAttestationForSignature,
  NO_ALIASING_HEADER,
} from './core/cloud-api';
export { SecureClient } from './core/secure-client';
export type {
  AttestationClientOptions,
  FetchCompletionSignatureParams,
  FetchedGatewayAttestation,
  FetchedModelAttestations,
  FetchModelAttestationsParams,
  FindModelAttestationForSignatureParams,
} from './types/cloud-api';
export type {
  DeploymentPolicy,
  DeploymentPolicyParams,
  ModelVerificationOptions,
  SecureChat,
  SecureChatCompletions,
  SecureClientOptions,
  VerifiedCompletionReceipt,
  VerifiedGatewayCompletionReceipt,
  VerifiedModelCompletionReceipt,
} from './types/secure-client';
export type { Awaitable } from './types/shared';

export { verifyModelAttestation } from './core/attestation-model';
export { verifyGatewayAttestation } from './core/attestation-gateway';
export { verifyGatewayResponse, verifyModelResponse } from './core/chat';
export { fetchImageProvenance, verifyImageProvenance } from './core/provenance';
export { verifyDeploymentImageProvenance } from './core/deployment-provenance';
export type {
  DeploymentImagesFailureReason,
  FetchImageProvenanceParams,
  ImageProvenanceFailureReason,
  ImageProvenancePolicy,
  VerifiedImageProvenance,
  VerifyImageProvenanceParams,
  VerifyDeploymentImageProvenanceParams,
} from './types/provenance';

export type {
  AttestationEventLog,
  AttestationEvidence,
  SigningAlgo,
  SigningIdentity,
} from './types/attestation-common';
export type { GatewayAttestation } from './types/attestation-gateway';
export type { ModelAttestation } from './types/attestation-model';
export type {
  CompletionSignature,
  CompletionSignatureKind,
  CompletionSignatureReference,
} from './types/chat';
export type {
  AttestationPolicy,
  AttestationVerifiers,
  DeploymentProvenanceStatus,
  DeploymentVerifier,
  GatewayClientBinding,
  GatewayTlsBinding,
  GpuEvidenceStatus,
  MeasuredDeployment,
  ModelClientBinding,
  ModelAttestationPolicy,
  ModelAttestationVerifiers,
  NvidiaEvidenceVerifier,
  QuoteVerifier,
  QuoteVerificationResult,
  RuntimeMeasurements,
  TcbStatus,
  VerifiedAttestationEvidence,
  VerifiedGatewayAttestation,
  VerifiedModelAttestation,
  VerifyGatewayAttestationParams,
  VerifyGatewayResponseParams,
  VerifyModelAttestationParams,
  VerifyModelResponseParams,
} from './types/verification';

export {
  ApiError,
  isApiError,
  isVerificationError,
  VerificationError,
} from './utils/errors';
export type {
  ApiErrorCode,
  ApiErrorJson,
  ApiFailure,
  SdkErrorOptions,
  VerificationErrorCode,
  VerificationErrorJson,
  VerificationFailure,
} from './utils/errors';
