export {
  DEFAULT_NEAR_AI_CLOUD_BASE_URL,
  findModelAttestationForSignature,
  NO_ALIASING_HEADER,
} from './core/cloud-api';
export { InferenceClient } from './core/inference-client';
export {
  DirectInferenceClient,
  verifyDirectModelResponse,
} from './core/direct-inference-client';
export {
  verifyDirectModelAttestation,
  verifyDirectModelAttestations,
} from './core/attestation-direct';
export type {
  DirectAttestationClientOptions,
  DirectClientBinding,
  DirectModelAttestation,
  DirectModelAttestations,
  FetchedDirectModelAttestations,
} from './types/direct-api';
export type {
  VerifiedDirectModelAttestation,
  VerifiedDirectModelAttestations,
  DirectTlsBinding,
  VerifyDirectModelAttestationParams,
  VerifyDirectModelAttestationsParams,
} from './types/direct-verification';
export type {
  DirectInferenceClientOptions,
  DirectModelVerificationOptions,
  VerifiedDirectCompletionResult,
  VerifyDirectModelResponseParams,
} from './types/direct-inference-client';
export { prepareE2eeChatRequest } from './core/e2ee-request';
export { verifyOhttpKeyConfig } from './core/ohttp-attestation';
export { createOhttpFetch } from './core/ohttp-fetch';
export type {
  CreateOhttpFetchParams,
  OhttpAttestation,
  VerifyOhttpKeyConfigParams,
} from './types/ohttp';
export type {
  E2eeModelKey,
  PrepareE2eeChatRequestParams,
  PreparedE2eeChatRequest,
} from './types/e2ee';
export type {
  AttestationClientOptions,
  FetchCompletionSignatureParams,
  FetchedGatewayAttestation,
  FetchedModelAttestations,
  FetchModelAttestationsParams,
  FindModelAttestationForSignatureParams,
  ModelMetadata,
} from './types/cloud-api';
export type {
  DeploymentPolicy,
  DeploymentPolicyParams,
  ModelVerificationOptions,
  InferenceChat,
  InferenceChatCompletions,
  InferenceClientOptions,
  VerifiedCompletionResult,
  VerifiedGatewayCompletionResult,
  VerifiedModelCompletionResult,
} from './types/inference-client';
export type { Awaitable } from './types/shared';

export { verifyModelAttestation } from './core/attestation-model';
export { verifyGatewayAttestation } from './core/attestation-gateway';
export { createTdxQuoteVerifier } from './utils/intel';
export { createGpuEvidenceVerifier } from './utils/nvidia';
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
  CreateTdxQuoteVerifierParams,
  CreateGpuEvidenceVerifierParams,
  DeploymentProvenanceStatus,
  DeploymentVerifier,
  GatewayClientBinding,
  GatewayTlsBinding,
  GpuEvidenceStatus,
  GpuEvidenceVerifier,
  MeasuredDeployment,
  ModelClientBinding,
  ModelAttestationPolicy,
  ModelAttestationVerifiers,
  TdxQuoteVerifier,
  TdxQuoteVerificationResult,
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
