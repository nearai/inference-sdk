export {
  DEFAULT_NEAR_AI_CLOUD_BASE_URL,
  fetchCompletionSignature,
  fetchModelAttestationForSignature,
  fetchModelAttestations,
  findModelAttestationForSignature,
  lookupCompletionSignature,
  NO_ALIASING_HEADER,
} from './core/cloud-api';
export type {
  FetchCompletionSignatureParams,
  FetchedGatewayAttestation,
  FetchedModelAttestation,
  FetchedModelAttestations,
  FetchGatewayAttestationParams,
  FetchModelAttestationForSignatureParams,
  FetchModelAttestationsParams,
  FindModelAttestationForSignatureParams,
  LookupCompletionSignatureParams,
} from './types/cloud-api';
export type { Awaitable } from './types/shared';

export { verifyModelAttestation } from './core/attestation-model';
export { verifyGatewayAttestation } from './core/attestation-gateway';
export { verifyGatewayResponse, verifyModelResponse } from './core/chat';

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
  CompletionSignatureLookup,
  CompletionSignatureReference,
  SignatureUnavailable,
} from './types/chat';
export type {
  AttestationPolicy,
  AttestationVerifiers,
  DeploymentProvenanceStatus,
  DeploymentVerifier,
  GatewayAttestationPolicy,
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
