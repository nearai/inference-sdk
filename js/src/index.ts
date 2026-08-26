export { NearAiCloudClient, NO_ALIASING_HEADER } from './core/cloud-api';
export type {
  FetchCompletionSignatureInput,
  FetchGatewayAttestationInput,
  FetchNearModelAttestationInput,
  NearAiCloudClientOptions,
} from './core/cloud-api';

export { verifyNearModelAttestation } from './core/attestation-model';
export { verifyGatewayAttestation } from './core/attestation-gateway';
export {
  gatewaySignatureText,
  providerTeeSignatureText,
  requireKnownSignature,
  verifyGatewayResponse,
  verifyProviderTeeResponse,
} from './core/chat';

export { generateNonce } from './utils/common';
export { verifyDcapQuote } from './utils/intel';
export { nvidiaNrasVerifier } from './utils/nvidia';

export type {
  GatewayAttestation,
  NearAiCloudAttestationReport,
  VpcInfo,
} from './types/attestation-gateway';
export type { NearModelAttestation } from './types/attestation-model';
export type {
  DstackAttestation,
  JsonObject,
  JsonValue,
  SigningAlgo,
  TcbInfo,
} from './types/attestation-common';
export type {
  CompletionBytes,
  GatewaySignature,
  KnownChatSignature,
  ProviderTeeSignature,
  SignatureLookup,
  SignatureUnavailable,
  UnknownChatSignature,
} from './types/chat';
export type {
  GpuVerifier,
  NearVerificationPolicy,
  ProvenanceVerifier,
  QuoteVerifier,
  TcbStatus,
  VerifiedDstackAttestation,
  VerifiedGatewayAttestation,
  VerifiedNearModelAttestation,
  VerifiedResponseSignature,
  VerifiedRuntimeMeasurements,
  VerifiedTdxQuote,
  VerifyGatewayAttestationInput,
  VerifyGatewayResponseInput,
  VerifyNearModelAttestationInput,
  VerifyProviderTeeResponseInput,
} from './types/verification';

export { CloudApiError, VerificationError } from './utils/errors';
