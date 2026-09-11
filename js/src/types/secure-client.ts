import type OpenAI from 'openai';
import type * as v from 'valibot';
import type { ChatCompletionRequestSchema } from '../schemas';
import type { AttestationClientOptions } from './cloud-api';
import type { Awaitable } from './shared';
import type {
  AttestationPolicy,
  AttestationVerifiers,
  DeploymentProvenanceStatus,
  MeasuredDeployment,
  ModelAttestationPolicy,
  ModelAttestationVerifiers,
  VerifiedGatewayAttestation,
  VerifiedModelAttestation,
} from './verification';

/** Parsed JSON used to identify a Chat Completions request. */
export type ChatCompletionRequest = v.InferOutput<
  typeof ChatCompletionRequestSchema
>;

/** JSON object preserved by the secure Chat transport. */
export type SecureChatJsonObject = Record<string, unknown>;

/** Parsed JSON accepted by the E2EE Chat Completions path. */
export type SecureChatCompletionRequest = ChatCompletionRequest &
  SecureChatJsonObject;

/** Parsed JSON returned by the secure Chat Completions path. */
export type SecureChatCompletionResponse = SecureChatJsonObject;

/** Parsed JSON in one secure Chat Completions SSE event. */
export type SecureChatCompletionStreamChunk = SecureChatJsonObject;

/** Application policy for the authenticated measurements of one model deployment. */
export type DeploymentPolicy = (
  params: DeploymentPolicyParams,
) => Awaitable<void>;

export type DeploymentPolicyParams = {
  readonly model: string;
  readonly deployment: MeasuredDeployment;
};

/** Advanced verification settings for Gateway evidence used by `SecureClient`. */
export type GatewayVerificationOptions = {
  readonly policy?: AttestationPolicy;
  readonly verifiers?: AttestationVerifiers;
};

/** Advanced verification settings for model evidence used by `SecureClient`. */
export type ModelVerificationOptions = {
  readonly policy?: ModelAttestationPolicy;
  readonly verifiers?: ModelAttestationVerifiers;
};

/** Configuration for verified Chat Completions for one canonical model. */
export type SecureClientOptions = AttestationClientOptions & {
  /** Canonical model ID that this client verifies before sending requests. */
  readonly model: string;
  /**
   * Encrypt supported Chat fields directly to the verified model key.
   * Defaults to `true`. Setting this to `false` keeps the fresh attestation
   * and deployment-policy checks, but sends plaintext Chat fields with a
   * verified Ed25519 model-key routing header.
   */
  readonly e2ee?: boolean;
  /**
   * Optional caller-owned allowlist for authenticated model measurements.
   * Without it or a model deployment verifier, `verify()` returns
   * `modelDeploymentProvenance: 'not_checked'`.
   */
  readonly deploymentPolicy?: DeploymentPolicy;
  readonly gatewayVerification?: GatewayVerificationOptions;
  readonly modelVerification?: ModelVerificationOptions;
};

/** Result of a successful `SecureClient.verify()` call. */
export type VerifiedSecureSession = {
  readonly model: string;
  readonly gatewayAttestation: VerifiedGatewayAttestation;
  readonly modelAttestations: readonly VerifiedModelAttestation[];
  /**
   * Verified model Ed25519 key used for E2EE or plaintext model routing.
   */
  readonly modelSigningPublicKey: string;
  /** Whether every model candidate passed a deployment verifier or policy. */
  readonly modelDeploymentProvenance: DeploymentProvenanceStatus;
};

/** Options accepted by the OpenAI-compatible `NearAiSecureClient`. */
export type NearAiSecureClientOptions = SecureClientOptions;

/** The supported OpenAI-compatible chat surface. */
export type SecureChat = {
  readonly completions: SecureChatCompletions;
};

/** Chat Completions create overloads supported by `NearAiSecureClient`. */
export type SecureChatCompletions = Pick<OpenAI.Chat.Completions, 'create'>;
