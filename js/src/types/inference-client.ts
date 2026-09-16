import type OpenAI from 'openai';
import type * as v from 'valibot';
import type { ChatCompletionRequestSchema } from '../schemas';
import type { AttestationClientOptions } from './cloud-api';
import type { CompletionSignature } from './chat';
import type { Awaitable } from './shared';
import type { SigningAlgo } from './attestation-common';
import type {
  AttestationPolicy,
  AttestationVerifiers,
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

/** Advanced verification settings for Gateway evidence used by `InferenceClient`. */
export type GatewayVerificationOptions = {
  /**
   * The generic client cannot observe an HTTPS peer certificate, so Gateway
   * evidence always uses the no-TLS report-data layout.
   */
  readonly includeSpkiFingerprint?: false;
  readonly policy?: AttestationPolicy;
  readonly verifiers?: AttestationVerifiers;
};

/** Gateway-evidence settings supported by the Node-specific inference client. */
export type NodeGatewayVerificationOptions = Omit<
  GatewayVerificationOptions,
  'includeSpkiFingerprint'
> & {
  /**
   * Request and verify the Gateway TLS SPKI fingerprint. Defaults to `true`.
   * Set this to `false` when the configured endpoint is an aggregator or
   * proxy rather than the attested Gateway.
   */
  readonly includeSpkiFingerprint?: boolean;
};

/** Advanced verification settings for model evidence used by `InferenceClient`. */
export type ModelVerificationOptions = {
  readonly policy?: ModelAttestationPolicy;
  readonly verifiers?: ModelAttestationVerifiers;
};

/** Settings shared by generic and Node verified Chat clients. */
type InferenceClientCommonOptions = {
  /**
   * How long to reuse a successfully verified Gateway/model session for the
   * same model. Defaults to 60 minutes. Set `0` to verify every request.
   */
  readonly attestationCacheTimeToLiveMs?: number;
  /** Retain response verification records for this long after the body finishes. Defaults to 60 minutes. */
  readonly responseCacheTimeToLiveMs?: number;
  /**
   * Encrypt supported Chat fields directly to the verified model key.
   * Defaults to `true`. Setting this to `false` keeps attestation and
   * deployment-policy checks, but sends plaintext Chat fields with a verified
   * model-key routing header.
   */
  readonly e2ee?: boolean;
  /**
   * Signing and E2EE protocol to use for Gateway/model evidence, model-key
   * routing, completion receipts, and optional field encryption. Defaults to
   * `ed25519`.
   */
  readonly signingAlgo?: SigningAlgo;
  /**
   * Optional caller-owned allowlist for authenticated model measurements.
   * It receives the model named by each Chat request.
   * Runs after `modelVerification.verifiers.deployment` when both are supplied.
   */
  readonly deploymentPolicy?: DeploymentPolicy;
  readonly modelVerification?: ModelVerificationOptions;
};

/** Configuration for browser-compatible verified Chat Completions. */
export type InferenceClientOptions = AttestationClientOptions &
  InferenceClientCommonOptions & {
    readonly gatewayVerification?: GatewayVerificationOptions;
  };

/** Options accepted by the Node-specific `InferenceClient`. */
export type NodeInferenceClientOptions = AttestationClientOptions &
  InferenceClientCommonOptions & {
    readonly gatewayVerification?: NodeGatewayVerificationOptions;
  };

/** A completion signature verified against the model evidence used for the request. */
export type VerifiedModelCompletionReceipt = {
  readonly completionId: string;
  readonly signatureKind: 'provider_tee';
  readonly signature: CompletionSignature;
  readonly attestation: VerifiedModelAttestation;
};

/** A completion signature verified against the Gateway evidence used for the request. */
export type VerifiedGatewayCompletionReceipt = {
  readonly completionId: string;
  readonly signatureKind: 'gateway';
  readonly signature: CompletionSignature;
  readonly attestation: VerifiedGatewayAttestation;
};

/** Successful byte-exact response verification. */
export type VerifiedCompletionReceipt =
  | VerifiedModelCompletionReceipt
  | VerifiedGatewayCompletionReceipt;

/** The supported OpenAI-compatible chat surface. */
export type SecureChat = {
  readonly completions: SecureChatCompletions;
};

/** Standard Chat Completions operations. */
export type SecureChatCompletions = Pick<OpenAI.Chat.Completions, 'create'>;
