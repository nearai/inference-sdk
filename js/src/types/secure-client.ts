import type OpenAI from 'openai';
import type { Stream } from 'openai/streaming';
import type * as v from 'valibot';
import type { ChatCompletionRequestSchema } from '../schemas';
import type { AttestationClientOptions } from './cloud-api';
import type { CompletionSignature } from './chat';
import type { Awaitable } from './shared';
import type {
  AttestationPolicy,
  AttestationVerifiers,
  MeasuredDeployment,
  ModelAttestationPolicy,
  ModelAttestationVerifiers,
  VerifiedGatewayAttestation,
  VerifiedModelAttestation,
} from './verification';

type OpenAiChatCompletionCreateParamsBase = Parameters<
  OpenAI.Chat.Completions['create']
>[0];

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

/** Configuration for verified Chat Completions. */
export type SecureClientOptions = AttestationClientOptions & {
  /**
   * Encrypt supported Chat fields directly to the verified model key.
   * Defaults to `true`. Setting this to `false` keeps the fresh attestation
   * and deployment-policy checks, but sends plaintext Chat fields with a
   * verified Ed25519 model-key routing header.
   */
  readonly e2ee?: boolean;
  /**
   * Optional caller-owned allowlist for authenticated model measurements.
   * It receives the model named by each Chat request.
   */
  readonly deploymentPolicy?: DeploymentPolicy;
  readonly gatewayVerification?: GatewayVerificationOptions;
  readonly modelVerification?: ModelVerificationOptions;
};

/** Options accepted by the OpenAI-compatible `NearAiSecureClient`. */
export type NearAiSecureClientOptions = SecureClientOptions;

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

/** Exact bytes and a deferred verification operation for one Chat response. */
export type CompletionReceipt = {
  /** Exact request bytes sent to the Gateway. These are ciphertext when E2EE is enabled. */
  readonly requestBody: Uint8Array;
  /** Resolves to the exact Gateway response bytes before E2EE decryption. */
  readonly responseBody: Promise<Uint8Array>;
  /** Wait for the full response, then fetch and verify its completion signature. */
  verify(): Promise<VerifiedCompletionReceipt>;
};

/** Native Fetch response with byte-exact response evidence. */
export type SecureFetchWithReceipt = {
  readonly response: Response;
  readonly receipt: CompletionReceipt;
};

/** Non-streaming OpenAI Chat result with byte-exact response evidence. */
export type SecureChatCompletionWithReceipt = {
  readonly completion: OpenAI.ChatCompletion;
  readonly receipt: CompletionReceipt;
};

/** Streaming OpenAI Chat result with byte-exact response evidence. */
export type SecureChatCompletionStreamWithReceipt = {
  readonly stream: Stream<OpenAI.ChatCompletionChunk>;
  readonly receipt: CompletionReceipt;
};

/** The supported OpenAI-compatible chat surface. */
export type SecureChat = {
  readonly completions: SecureChatCompletions;
};

/** Chat Completions operations supported by `NearAiSecureClient`. */
export type SecureChatCompletions = Pick<OpenAI.Chat.Completions, 'create'> & {
  createWithReceipt(
    body: OpenAI.ChatCompletionCreateParamsNonStreaming,
    options?: OpenAI.RequestOptions,
  ): Promise<SecureChatCompletionWithReceipt>;
  createWithReceipt(
    body: OpenAI.ChatCompletionCreateParamsStreaming,
    options?: OpenAI.RequestOptions,
  ): Promise<SecureChatCompletionStreamWithReceipt>;
  createWithReceipt(
    body: OpenAiChatCompletionCreateParamsBase,
    options?: OpenAI.RequestOptions,
  ): Promise<
    SecureChatCompletionWithReceipt | SecureChatCompletionStreamWithReceipt
  >;
};
