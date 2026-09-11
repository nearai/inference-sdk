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
  /**
   * The generic client cannot observe an HTTPS peer certificate, so Gateway
   * evidence always uses the no-TLS report-data layout.
   */
  readonly includeSpkiFingerprint?: false;
  readonly policy?: AttestationPolicy;
  readonly verifiers?: AttestationVerifiers;
};

/** Gateway-evidence settings supported by the Node-specific secure client. */
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

/** Advanced verification settings for model evidence used by `SecureClient`. */
export type ModelVerificationOptions = {
  readonly policy?: ModelAttestationPolicy;
  readonly verifiers?: ModelAttestationVerifiers;
};

/** Settings shared by generic and Node verified Chat clients. */
type SecureClientCommonOptions = {
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
  readonly modelVerification?: ModelVerificationOptions;
};

/** Configuration for browser-compatible verified Chat Completions. */
export type SecureClientOptions = AttestationClientOptions &
  SecureClientCommonOptions & {
    readonly gatewayVerification?: GatewayVerificationOptions;
  };

/** Options accepted by the Node-specific `SecureClient`. */
export type NodeSecureClientOptions = AttestationClientOptions &
  SecureClientCommonOptions & {
    readonly gatewayVerification?: NodeGatewayVerificationOptions;
  };

/** Options accepted by the OpenAI-compatible `NearAiSecureClient`. */
export type NearAiSecureClientOptions = SecureClientOptions;

/** Options accepted by the Node-specific `NearAiSecureClient`. */
export type NodeNearAiSecureClientOptions = NodeSecureClientOptions;

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
