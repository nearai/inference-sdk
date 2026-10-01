import type * as v from 'valibot';
import type { ComposeManagerActionSchema } from '../schemas';
import type { AttestationEventLog } from './attestation-common';
import type {
  MeasuredDeployment,
  RuntimeMeasurements,
  TcbStatus,
} from './verification';
import type { ImageProvenancePolicy } from './provenance';

/** Signed action fields retain their wire names for canonical JSON hashing. */
export type ComposeManagerAction = v.InferOutput<
  typeof ComposeManagerActionSchema
>;

/** Deployment-control evidence, separate from the model signer's quote. */
export type ComposeManagerAttestation = {
  readonly actions: readonly ComposeManagerAction[];
  readonly actionsHash: string;
  readonly nonce: string;
  readonly intelQuote: string;
  readonly eventLog: AttestationEventLog;
  readonly reportedQuoteData?: string;
};

/**
 * Quote-authenticated actions under the same measured appCompose configuration.
 * This does not establish a unique CVM identity or successful/current execution.
 */
export type VerifiedComposeManagerAttestation = {
  readonly actions: readonly ComposeManagerAction[];
  readonly tcbStatus: TcbStatus;
  readonly advisoryIds: readonly string[];
  readonly runtimeMeasurements: RuntimeMeasurements;
};

export type VerifyComposeManagerDeploymentImageProvenanceParams = {
  /** Deployment returned by model verification, or supplied to its callback. */
  readonly deployment: MeasuredDeployment;
  /** Required repositories in the deployment file or latest manager-start action. */
  readonly imagePolicies: Readonly<Record<string, ImageProvenancePolicy>>;
  /** Defaults to nearai/cvm-compose-files. */
  readonly composeRepository?: string;
  /** Select the latest compose_up for this path; otherwise use the latest compose_up. */
  readonly composeFile?: string;
  /** Optional GitHub token, never a Gateway API key. */
  readonly githubToken?: string;
};

export type ComposeManagerDeploymentFailureReason =
  | 'attestation_missing'
  | 'compose_up_missing'
  | 'invalid_file_reference';
