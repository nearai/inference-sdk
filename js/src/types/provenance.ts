import type * as v from 'valibot';
import type {
  DeploymentAppComposeSchema,
  DeploymentDockerComposeSchema,
  ImageProvenanceStatementSchema,
} from '../schemas';

/** Caller-owned GitHub Actions build identity and optional version approval. */
export type ImageProvenancePolicy = {
  readonly repository: string;
  readonly workflow: string;
  readonly ref?: string;
  readonly commit?: string;
  /** Defaults to GitHub Actions' OIDC issuer. */
  readonly issuer?: string;
};

export type FetchImageProvenanceParams = {
  readonly repository: string;
  /** Image manifest digest, including the `sha256:` prefix. */
  readonly digest: string;
  /** Optional GitHub token. Never use a gateway API key here. */
  readonly githubToken?: string;
};

export type VerifyImageProvenanceParams = {
  /** Serialized Sigstore bundles, as returned by fetchImageProvenance. */
  readonly bundles: readonly string[];
  readonly digest: string;
  readonly policy: ImageProvenancePolicy;
};

export type VerifyDeploymentImageProvenanceParams = {
  /** JSON appCompose from a measurement-bound deployment. */
  readonly appCompose: string;
  /** Required container image repositories mapped to trusted GitHub builds. */
  readonly imagePolicies: Readonly<Record<string, ImageProvenancePolicy>>;
  /** Optional GitHub token, not a gateway API key. */
  readonly githubToken?: string;
};

export type DeploymentImagesFailureReason =
  | 'empty_policy'
  | 'invalid_app_compose'
  | 'invalid_docker_compose'
  | 'unresolved_image'
  | 'image_missing'
  | 'image_not_pinned';

export type DeploymentAppCompose = v.InferOutput<
  typeof DeploymentAppComposeSchema
>;

export type DeploymentDockerCompose = v.InferOutput<
  typeof DeploymentDockerComposeSchema
>;

export type VerifiedImageProvenance = {
  readonly digest: string;
  readonly repository: string;
  readonly workflow: string;
  readonly ref: string;
  readonly commit: string;
  readonly certificateIdentity: string;
  readonly issuer: string;
  readonly predicateType: string;
};

export type ImageProvenanceFailureReason =
  | 'no_attestations'
  | 'invalid_bundle'
  | 'untrusted_identity'
  | 'invalid_statement'
  | 'digest_mismatch'
  | 'source_mismatch'
  | 'commit_mismatch'
  | 'trust_root_unavailable';

export type ImageProvenanceStatement = v.InferOutput<
  typeof ImageProvenanceStatementSchema
>;
