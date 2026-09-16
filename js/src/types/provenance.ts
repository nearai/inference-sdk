import type * as v from 'valibot';
import type { ImageProvenanceStatementSchema } from '../schemas';

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
