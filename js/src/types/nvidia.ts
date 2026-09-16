import type * as v from 'valibot';
import type {
  NrasOverallAttestationJwtClaimsSchema,
  NvidiaJwksSchema,
} from '../schemas';

export type NvidiaJwks = v.InferOutput<typeof NvidiaJwksSchema>;

export type NrasOverallAttestationJwtClaims = v.InferOutput<
  typeof NrasOverallAttestationJwtClaimsSchema
>;
