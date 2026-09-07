import type * as v from 'valibot';
import type {
  NrasOverallAttestationJwtClaimsSchema,
  NrasResponseSchema,
} from '../schemas';

export type NrasResponse = v.InferOutput<typeof NrasResponseSchema>;

export type NrasOverallAttestationJwtClaims = v.InferOutput<
  typeof NrasOverallAttestationJwtClaimsSchema
>;
