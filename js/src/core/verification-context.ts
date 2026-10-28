import type {
  CreateVerificationContextParams,
  VerificationContext,
} from '../types/verification-context';
import { IntelCollateralCache } from '../utils/intel-collateral-cache';

// The root and /node entry points are separate bundles. The context must carry
// its own state so callers can pass it between those entry points.
const cacheKey = Symbol.for('@nearai/inference-sdk/verification-context/v1');
type InternalContext = VerificationContext & {
  readonly [cacheKey]: IntelCollateralCache;
};

/** Create once per verification operation; discard after all related checks finish. */
export function createVerificationContext({
  fetch = globalThis.fetch,
}: CreateVerificationContextParams = {}): VerificationContext {
  return Object.freeze({
    [cacheKey]: new IntelCollateralCache(fetch.bind(globalThis)),
  }) as InternalContext;
}

/** Internal access keeps material and pending downloads out of the public context. */
export function collateralCache(
  context: VerificationContext,
): IntelCollateralCache {
  const cache = (context as InternalContext)[cacheKey];
  if (cache === undefined)
    throw new TypeError('Use createVerificationContext()');
  return cache;
}
