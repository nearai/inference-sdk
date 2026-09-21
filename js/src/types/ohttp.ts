import type * as v from 'valibot';
import type { OhttpAttestationSchema } from '../schemas';
import type { SigningIdentity } from './attestation-common';

/** Wire-format OHTTP proof in Gateway and direct attestation reports. */
export type OhttpAttestationResponse = v.InferOutput<
  typeof OhttpAttestationSchema
>;

/** Signed OHTTP key configuration advertised by an attestation endpoint. */
export type OhttpAttestation = {
  readonly signingAlgo: 'ed25519';
  readonly signingKey: string;
  readonly keyConfig: string;
  readonly signature: string;
};

export type VerifyOhttpKeyConfigParams = {
  readonly ohttpAttestation: OhttpAttestation;
  /** Identity obtained from a successfully verified Gateway or direct model attestation. */
  readonly signer: SigningIdentity;
};

/** Configure OHTTP transport with a previously authenticated key configuration. */
export type CreateOhttpFetchParams = {
  readonly keyConfig: Uint8Array;
  readonly baseUrl: string;
  readonly fetch?: typeof globalThis.fetch;
  /** Additional inner header names to expose on the outer request. Authorization is always forwarded. */
  readonly forwardedHeaders?: readonly string[];
};
