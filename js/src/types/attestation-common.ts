/** Algorithms emitted by NEAR AI attestation and signature endpoints. */
export type SigningAlgo = 'ecdsa' | 'ed25519';

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonObject | JsonValue[];
export type JsonObject = { [key: string]: JsonValue };

/**
 * dstack exposes this value either as an object or as JSON encoded in a
 * string. `app_compose` itself is intentionally kept as its original string:
 * its exact UTF-8 bytes are measured in MRCONFIGID.
 */
export type TcbInfo = JsonObject & {
  app_compose: string;
};

/**
 * Decoded Cloud API wire data common to NEAR dstack gateway and model reports.
 * Parsing this shape only validates JSON types; none of its fields is trusted
 * until a verification function has authenticated the Intel quote and its
 * bindings.
 */
export type DstackAttestation = {
  request_nonce: string;
  signing_algo: SigningAlgo;
  signing_address: string;
  intel_quote: string;
  event_log: JsonValue;
  info: {
    tcb_info: string | TcbInfo;
  };
  /**
   * SHA-256 SPKI fingerprint supplied by the report when requested. For a
   * model report it is a server declaration; only gateway verification can
   * compare it with a client-observed TLS peer.
   */
  tls_cert_fingerprint?: string | null;
  /** Present for signing schemes that expose a separate public key. */
  signing_public_key?: string | null;
  /**
   * Optional JSON copy of the Intel quote's report data. The verifier only
   * cross-checks it against the authenticated quote; it is not a trust root.
   */
  report_data?: string;
};
