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

/** Fields common to NEAR dstack gateway and model reports. */
export type DstackAttestation = {
  request_nonce: string;
  signing_algo: SigningAlgo;
  signing_address: string;
  intel_quote: string;
  event_log: JsonValue;
  info: {
    tcb_info: string | TcbInfo;
  };
  /** SHA-256 of the serving TLS certificate SPKI when requested. */
  tls_cert_fingerprint?: string | null;
  /** Present for signing schemes that expose a separate public key. */
  signing_public_key?: string | null;
  /** Optional JSON copy of quote report_data; compare it when present. */
  report_data?: string;
};
