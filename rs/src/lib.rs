//! Verification primitives for NEAR AI Cloud attestations and completion
//! signatures.
//!
//! The public API deliberately separates three operations:
//! - fetch raw evidence from NEAR AI Cloud;
//! - verify a model or Gateway deployment; and
//! - verify an exact completion response against verified evidence.

mod attestation;
mod bindings;
mod cloud_api;
mod errors;
mod event_log;
mod gateway;
mod model;
mod nvidia;
mod provenance;
mod quote;
mod response;
mod types;
mod util;

pub use cloud_api::{
    find_model_attestation_for_signature, AttestationClient, DEFAULT_NEAR_AI_CLOUD_BASE_URL,
    NO_ALIASING_HEADER,
};
pub use errors::{ApiError, ApiResource, ApiTransportReason, VerificationError};
pub use gateway::verify_gateway_attestation;
pub use model::verify_model_attestation;
pub use nvidia::{NrasNvidiaEvidenceVerifier, DEFAULT_NVIDIA_NRAS_URL};
pub use provenance::{fetch_image_provenance, verify_image_provenance};
pub use quote::{verify_dcap_quote, DcapQuoteVerifier, DEFAULT_INTEL_PCCS_URL};
pub use response::{verify_gateway_response, verify_model_response};
pub use types::*;
