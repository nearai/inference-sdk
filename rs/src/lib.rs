pub mod core;
pub mod types;
pub mod utils;

pub use core::attestation_domain::verify_domain_attestation;
pub use core::attestation_gateway::verify_gateway_attestation;
pub use core::attestation_model::verify_model_attestation;
pub use core::chat::{verify_chat, verify_signing_address};

pub use types::attestation_common::SigningAlgo;
pub use types::attestation_domain::DomainAttestation;
pub use types::attestation_gateway::{GatewayAttestation, GatewayAttestationReport};
pub use types::attestation_model::{ModelAttestation, ModelAttestationReport};
pub use types::chat::{Chat, ChatSignature};

pub use utils::errors::Error;
