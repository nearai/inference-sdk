//! Quote-authenticated deployment actions. These are not successful/current-state claims.

use crate::attestation::verify_tdx_quote_policy;
use crate::bindings::{
    verify_advertised_report_data, verify_app_compose_mrconfigid_binding, verify_reported_nonce,
};
use crate::event_log::verify_and_replay_rtmr3;
use crate::util::{require_hex_length, sha256};
use crate::{
    AttestationEventLog, AttestationPolicy, RuntimeMeasurements, TcbStatus, TdxQuoteVerifier,
    VerificationError,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Values in Compose Manager's canonical action log; unknown fields remain signed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ComposeManagerActionValue {
    String(String),
    Strings(Vec<String>),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ComposeManagerAction {
    pub action: String,
    pub timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub services: Option<Vec<String>>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, ComposeManagerActionValue>,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct ComposeManagerAttestation {
    pub actions: Vec<ComposeManagerAction>,
    pub actions_hash: String,
    pub nonce: String,
    #[serde(rename = "quote")]
    pub intel_quote: String,
    pub event_log: AttestationEventLog,
    #[serde(rename = "report_data")]
    pub reported_quote_data: Option<String>,
}

/// Actions authenticated under the same measured configuration as a model report.
/// Matching configuration does not establish a unique CVM identity or action success.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedComposeManagerAttestation {
    pub actions: Vec<ComposeManagerAction>,
    pub tcb_status: TcbStatus,
    pub advisory_ids: Vec<String>,
    pub runtime_measurements: RuntimeMeasurements,
}

pub(crate) async fn verify_compose_manager_attestation(
    attestation: &ComposeManagerAttestation,
    app_compose: &str,
    nonce: &str,
    policy: Option<&AttestationPolicy>,
    verifier: Option<&dyn TdxQuoteVerifier>,
) -> Result<VerifiedComposeManagerAttestation, VerificationError> {
    verify_reported_nonce(&attestation.nonce, nonce, "compose_manager_attestation")?;
    let quote = verify_tdx_quote_policy(&attestation.intel_quote, policy, verifier).await?;
    verify_advertised_report_data(
        attestation.reported_quote_data.as_deref(),
        &quote.report_data,
    )?;
    crate::bindings::verify_quote_report_data_nonce(&quote.report_data, nonce)?;
    // BTreeMap makes key ordering explicit even if serde_json enables preserve_order.
    let actions: Vec<BTreeMap<String, serde_json::Value>> = attestation
        .actions
        .iter()
        .map(|action| serde_json::to_value(action).and_then(serde_json::from_value))
        .collect::<Result<_, _>>()
        .map_err(|_| VerificationError::ComposeManagerActionsMismatch)?;
    let canonical = serde_json::to_vec(&actions)
        .map_err(|_| VerificationError::ComposeManagerActionsMismatch)?;
    let hash = sha256(&canonical);
    let reported_hash = require_hex_length(&attestation.actions_hash, 32)
        .map_err(|_| VerificationError::ComposeManagerActionsMismatch)?;
    if hash.as_slice() != reported_hash || quote.report_data[..32] != hash {
        return Err(VerificationError::ComposeManagerActionsMismatch);
    }
    verify_app_compose_mrconfigid_binding(app_compose, &quote.mr_config_id)?;
    let runtime_measurements = verify_and_replay_rtmr3(&attestation.event_log, &quote.rt_mr3)?;
    Ok(VerifiedComposeManagerAttestation {
        actions: attestation.actions.clone(),
        tcb_status: quote.tcb_status,
        advisory_ids: quote.advisory_ids,
        runtime_measurements,
    })
}
