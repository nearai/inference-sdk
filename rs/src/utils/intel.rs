use crate::types::intel::IntelTdxVerificationData;
use crate::utils::common::hex_to_bytes;
use crate::utils::consts::INTEL_PCCS_API_URL;
use crate::utils::errors::VerificationError;
use dcap_qvl::collateral::get_collateral;
use dcap_qvl::verify::verify;
use std::time::{SystemTime, UNIX_EPOCH};

pub async fn fetch_intel_tdx_verification_data(
    quote: &str,
) -> Result<IntelTdxVerificationData, VerificationError> {
    let quote_raw = hex_to_bytes(quote)?;

    let collateral = get_collateral(INTEL_PCCS_API_URL, &quote_raw)
        .await
        .map_err(|e| VerificationError::new(format!("Failed to get collateral: {}", e)))?;

    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let verification_data_raw = verify(&quote_raw, &collateral, current_time)
        .map_err(|e| VerificationError::new(format!("Failed to verify Intel quote: {}", e)))?;

    let td10 = verification_data_raw
        .report
        .as_td10()
        .ok_or_else(|| VerificationError::new("Bad report data".to_string()))?;

    let verified = matches!(verification_data_raw.status, dcap_qvl::verify::VerificationStatus::UpToDate);
    let report_data = td10.report_data();
    let mr_config = td10.mr_config_id();

    Ok(IntelTdxVerificationData {
        quote: crate::types::intel::IntelQuote {
            verified,
            body: crate::types::intel::IntelQuoteBody {
                reportdata: format!("0x{}", hex::encode(report_data)),
                mrconfig: format!("0x{}", hex::encode(mr_config)),
            },
        },
    })
}

