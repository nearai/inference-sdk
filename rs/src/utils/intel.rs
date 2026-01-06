use crate::types::intel::{IntelQuote, IntelQuoteBody, IntelTdxVerificationData};
use crate::utils::common::hex_to_bytes;
use crate::utils::consts::INTEL_PCCS_API_URL;
use anyhow::Context;
use dcap_qvl::collateral::get_collateral;
use dcap_qvl::verify::verify;
use std::time::{SystemTime, UNIX_EPOCH};

pub async fn fetch_intel_tdx_verification_data(
    quote: &str,
) -> anyhow::Result<IntelTdxVerificationData> {
    let quote_raw = hex_to_bytes(quote)?;

    let collateral = get_collateral(INTEL_PCCS_API_URL, &quote_raw).await?;

    let current_time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    let verification_data_raw = verify(&quote_raw, &collateral, current_time)?;

    let td10 = verification_data_raw
        .report
        .as_td10()
        .context("bad report data: expected TD10 report structure")?;

    let verified = verification_data_raw.status == "UpToDate";
    let report_data = td10.report_data;
    let mr_config = td10.mr_config_id;

    Ok(IntelTdxVerificationData {
        quote: IntelQuote {
            verified,
            body: IntelQuoteBody {
                reportdata: format!("0x{}", hex::encode(report_data)),
                mrconfig: format!("0x{}", hex::encode(mr_config)),
            },
        },
    })
}
