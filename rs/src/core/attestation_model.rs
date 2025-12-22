use crate::core::attestation_common::{
    get_compose_from_tcb_info, verify_compose,
    verify_intel_quote_report_data_for_attestation_report,
};
use crate::types::attestation_model::ModelAttestation;
use crate::utils::errors::Error;
use crate::utils::intel::fetch_intel_tdx_verification_data;
use crate::utils::nvidia::fetch_nvidia_gpu_verification_data;

pub async fn verify_model_attestation(attestation: &ModelAttestation) -> Result<(), Error> {
    let intel_tdx_verification_data =
        fetch_intel_tdx_verification_data(&attestation.intel_quote).await?;

    verify_intel_tdx_for_model(
        &intel_tdx_verification_data,
        &attestation.request_nonce,
        &attestation.signing_address,
    )?;

    let nvidia_gpu_verification_data =
        fetch_nvidia_gpu_verification_data(&attestation.nvidia_payload).await?;

    verify_nvidia_gpu_for_model(&nvidia_gpu_verification_data)?;

    let compose = get_compose_from_tcb_info(&attestation.info.tcb_info)?;
    verify_compose(&compose).await?;

    Ok(())
}

fn verify_intel_tdx_for_model(
    verification_data: &crate::types::intel::IntelTdxVerificationData,
    request_nonce: &str,
    signing_address: &str,
) -> Result<(), Error> {
    if !verification_data.quote.verified {
        return Err(Error::verification(format!(
            "Intel quote not verified: quote.verified=false (request_nonce={}, signing_address={})",
            request_nonce, signing_address
        )));
    }

    verify_intel_quote_report_data_for_attestation_report(
        &verification_data.quote.body.reportdata,
        request_nonce,
        signing_address,
    )
}

fn verify_nvidia_gpu_for_model(
    verification_data: &crate::types::nvidia::NvidiaGpuVerificationData,
) -> Result<(), Error> {
    if !verification_data.jwt.x_nvidia_overall_att_result {
        return Err(Error::verification(
            "NVIDIA GPU not verified: x-nvidia-overall-att-result=false".to_owned(),
        ));
    }

    Ok(())
}
