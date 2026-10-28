use crate::{
    DeploymentProvenanceStatus, DeploymentVerifier, MeasuredDeployment, VerificationError,
};

pub(crate) async fn run_deployment_verifier(
    deployment: &MeasuredDeployment,
    verifier: Option<&dyn DeploymentVerifier>,
) -> Result<DeploymentProvenanceStatus, VerificationError> {
    if let Some(verifier) = verifier {
        verifier.verify(deployment).await?;
        Ok(DeploymentProvenanceStatus::Verified)
    } else {
        Ok(DeploymentProvenanceStatus::NotChecked)
    }
}
