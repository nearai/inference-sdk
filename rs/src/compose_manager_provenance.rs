const MAX_COMPOSE_FILE_BYTES: usize = 8 * 1024 * 1024;

use crate::deployment_provenance::{
    pinned_digest, verify_compose_image_provenance, verify_required_image_provenance,
};
use crate::{
    ImageProvenanceFetchOptions, ImageProvenancePolicy, MeasuredDeployment, VerificationError,
};
use std::collections::BTreeMap;

/// File selection and GitHub access for Compose Manager image provenance.
#[derive(Clone)]
pub struct ComposeManagerDeploymentImageProvenanceOptions<'a> {
    pub compose_repository: &'a str,
    /// Select the latest compose_up for this path, or the latest compose_up overall.
    pub compose_file: Option<&'a str>,
    pub github_proxy_url: Option<&'a str>,
    pub github_token: Option<&'a str>,
    pub image_signer_identities: Option<&'a BTreeMap<String, String>>,
}

impl Default for ComposeManagerDeploymentImageProvenanceOptions<'_> {
    fn default() -> Self {
        Self {
            compose_repository: "nearai/cvm-compose-files",
            compose_file: None,
            github_token: None,
            github_proxy_url: None,
            image_signer_identities: None,
        }
    }
}

/// Independent build policy for the latest manager-start image.
#[derive(Clone)]
pub struct ComposeManagerImagePolicy {
    pub image_repository: String,
    pub build: ImageProvenancePolicy,
    pub signer_identity: Option<String>,
}

/// Check recorded compose bytes and required image builds after model verification.
/// This proves deployment intent authenticated by Compose Manager, not action
/// success or the currently running software. Unlisted images are not approved.
pub async fn verify_compose_manager_deployment_image_provenance(
    deployment: &MeasuredDeployment,
    image_policies: &BTreeMap<String, ImageProvenancePolicy>,
    compose_manager_image_policy: &ComposeManagerImagePolicy,
    options: ComposeManagerDeploymentImageProvenanceOptions<'_>,
) -> Result<(), VerificationError> {
    if image_policies.is_empty() {
        return Err(VerificationError::DeploymentImagesInvalid {
            reason: crate::DeploymentImagesFailureReason::EmptyPolicy,
            image_repository: None,
            service: None,
        });
    }
    let manager = deployment
        .compose_manager
        .as_ref()
        .ok_or_else(|| invalid("attestation_missing"))?;
    let action = manager
        .actions
        .iter()
        .rev()
        .find(|action| {
            action.action == "compose_up"
                && options
                    .compose_file
                    .is_none_or(|file| action.file.as_deref() == Some(file))
        })
        .ok_or_else(|| invalid("compose_up_missing"))?;
    let manager_image = manager
        .actions
        .iter()
        .rev()
        .find(|a| a.action == "compose_manager_started")
        .and_then(|a| a.image.as_deref())
        .ok_or_else(|| invalid("manager_image_missing"))?;
    let manager_repository = compose_manager_image_policy
        .image_repository
        .strip_prefix("docker.io/")
        .unwrap_or(&compose_manager_image_policy.image_repository);
    let normalized = manager_image
        .strip_prefix("docker.io/")
        .unwrap_or(manager_image);
    if manager_repository.is_empty()
        || !(normalized.starts_with(&format!("{manager_repository}@"))
            || normalized.starts_with(&format!("{manager_repository}:")))
    {
        return Err(invalid("manager_image_mismatch"));
    }
    let manager_digest = pinned_digest(&normalized[manager_repository.len()..])
        .ok_or_else(|| VerificationError::DeploymentImagesInvalid {
            reason: crate::DeploymentImagesFailureReason::ImageNotPinned,
            image_repository: Some(manager_repository.to_owned()),
            service: Some("compose-manager".to_owned()),
        })?
        .to_ascii_lowercase();
    let (Some(commit), Some(file), Some(digest)) =
        (&action.commit, &action.file, &action.file_sha256)
    else {
        return Err(invalid("invalid_file_reference"));
    };
    let repository = options.compose_repository;
    if !is_hex(commit, 40)
        || !is_hex(digest, 64)
        || file.split('/').any(|part| matches!(part, "" | "." | ".."))
        || repository.split('/').count() != 2
        || repository.split('/').any(|part| {
            matches!(part, "" | "." | "..")
                || !part
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'))
        })
    {
        return Err(invalid("invalid_file_reference"));
    }
    if let Some(identities) = options.image_signer_identities {
        for name in identities.keys() {
            if !image_policies.contains_key(name) {
                return Err(VerificationError::InvalidInput {
                    field: "image_signer_identities".into(),
                    reason: format!("{name:?} must be an exact key from image_policies"),
                });
            }
        }
    }
    let request_error = |status: Option<u16>| VerificationError::ComposeFileRequestFailed {
        repository: repository.to_owned(),
        commit: commit.clone(),
        file: file.clone(),
        status,
        retryable: status.is_none_or(|status| status == 429 || status >= 500),
    };
    let mut url = crate::provenance::github_api_base(options.github_proxy_url)
        .map_err(|_| invalid("invalid_file_reference"))?;
    url.path_segments_mut()
        .expect("HTTPS URL supports path segments")
        .pop_if_empty()
        .extend(["repos"])
        .extend(repository.split('/'))
        .push("contents")
        .extend(file.split('/'));
    url.query_pairs_mut().append_pair("ref", commit);
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| request_error(None))?;
    let mut request = client
        .get(url)
        .header("Accept", "application/vnd.github.raw+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .header("User-Agent", "nearai-inference-sdk");
    if options.github_proxy_url.is_none() {
        if let Some(token) = options.github_token {
            request = request.bearer_auth(token);
        }
    }
    let mut response = request.send().await.map_err(|_| request_error(None))?;
    if !response.status().is_success() {
        return Err(request_error(Some(response.status().as_u16())));
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_COMPOSE_FILE_BYTES as u64)
    {
        return Err(invalid("compose_file_too_large"));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| request_error(None))? {
        if chunk.len() > MAX_COMPOSE_FILE_BYTES - bytes.len() {
            return Err(invalid("compose_file_too_large"));
        }
        bytes.extend_from_slice(&chunk);
    }
    let expected_hash = hex::decode(digest).map_err(|_| invalid("invalid_file_reference"))?;
    if crate::util::sha256(&bytes) != expected_hash {
        return Err(VerificationError::ComposeFileHashMismatch {
            repository: repository.to_owned(),
            commit: commit.clone(),
            file: file.clone(),
        });
    }
    let compose =
        std::str::from_utf8(&bytes).map_err(|_| VerificationError::DeploymentImagesInvalid {
            reason: crate::DeploymentImagesFailureReason::InvalidDockerCompose,
            image_repository: None,
            service: None,
        })?;
    verify_compose_image_provenance(
        compose,
        image_policies,
        options.image_signer_identities,
        options.github_token,
        action.services.as_deref(),
        options.github_proxy_url,
    )
    .await?;
    verify_required_image_provenance(
        manager_repository,
        &manager_digest,
        &compose_manager_image_policy.build,
        compose_manager_image_policy.signer_identity.as_deref(),
        ImageProvenanceFetchOptions {
            github_token: options.github_token,
            github_proxy_url: options.github_proxy_url,
        },
    )
    .await
}

fn invalid(reason: &'static str) -> VerificationError {
    VerificationError::ComposeManagerDeploymentInvalid { reason }
}

fn is_hex(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|c| c.is_ascii_hexdigit())
}
