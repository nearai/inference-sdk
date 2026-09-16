use crate::errors::{ApiError, ApiResource, ApiTransportReason, VerificationError};
use crate::types::{
    ImageProvenanceFailureReason as Reason, ImageProvenancePolicy, VerifiedImageProvenance,
};
use reqwest::{header::HeaderMap, Client, Url};
use serde::Deserialize;
use sigstore_verify::{
    trust_root::{TrustedRoot, SIGSTORE_PRODUCTION_TRUSTED_ROOT},
    types::{Bundle, Sha256Hash, SignatureContent},
    VerificationPolicy, Verifier,
};
use std::collections::HashSet;

const RESOURCE: ApiResource = ApiResource::ImageProvenance;
const SLSA_V1: &str = "https://slsa.dev/provenance/v1";
const SLSA_V02: &str = "https://slsa.dev/provenance/v0.2";

/// Fetch inline GitHub attestation bundles for a `sha256:…` image digest.
///
/// This only retrieves evidence. Call [`verify_image_provenance`] before using
/// its contents. The optional token is a GitHub token, not a Gateway API key.
pub async fn fetch_image_provenance(
    repository: &str,
    digest: &str,
    github_token: Option<&str>,
) -> Result<Vec<String>, ApiError> {
    if !valid_repository(repository) {
        return Err(api_input("repository", "expected owner/repo"));
    }
    let hash = image_hash(digest).ok_or_else(|| {
        api_input(
            "digest",
            "expected sha256: followed by 64 hexadecimal digits",
        )
    })?;
    let url = Url::parse(&format!(
        "https://api.github.com/repos/{repository}/attestations/sha256:{hash}?per_page=100"
    ))
    .expect("validated repository and digest form a valid GitHub URL");
    fetch_image_provenance_pages(&Client::new(), url, github_token).await
}

async fn fetch_image_provenance_pages(
    client: &Client,
    original_url: Url,
    github_token: Option<&str>,
) -> Result<Vec<String>, ApiError> {
    let mut bundles = Vec::new();
    let mut url = original_url.clone();
    let mut visited = HashSet::new();
    loop {
        if !visited.insert(url.clone()) {
            return Err(pagination_error("repeated pagination cursor"));
        }
        let mut request = client
            .get(url.clone())
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("User-Agent", "verifiable-ai-sdk");
        if let Some(token) = github_token {
            request = request.bearer_auth(token);
        }
        let response = request.send().await.map_err(|_| ApiError::Transport {
            resource: RESOURCE,
            reason: ApiTransportReason::Request,
        })?;
        if !response.status().is_success() {
            return Err(ApiError::HttpStatus {
                resource: RESOURCE,
                status: response.status().as_u16(),
            });
        }
        let next = next_attestation_page(&original_url, response.headers())?;
        let text = response.text().await.map_err(|_| ApiError::Transport {
            resource: RESOURCE,
            reason: ApiTransportReason::ResponseBody,
        })?;
        let response: GitHubAttestations = serde_json::from_str(&text).map_err(|error| {
            if error.is_syntax() || error.is_eof() {
                ApiError::InvalidJson { resource: RESOURCE }
            } else {
                ApiError::InvalidResponse {
                    path: "attestations".to_owned(),
                    expected: "an array of inline bundle objects".to_owned(),
                    actual: "invalid attestation response".to_owned(),
                }
            }
        })?;
        bundles.extend(
            response
                .attestations
                .into_iter()
                .map(|entry| serde_json::Value::Object(entry.bundle).to_string()),
        );
        let Some(next) = next else {
            return Ok(bundles);
        };
        url = next;
    }
}

fn next_attestation_page(original_url: &Url, headers: &HeaderMap) -> Result<Option<Url>, ApiError> {
    for header in headers.get_all(reqwest::header::LINK) {
        let header = header
            .to_str()
            .map_err(|_| pagination_error("invalid Link header"))?;
        for link in header.split(',') {
            let mut parts = link.trim().split(';');
            let target = parts.next().unwrap_or_default().trim();
            let is_next = parts.any(|part| {
                part.trim().split_once('=').is_some_and(|(name, value)| {
                    name.trim().eq_ignore_ascii_case("rel")
                        && value
                            .trim()
                            .trim_matches('"')
                            .split_whitespace()
                            .any(|relation| relation == "next")
                })
            });
            if !is_next {
                continue;
            }
            let target = target
                .strip_prefix('<')
                .and_then(|target| target.strip_suffix('>'))
                .and_then(|target| Url::parse(target).ok())
                .filter(|target| matches!(target.scheme(), "http" | "https"))
                .ok_or_else(|| pagination_error("invalid next link URL"))?;
            let mut cursors = target
                .query_pairs()
                .filter(|(name, _)| name == "before" || name == "after");
            let (name, value) = cursors
                .next()
                .filter(|(_, value)| !value.is_empty())
                .ok_or_else(|| pagination_error("missing next link cursor"))?;
            if cursors.next().is_some() {
                return Err(pagination_error("multiple next link cursors"));
            }
            // Retain the caller's validated GitHub origin and attestation path;
            // only the cursor is taken from the server-supplied URL.
            let mut url = original_url.clone();
            url.set_query(None);
            url.query_pairs_mut()
                .append_pair("per_page", "100")
                .append_pair(&name, &value);
            return Ok(Some(url));
        }
    }
    Ok(None)
}

fn pagination_error(actual: &str) -> ApiError {
    ApiError::InvalidResponse {
        path: "Link".to_owned(),
        expected: "a next link with a new before or after cursor".to_owned(),
        actual: actual.to_owned(),
    }
}

/// Verify one matching GitHub build provenance from a collection of bundles.
///
/// The Sigstore library verifies the DSSE signature, Fulcio certificate, SCT,
/// Rekor inclusion proof/checkpoint and artifact digest using its embedded
/// public-good trust root. This function additionally checks the caller's
/// source repository, workflow, optional ref and commit against signed data.
/// It does not discover images, approve a deployment or rebuild the artifact.
pub async fn verify_image_provenance(
    bundles: &[String],
    digest: &str,
    policy: &ImageProvenancePolicy,
) -> Result<VerifiedImageProvenance, VerificationError> {
    let hash = image_hash(digest).ok_or_else(|| VerificationError::InvalidInput {
        field: "digest".to_owned(),
        reason: "expected sha256: followed by 64 hexadecimal digits".to_owned(),
    })?;
    let normalized_digest = format!("sha256:{hash}");
    let root = TrustedRoot::from_json(SIGSTORE_PRODUCTION_TRUSTED_ROOT)
        .map_err(|_| provenance_error(&normalized_digest, vec![Reason::TrustRootUnavailable]))?;
    let verifier = Verifier::new(&root);
    let mut reasons = Vec::new();
    for bundle in bundles {
        match verify_bundle(bundle, &hash, policy, &verifier) {
            Ok(result) => return Ok(result),
            Err(reason) if !reasons.contains(&reason) => reasons.push(reason),
            Err(_) => {}
        }
    }
    if reasons.is_empty() {
        reasons.push(Reason::NoAttestations);
    }
    Err(provenance_error(&normalized_digest, reasons))
}

fn verify_bundle(
    json: &str,
    hash: &str,
    policy: &ImageProvenancePolicy,
    verifier: &Verifier,
) -> Result<VerifiedImageProvenance, Reason> {
    let bundle = Bundle::from_json(json).map_err(|_| Reason::InvalidBundle)?;
    let SignatureContent::DsseEnvelope(envelope) = &bundle.content else {
        return Err(Reason::InvalidStatement);
    };
    // Sigstore bundles use one signature. In particular, the signature verified
    // by DSSE must be the same one authenticated by the transparency log.
    if envelope.signatures.len() != 1 {
        return Err(Reason::InvalidBundle);
    }
    if envelope.payload_type != "application/vnd.in-toto+json" {
        return Err(Reason::InvalidStatement);
    }
    let statement: Statement = serde_json::from_slice(envelope.payload.as_bytes())
        .map_err(|_| Reason::InvalidStatement)?;
    if !matches!(
        statement.statement_type.as_str(),
        "https://in-toto.io/Statement/v1" | "https://in-toto.io/Statement/v0.1"
    ) {
        return Err(Reason::InvalidStatement);
    }
    // This preliminary comparison only rejects a candidate. No statement is
    // trusted or returned until the cryptographic verifier below succeeds.
    if !statement.subject.iter().any(|subject| {
        subject
            .digest
            .sha256
            .as_deref()
            .is_some_and(|value| value.eq_ignore_ascii_case(hash))
    }) {
        return Err(Reason::DigestMismatch);
    }
    let artifact = Sha256Hash::from_hex(hash).map_err(|_| Reason::DigestMismatch)?;
    let verified = verifier
        .verify(artifact, &bundle, &VerificationPolicy::default())
        .map_err(|_| Reason::InvalidBundle)?;
    let identity = verified.identity.ok_or(Reason::UntrustedIdentity)?;
    let issuer = verified.issuer.ok_or(Reason::UntrustedIdentity)?;
    let identity_prefix = format!(
        "https://github.com/{}/{}@",
        policy.repository, policy.workflow
    );
    let git_ref = identity
        .strip_prefix(&identity_prefix)
        .filter(|value| value.starts_with("refs/"))
        .ok_or(Reason::UntrustedIdentity)?;
    if issuer != policy.issuer
        || policy
            .git_ref
            .as_deref()
            .is_some_and(|expected| expected != git_ref)
    {
        return Err(Reason::UntrustedIdentity);
    }
    let (commit, predicate_type) = source_commit(statement.provenance, policy, git_ref)?;
    if policy
        .commit
        .as_deref()
        .is_some_and(|expected| !expected.eq_ignore_ascii_case(&commit))
    {
        return Err(Reason::CommitMismatch);
    }
    Ok(VerifiedImageProvenance {
        digest: format!("sha256:{hash}"),
        repository: policy.repository.clone(),
        workflow: policy.workflow.clone(),
        git_ref: git_ref.to_owned(),
        commit,
        certificate_identity: identity,
        issuer,
        predicate_type: predicate_type.to_owned(),
    })
}

fn source_commit(
    provenance: Provenance,
    policy: &ImageProvenancePolicy,
    git_ref: &str,
) -> Result<(String, &'static str), Reason> {
    match provenance {
        Provenance::V1(predicate) => {
            let definition = predicate.build_definition;
            let workflow = definition.external_parameters.workflow;
            let expected_repository = format!("https://github.com/{}", policy.repository);
            if workflow
                .repository
                .strip_suffix(".git")
                .unwrap_or(&workflow.repository)
                != expected_repository
                || workflow.path != policy.workflow
                || workflow.git_ref != git_ref
            {
                return Err(Reason::SourceMismatch);
            }
            let commit = definition
                .resolved_dependencies
                .iter()
                .find(|material| require_source(&material.uri, policy, git_ref).is_ok())
                .and_then(|material| material.digest.git_commit.as_deref())
                .filter(|commit| is_commit(commit))
                .ok_or(Reason::SourceMismatch)?
                .to_ascii_lowercase();
            Ok((commit, SLSA_V1))
        }
        Provenance::V02(predicate) => {
            let source = predicate.invocation.config_source;
            if source.entry_point != policy.workflow {
                return Err(Reason::SourceMismatch);
            }
            require_source(&source.uri, policy, git_ref)?;
            let commit = source
                .digest
                .sha1
                .filter(|commit| is_commit(commit))
                .ok_or(Reason::SourceMismatch)?
                .to_ascii_lowercase();
            Ok((commit, SLSA_V02))
        }
    }
}

fn require_source(uri: &str, policy: &ImageProvenancePolicy, git_ref: &str) -> Result<(), Reason> {
    let (repository, reference) = github_source(uri).ok_or(Reason::SourceMismatch)?;
    if repository != policy.repository || reference != Some(git_ref) {
        return Err(Reason::SourceMismatch);
    }
    Ok(())
}

fn github_source(uri: &str) -> Option<(&str, Option<&str>)> {
    let uri = uri.strip_prefix("git+").unwrap_or(uri);
    let path = uri.strip_prefix("https://github.com/")?;
    let (repository, reference) = path
        .split_once('@')
        .map_or((path, None), |(repo, reference)| (repo, Some(reference)));
    Some((
        repository.strip_suffix(".git").unwrap_or(repository),
        reference,
    ))
}

fn is_commit(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn image_hash(digest: &str) -> Option<String> {
    let value = digest.strip_prefix("sha256:")?;
    (value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| value.to_ascii_lowercase())
}

fn valid_repository(repository: &str) -> bool {
    let Some((owner, repo)) = repository.split_once('/') else {
        return false;
    };
    [owner, repo].into_iter().all(|part| {
        !part.is_empty()
            && part != "."
            && part != ".."
            && part
                .bytes()
                .all(|value| value.is_ascii_alphanumeric() || b"-_.".contains(&value))
    })
}

fn api_input(field: &str, reason: &str) -> ApiError {
    ApiError::InvalidInput {
        field: field.to_owned(),
        reason: reason.to_owned(),
        expected: None,
        actual: None,
    }
}

fn provenance_error(digest: &str, reasons: Vec<Reason>) -> VerificationError {
    VerificationError::ImageProvenanceVerificationFailed {
        digest: digest.to_owned(),
        reasons,
    }
}

#[derive(Deserialize)]
struct GitHubAttestations {
    attestations: Vec<GitHubAttestation>,
}

#[derive(Deserialize)]
struct GitHubAttestation {
    bundle: serde_json::Map<String, serde_json::Value>,
}

#[derive(Deserialize)]
struct Statement {
    #[serde(rename = "_type")]
    statement_type: String,
    subject: Vec<Subject>,
    #[serde(flatten)]
    provenance: Provenance,
}

#[derive(Deserialize)]
struct Subject {
    digest: SubjectDigest,
}

#[derive(Deserialize)]
struct SubjectDigest {
    sha256: Option<String>,
}

#[derive(Deserialize)]
#[serde(tag = "predicateType", content = "predicate")]
enum Provenance {
    #[serde(rename = "https://slsa.dev/provenance/v1")]
    V1(PredicateV1),
    #[serde(rename = "https://slsa.dev/provenance/v0.2")]
    V02(PredicateV02),
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PredicateV1 {
    build_definition: BuildDefinition,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BuildDefinition {
    external_parameters: ExternalParameters,
    resolved_dependencies: Vec<Material>,
}

#[derive(Deserialize)]
struct ExternalParameters {
    workflow: Workflow,
}

#[derive(Deserialize)]
struct Workflow {
    repository: String,
    path: String,
    #[serde(rename = "ref")]
    git_ref: String,
}

#[derive(Deserialize)]
struct PredicateV02 {
    invocation: Invocation,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Invocation {
    config_source: ConfigSource,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConfigSource {
    uri: String,
    #[serde(default)]
    digest: SourceDigest,
    entry_point: String,
}

#[derive(Deserialize)]
struct Material {
    uri: String,
    #[serde(default)]
    digest: SourceDigest,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SourceDigest {
    git_commit: Option<String>,
    sha1: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::{
        matchers::{header, method, path, query_param, query_param_is_missing},
        Mock, MockServer, ResponseTemplate,
    };

    const COMMIT: &str = "8e07c3583909c9ab9da94d883e87add1ae90832d";

    fn policy() -> ImageProvenancePolicy {
        ImageProvenancePolicy::new(
            "nearai/compose-manager".to_owned(),
            ".github/workflows/build.yml".to_owned(),
        )
    }

    #[tokio::test]
    async fn fetches_cursor_pages_at_the_original_origin_and_path() {
        for cursor_name in ["before", "after"] {
            let server = MockServer::start().await;
            let endpoint_path = "/repos/nearai/compose-manager/attestations/sha256:abc";
            let initial =
                Url::parse(&format!("{}{endpoint_path}?per_page=100", server.uri())).unwrap();
            let next_link = format!(
                "<https://example.com/untrusted?per_page=1&page=2&{cursor_name}=a%2B%2F%3D%26>; rel=\"next\""
            );
            Mock::given(method("GET"))
                .and(path(endpoint_path))
                .and(query_param("per_page", "100"))
                .and(query_param_is_missing(cursor_name))
                .and(header("Authorization", "Bearer test-token"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .insert_header("Link", next_link)
                        .set_body_json(json!({"attestations": [{"bundle": {"page": 1}}]})),
                )
                .expect(1)
                .mount(&server)
                .await;
            let final_bundles = (0..100)
                .map(|index| json!({"index": index}))
                .collect::<Vec<_>>();
            Mock::given(method("GET"))
                .and(path(endpoint_path))
                .and(query_param("per_page", "100"))
                .and(query_param(cursor_name, "a+/=&"))
                .and(header("Authorization", "Bearer test-token"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "attestations": final_bundles.iter().map(|bundle| json!({"bundle": bundle})).collect::<Vec<_>>()
                })))
                .expect(1)
                .mount(&server)
                .await;

            let bundles =
                fetch_image_provenance_pages(&Client::new(), initial.clone(), Some("test-token"))
                    .await
                    .unwrap();

            let mut expected = vec![json!({"page": 1}).to_string()];
            expected.extend(final_bundles.iter().map(ToString::to_string));
            assert_eq!(bundles, expected);
            let requests = server.received_requests().await.unwrap();
            assert_eq!(requests.len(), 2);
            assert!(requests
                .iter()
                .all(|request| request.url.path() == endpoint_path));
            assert_eq!(requests[0].url.query(), Some("per_page=100"));
            assert_eq!(
                requests[1].url.query().unwrap(),
                format!("per_page=100&{cursor_name}=a%2B%2F%3D%26")
            );
        }
    }

    #[tokio::test]
    async fn rejects_repeated_pagination_before_repeating_a_request() {
        let server = MockServer::start().await;
        let initial = Url::parse(&format!("{}/attestations?per_page=100", server.uri())).unwrap();
        let next_link = format!("<{}&after=repeated>; rel=\"next\"", initial);
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Link", next_link)
                    .set_body_json(json!({"attestations": [{"bundle": {}}]})),
            )
            .expect(2)
            .up_to_n_times(2)
            .mount(&server)
            .await;

        let result = fetch_image_provenance_pages(&Client::new(), initial, None).await;

        assert!(matches!(result, Err(ApiError::InvalidResponse { path, .. }) if path == "Link"));
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }

    #[test]
    fn rejects_malformed_or_missing_next_cursors() {
        let initial = Url::parse("https://api.github.com/attestations?per_page=100").unwrap();
        for link in [
            "<not-a-url>; rel=\"next\"",
            "<https://api.github.com/attestations?per_page=100>; rel=\"next\"",
            "<https://api.github.com/attestations?after=>; rel=\"next\"",
            "<https://api.github.com/attestations?after=a&before=b>; rel=\"next\"",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(reqwest::header::LINK, link.parse().unwrap());
            assert!(matches!(
                next_attestation_page(&initial, &headers),
                Err(ApiError::InvalidResponse { path, .. }) if path == "Link"
            ));
        }
        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::LINK,
            "<https://api.github.com/attestations?before=a>; rel=\"prev\""
                .parse()
                .unwrap(),
        );
        assert_eq!(next_attestation_page(&initial, &headers).unwrap(), None);
    }

    #[test]
    fn parses_slsa_v02_invoked_source_and_commit() {
        let statement = json!({
            "predicateType": SLSA_V02,
            "predicate": {
                "invocation": {
                    "configSource": {
                        "uri": "git+https://github.com/nearai/compose-manager.git@refs/heads/master",
                        "entryPoint": ".github/workflows/build.yml",
                        "digest": { "sha1": COMMIT }
                    }
                }
            }
        });
        let provenance = serde_json::from_value(statement).unwrap();
        let result = source_commit(provenance, &policy(), "refs/heads/master").unwrap();

        assert_eq!(result, (COMMIT.to_owned(), SLSA_V02));
    }

    #[test]
    fn selects_the_exact_slsa_v1_source_instead_of_the_first_dependency() {
        let statement = json!({
            "predicateType": SLSA_V1,
            "predicate": {
                "buildDefinition": {
                    "externalParameters": {
                        "workflow": {
                            "repository": "https://github.com/nearai/compose-manager",
                            "path": ".github/workflows/build.yml",
                            "ref": "refs/heads/master"
                        }
                    },
                    "resolvedDependencies": [
                        {
                            "uri": "git+https://github.com/other/repo@refs/heads/main",
                            "digest": { "gitCommit": "a".repeat(40) }
                        },
                        {
                            "uri": "git+https://github.com/nearai/compose-manager@refs/heads/master",
                            "digest": { "gitCommit": COMMIT }
                        }
                    ]
                }
            }
        });
        let provenance = serde_json::from_value(statement.clone()).unwrap();
        let result = source_commit(provenance, &policy(), "refs/heads/master").unwrap();
        assert_eq!(result, (COMMIT.to_owned(), SLSA_V1));

        let provenance = serde_json::from_value(statement).unwrap();
        assert_eq!(
            source_commit(provenance, &policy(), "refs/heads/feature"),
            Err(Reason::SourceMismatch)
        );
    }
}
