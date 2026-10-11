//! Fixed resource limits for endpoint-supplied attestation evidence.
pub(crate) const MAX_EVIDENCE_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const MAX_MODEL_REPORTS: usize = 64;
pub(crate) const REPORT_VERIFICATION_CONCURRENCY: usize = 4;

pub(crate) fn require_report_count(count: usize, path: &str) -> Result<(), crate::ApiError> {
    if count > MAX_MODEL_REPORTS {
        return Err(crate::ApiError::InvalidResponse {
            path: path.into(),
            expected: format!("at most {MAX_MODEL_REPORTS} model reports"),
            actual: "report count exceeds limit".into(),
        });
    }
    Ok(())
}
