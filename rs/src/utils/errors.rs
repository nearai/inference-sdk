use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to verify: {0}")]
    VerificationError(String),

    #[error(transparent)]
    OtherError(#[from] anyhow::Error),
}

impl Error {
    pub fn verification(message: String) -> Self {
        Self::VerificationError(message)
    }

    pub fn common(message: String) -> Self {
        Self::OtherError(anyhow::Error::msg(message))
    }

    pub fn other<E: std::error::Error + Send + Sync + 'static>(e: E) -> Self {
        Self::OtherError(anyhow::Error::new(e))
    }
}
