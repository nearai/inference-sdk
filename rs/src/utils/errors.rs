use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("{0}")]
    VerificationError(String),

    #[error(transparent)]
    OtherError(#[from] anyhow::Error),
}
