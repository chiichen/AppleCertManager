use std::process::ExitStatus;

/// Errors produced by the certificate manager.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Message(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    OpenSsl(#[from] openssl::error::ErrorStack),
    #[error("invalid configuration: {0}")]
    Config(String),
    #[error("failed to read configuration: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("encryption failed: {0}")]
    Crypto(String),
    #[error("command `{command}` failed ({status}): {stderr}")]
    Command {
        command: String,
        status: ExitStatus,
        stderr: String,
    },
}

impl Error {
    pub fn msg(message: impl Into<String>) -> Self {
        Self::Message(message.into())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
