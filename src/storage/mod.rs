//! Certificate repositories.
//!
//! Local directories, Git, and S3-compatible buckets all expose the same
//! working tree. Callers encrypt or decrypt that tree before `commit`.

mod files;
mod git;
mod local;
mod object;
mod s3;
mod sigv4;

use std::path::{Path, PathBuf};

pub use git::GitRepo;
pub use local::LocalRepo;
pub use object::{MemoryStore, ObjectRepo, ObjectStore};
pub use s3::S3Client;
pub use sigv4::{sign_request, SignInput};

use crate::config::{Config, StorageMode};
use crate::{Error, Result};

pub enum Repo {
    Local(LocalRepo),
    Git(GitRepo),
    Object(ObjectRepo),
}

impl Repo {
    pub fn from_config(config: &Config) -> Result<Self> {
        config.validate_storage()?;
        match config.storage_mode {
            StorageMode::Local => {
                let local = config.local.as_ref().expect("validated");
                Ok(Self::Local(LocalRepo::new(local.path.clone())))
            }
            StorageMode::Git => {
                let git = config.git.as_ref().expect("validated");
                Ok(Self::Git(GitRepo::new(
                    git.url.clone(),
                    git.branch.clone(),
                    git.user_name.clone(),
                    git.user_email.clone(),
                    git.shallow,
                )))
            }
            StorageMode::S3 => {
                let s3 = config.s3.as_ref().expect("validated");
                let client = S3Client::from_config(s3)?;
                Ok(Self::Object(ObjectRepo::new(
                    Box::new(client),
                    s3.prefix.clone(),
                )))
            }
        }
    }

    pub fn open(&mut self) -> Result<PathBuf> {
        match self {
            Self::Local(repo) => repo.open(),
            Self::Git(repo) => repo.open(),
            Self::Object(repo) => repo.open(),
        }
    }

    pub fn commit(&mut self, message: &str) -> Result<()> {
        match self {
            Self::Local(repo) => repo.commit(message),
            Self::Git(repo) => repo.commit(message),
            Self::Object(repo) => repo.commit(message),
        }
    }

    pub fn description(&self) -> String {
        match self {
            Self::Local(repo) => repo.description(),
            Self::Git(repo) => repo.description(),
            Self::Object(repo) => repo.description(),
        }
    }

    pub fn working_dir(&self) -> Result<&Path> {
        match self {
            Self::Local(repo) => repo.working_dir(),
            Self::Git(repo) => repo.working_dir(),
            Self::Object(repo) => repo.working_dir(),
        }
    }
}

pub(crate) fn storage_err(message: impl Into<String>) -> Error {
    Error::Storage(message.into())
}
