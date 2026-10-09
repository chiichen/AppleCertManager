use std::path::{Path, PathBuf};

use super::files::{self, Scratch};
use acm_error::Result;

pub struct LocalRepo {
    root: PathBuf,
    scratch: Option<Scratch>,
}

impl LocalRepo {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            scratch: None,
        }
    }

    pub fn open(&mut self) -> Result<PathBuf> {
        if let Some(scratch) = &self.scratch {
            return Ok(scratch.path.clone());
        }
        let scratch = Scratch::new()?;
        if self.root.exists() {
            files::copy_tree(&self.root, &scratch.path)?;
        }
        let path = scratch.path.clone();
        self.scratch = Some(scratch);
        Ok(path)
    }

    pub fn commit(&mut self, _message: &str) -> Result<()> {
        let from = self.working_dir()?.to_path_buf();
        files::replace_tree(&from, &self.root)?;
        Ok(())
    }

    pub fn description(&self) -> String {
        format!("local directory {}", self.root.display())
    }

    pub fn working_dir(&self) -> Result<&Path> {
        self.scratch
            .as_ref()
            .map(|scratch| scratch.path.as_path())
            .ok_or_else(|| super::storage_err("local repository is not open"))
    }
}
