use std::fs;
use std::path::{Path, PathBuf};

use acm_error::Result;

pub(crate) struct Scratch {
    _keep: tempfile::TempDir,
    pub(crate) path: PathBuf,
}

impl Scratch {
    pub(crate) fn new() -> Result<Self> {
        let keep = tempfile::tempdir()?;
        let path = keep.path().to_path_buf();
        Ok(Self { _keep: keep, path })
    }
}

pub fn copy_tree(from: &Path, to: &Path) -> Result<()> {
    if !from.exists() {
        fs::create_dir_all(to)?;
        return Ok(());
    }
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        if entry.file_name() == ".git" {
            continue;
        }
        let dest = to.join(entry.file_name());
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            copy_tree(&entry.path(), &dest)?;
        } else if file_type.is_file() {
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(entry.path(), dest)?;
        }
    }
    Ok(())
}

/// Replace `to` with the files in `from`, leaving a `.git` directory in place.
pub(crate) fn replace_tree(from: &Path, to: &Path) -> Result<()> {
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(to)? {
        let entry = entry?;
        if entry.file_name() == ".git" {
            continue;
        }
        let path = entry.path();
        if path.is_dir() {
            fs::remove_dir_all(path)?;
        } else {
            fs::remove_file(path)?;
        }
    }
    copy_tree(from, to)
}

pub(crate) fn relative_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    collect(root, root, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect(root: &Path, dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_name() == ".git" {
            continue;
        }
        let path = entry.path();
        if path.is_dir() {
            collect(root, &path, files)?;
        } else if path.is_file() {
            files.push(path.strip_prefix(root).unwrap_or(&path).to_path_buf());
        }
    }
    Ok(())
}
