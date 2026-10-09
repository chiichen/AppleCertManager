use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use super::files::{self, Scratch};
use crate::Result;

pub trait ObjectStore: Send + Sync {
    fn list(&self, prefix: &str) -> Result<Vec<String>>;
    fn get(&self, key: &str) -> Result<Vec<u8>>;
    fn put(&self, key: &str, body: &[u8]) -> Result<()>;
    fn delete(&self, key: &str) -> Result<()>;
}

#[derive(Default)]
pub struct MemoryStore {
    objects: Mutex<BTreeMap<String, Vec<u8>>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ObjectStore for MemoryStore {
    fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let objects = self.objects.lock().expect("memory store lock");
        Ok(objects
            .keys()
            .filter(|key| key.starts_with(prefix))
            .cloned()
            .collect())
    }

    fn get(&self, key: &str) -> Result<Vec<u8>> {
        self.objects
            .lock()
            .expect("memory store lock")
            .get(key)
            .cloned()
            .ok_or_else(|| super::storage_err(format!("object `{key}` was not found")))
    }

    fn put(&self, key: &str, body: &[u8]) -> Result<()> {
        self.objects
            .lock()
            .expect("memory store lock")
            .insert(key.to_string(), body.to_vec());
        Ok(())
    }

    fn delete(&self, key: &str) -> Result<()> {
        self.objects.lock().expect("memory store lock").remove(key);
        Ok(())
    }
}

pub struct ObjectRepo {
    store: Box<dyn ObjectStore>,
    prefix: String,
    label: String,
    scratch: Option<Scratch>,
}

impl ObjectRepo {
    pub fn new(store: Box<dyn ObjectStore>, prefix: impl Into<String>) -> Self {
        let prefix = normalize_prefix(&prefix.into());
        Self {
            store,
            prefix,
            label: "object storage".into(),
            scratch: None,
        }
    }

    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = label.into();
        self
    }

    pub fn open(&mut self) -> Result<PathBuf> {
        if let Some(scratch) = &self.scratch {
            return Ok(scratch.path.clone());
        }
        let scratch = Scratch::new()?;
        for key in self.store.list(&self.prefix)? {
            if key.ends_with('/') || !key.starts_with(&self.prefix) {
                continue;
            }
            let relative = &key[self.prefix.len()..];
            if relative.is_empty() {
                continue;
            }
            let path = scratch.path.join(relative);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(path, self.store.get(&key)?)?;
        }
        let path = scratch.path.clone();
        self.scratch = Some(scratch);
        Ok(path)
    }

    pub fn commit(&mut self, _message: &str) -> Result<()> {
        let root = self.working_dir()?.to_path_buf();
        let mut live = Vec::new();
        for relative in files::relative_files(&root)? {
            let key = format!(
                "{}{}",
                self.prefix,
                relative.to_string_lossy().replace('\\', "/")
            );
            let bytes = fs::read(root.join(&relative))?;
            self.store.put(&key, &bytes)?;
            live.push(key);
        }
        for existing in self.store.list(&self.prefix)? {
            if !live.iter().any(|key| key == &existing) {
                self.store.delete(&existing)?;
            }
        }
        Ok(())
    }

    pub fn description(&self) -> String {
        if self.prefix.is_empty() {
            self.label.clone()
        } else {
            format!("{} ({})", self.label, self.prefix.trim_end_matches('/'))
        }
    }

    pub fn working_dir(&self) -> Result<&Path> {
        self.scratch
            .as_ref()
            .map(|scratch| scratch.path.as_path())
            .ok_or_else(|| super::storage_err("object repository is not open"))
    }
}

fn normalize_prefix(prefix: &str) -> String {
    let trimmed = prefix.trim_matches('/');
    if trimmed.is_empty() {
        String::new()
    } else {
        format!("{trimmed}/")
    }
}
