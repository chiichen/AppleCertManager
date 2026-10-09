use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use acm_error::{Error, Result};
use acm_types::{Platform, SigningType};

/// Repository encryption password. Never stored in `acm.toml`.
pub const PASSWORD_ENV: &str = "MATCH_PASSWORD";

pub const SAMPLE_CONFIG: &str = r#"# One file replaces Matchfile + Fastfile for signing.
# The encryption password is NOT stored here. Export MATCH_PASSWORD instead.

storage_mode = "local"
# Device list stored in the certificate repository, next to certs/ and profiles/.
devices_file = "devices.txt"

[local]
path = "./certs"

# [git]
# url = "git@git.internal.example:certs.git"
# branch = "main"

# [s3]
# bucket = "apple-certs"
# region = "us-east-1"
# endpoint = "https://minio.internal.example"
# path_style = true

[apple]
key_id = "ABC123XYZ1"
issuer_id = "00000000-0000-0000-0000-000000000000"
key_path = "./AuthKey.p8"
team_id = "TEAMID1234"
in_house = false

[sync]
output_dir = "./signing"
force_for_new_devices = true
renew_expired = true

[[apps]]
name = "政务门户"
bundle_id = "com.example.portal"
platforms = ["ios"]
types = ["development", "adhoc", "appstore"]
"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageMode {
    Git,
    Local,
    S3,
}

impl StorageMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Git => "git",
            Self::Local => "local",
            Self::S3 => "s3",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitStorageConfig {
    pub url: String,
    #[serde(default = "default_branch")]
    pub branch: String,
    #[serde(default)]
    pub shallow: bool,
    #[serde(default = "default_git_name")]
    pub user_name: String,
    #[serde(default = "default_git_email")]
    pub user_email: String,
}

impl Default for GitStorageConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            branch: default_branch(),
            shallow: false,
            user_name: default_git_name(),
            user_email: default_git_email(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalStorageConfig {
    pub path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct S3StorageConfig {
    pub bucket: String,
    #[serde(default = "default_region")]
    pub region: String,
    #[serde(default)]
    pub prefix: String,
    #[serde(default)]
    pub endpoint: Option<String>,
    /// `None` uses path-style when `endpoint` is set, and virtual-host style otherwise.
    #[serde(default)]
    pub path_style: Option<bool>,
    #[serde(default = "default_access_key_env")]
    pub access_key_env: String,
    #[serde(default = "default_secret_key_env")]
    pub secret_key_env: String,
}

impl S3StorageConfig {
    pub fn use_path_style(&self) -> bool {
        self.path_style.unwrap_or(self.endpoint.is_some())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppleConfig {
    #[serde(default)]
    pub key_id: String,
    #[serde(default)]
    pub issuer_id: String,
    #[serde(default)]
    pub key_path: Option<PathBuf>,
    #[serde(default)]
    pub team_id: String,
    #[serde(default)]
    pub in_house: bool,
    /// PEM loaded from the environment. Ignored if present in the toml file.
    #[serde(skip)]
    pub key_pem: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncConfig {
    #[serde(default)]
    pub readonly: bool,
    #[serde(default)]
    pub force: bool,
    #[serde(default = "default_true")]
    pub force_for_new_devices: bool,
    #[serde(default = "default_true")]
    pub renew_expired: bool,
    #[serde(default)]
    pub include_all_certificates: bool,
    #[serde(default)]
    pub force_legacy_encryption: bool,
    #[serde(default)]
    pub skip_profiles: bool,
    #[serde(default)]
    pub skip_install: bool,
    #[serde(default)]
    pub certificate_id: Option<String>,
    #[serde(default = "default_output_dir")]
    pub output_dir: PathBuf,
    /// Password of the inner PKCS#12. Match repositories use an empty password.
    /// This is separate from `MATCH_PASSWORD`, which encrypts the repository.
    #[serde(default)]
    pub p12_password: String,
    #[serde(default = "default_keychain")]
    pub keychain_name: String,
    #[serde(default)]
    pub keychain_password: Option<String>,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            readonly: false,
            force: false,
            force_for_new_devices: true,
            renew_expired: true,
            include_all_certificates: false,
            force_legacy_encryption: false,
            skip_profiles: false,
            skip_install: false,
            certificate_id: None,
            output_dir: default_output_dir(),
            p12_password: String::new(),
            keychain_name: default_keychain(),
            keychain_password: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppConfig {
    pub bundle_id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default = "default_platforms")]
    pub platforms: Vec<Platform>,
    #[serde(default = "default_types")]
    pub types: Vec<SigningType>,
    #[serde(default)]
    pub profile_name: Option<String>,
    #[serde(default)]
    pub extra_cert_types: Vec<SigningType>,
}

impl AppConfig {
    pub fn display_name(&self) -> &str {
        if self.name.is_empty() {
            &self.bundle_id
        } else {
            &self.name
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub storage_mode: StorageMode,
    /// Path of the device list inside the certificate repository.
    #[serde(default = "default_devices_file")]
    pub devices_file: PathBuf,
    #[serde(default)]
    pub git: Option<GitStorageConfig>,
    #[serde(default)]
    pub local: Option<LocalStorageConfig>,
    #[serde(default)]
    pub s3: Option<S3StorageConfig>,
    #[serde(default)]
    pub apple: AppleConfig,
    #[serde(default)]
    pub sync: SyncConfig,
    #[serde(default)]
    pub apps: Vec<AppConfig>,
}

impl Config {
    pub fn parse(text: &str) -> Result<Self> {
        Ok(toml::from_str(text)?)
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path)
            .map_err(|err| Error::Config(format!("cannot read {}: {err}", path.display())))?;
        let mut config = Self::parse(&text)?;
        config.apply_env();
        Ok(config)
    }

    pub fn apply_env(&mut self) {
        if let Ok(url) = std::env::var("MATCH_GIT_URL") {
            if !url.is_empty() {
                self.storage_mode = StorageMode::Git;
                let git = self.git.get_or_insert_with(GitStorageConfig::default);
                git.url = url;
            }
        }
        if let Ok(branch) = std::env::var("MATCH_GIT_BRANCH") {
            if !branch.is_empty() {
                if let Some(git) = self.git.as_mut() {
                    git.branch = branch;
                }
            }
        }
        if let Ok(value) = std::env::var("MATCH_READONLY") {
            self.sync.readonly = is_truthy(&value);
        }
        if let Ok(value) = std::env::var("MATCH_KEYCHAIN_NAME") {
            if !value.is_empty() {
                self.sync.keychain_name = value;
            }
        }
        if let Ok(value) = std::env::var("MATCH_KEYCHAIN_PASSWORD") {
            self.sync.keychain_password = Some(value);
        }

        if let Some(value) = env_nonempty(&["APP_STORE_CONNECT_API_KEY_KEY_ID", "ASC_KEY_ID"]) {
            self.apple.key_id = value;
        }
        if let Some(value) = env_nonempty(&["APP_STORE_CONNECT_API_KEY_ISSUER_ID", "ASC_ISSUER_ID"])
        {
            self.apple.issuer_id = value;
        }
        if let Some(value) = env_nonempty(&["APP_STORE_CONNECT_API_KEY_PATH", "ASC_KEY_PATH"]) {
            self.apple.key_path = Some(PathBuf::from(value));
        }
        if let Some(value) = env_nonempty(&["FASTLANE_TEAM_ID", "ACM_TEAM_ID"]) {
            self.apple.team_id = value;
        }
        if let Ok(value) = std::env::var("APP_STORE_CONNECT_API_KEY_KEY") {
            if !value.trim().is_empty() {
                self.apple.key_pem = Some(normalize_pem_env(&value));
            }
        }
    }

    pub fn validate_storage(&self) -> Result<()> {
        match self.storage_mode {
            StorageMode::Git => {
                let git = self.git.as_ref().ok_or_else(|| {
                    Error::Config("storage_mode is git, but [git] is missing".into())
                })?;
                if git.url.trim().is_empty() {
                    return Err(Error::Config("[git].url is empty".into()));
                }
            }
            StorageMode::Local => {
                let local = self.local.as_ref().ok_or_else(|| {
                    Error::Config("storage_mode is local, but [local] is missing".into())
                })?;
                if local.path.as_os_str().is_empty() {
                    return Err(Error::Config("[local].path is empty".into()));
                }
            }
            StorageMode::S3 => {
                let s3 = self.s3.as_ref().ok_or_else(|| {
                    Error::Config("storage_mode is s3, but [s3] is missing".into())
                })?;
                if s3.bucket.trim().is_empty() {
                    return Err(Error::Config("[s3].bucket is empty".into()));
                }
                if s3.region.trim().is_empty() {
                    return Err(Error::Config("[s3].region is empty".into()));
                }
            }
        }
        Ok(())
    }

    pub fn require_apple(&self) -> Result<()> {
        if self.apple.key_id.trim().is_empty() {
            return Err(Error::Config(
                "apple.key_id is empty. Set it in acm.toml or APP_STORE_CONNECT_API_KEY_KEY_ID"
                    .into(),
            ));
        }
        if self.apple.issuer_id.trim().is_empty() {
            return Err(Error::Config(
                "apple.issuer_id is empty. Set it in acm.toml or APP_STORE_CONNECT_API_KEY_ISSUER_ID".into(),
            ));
        }
        if self.apple.team_id.trim().is_empty() {
            return Err(Error::Config(
                "apple.team_id is empty. Set it in acm.toml or FASTLANE_TEAM_ID".into(),
            ));
        }
        if self.apple.key_pem.is_none() && self.apple.key_path.is_none() {
            return Err(Error::Config(
                "apple.key_path is empty. Set it in acm.toml, ASC_KEY_PATH, or APP_STORE_CONNECT_API_KEY_KEY".into(),
            ));
        }
        Ok(())
    }

    pub fn apple_key_pem(&self) -> Result<Vec<u8>> {
        if let Some(pem) = &self.apple.key_pem {
            return Ok(pem.clone());
        }
        let path = self
            .apple
            .key_path
            .as_ref()
            .ok_or_else(|| Error::Config("apple.key_path is empty".into()))?;
        fs::read(path)
            .map_err(|err| Error::Config(format!("cannot read API key {}: {err}", path.display())))
    }

    /// Relative path of `devices.txt` inside the certificate repository.
    pub fn devices_relative_path(&self) -> Result<&Path> {
        let relative = self.devices_file.as_path();
        if relative.as_os_str().is_empty() {
            return Err(Error::Config(
                "devices_file is empty. Use a relative path such as devices.txt".into(),
            ));
        }
        if relative.is_absolute()
            || relative
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            return Err(Error::Config(format!(
                "devices_file {} must stay inside the certificate repository",
                relative.display()
            )));
        }
        Ok(relative)
    }

    pub fn password_from_env() -> Result<String> {
        match std::env::var(PASSWORD_ENV) {
            Ok(value) if !value.is_empty() => Ok(value),
            Ok(_) => Err(Error::Config(format!("{PASSWORD_ENV} is empty"))),
            Err(_) => Err(Error::Config(format!(
                "{PASSWORD_ENV} is not set. This passphrase encrypts the certificate repository and is never written to acm.toml"
            ))),
        }
    }
}

fn default_devices_file() -> PathBuf {
    PathBuf::from("devices.txt")
}

fn default_branch() -> String {
    "main".into()
}

fn default_git_name() -> String {
    "acm".into()
}

fn default_git_email() -> String {
    "acm@localhost".into()
}

fn default_region() -> String {
    "us-east-1".into()
}

fn default_access_key_env() -> String {
    "AWS_ACCESS_KEY_ID".into()
}

fn default_secret_key_env() -> String {
    "AWS_SECRET_ACCESS_KEY".into()
}

fn default_true() -> bool {
    true
}

fn default_output_dir() -> PathBuf {
    PathBuf::from("signing")
}

fn default_keychain() -> String {
    "login.keychain-db".into()
}

fn default_platforms() -> Vec<Platform> {
    vec![Platform::Ios]
}

fn default_types() -> Vec<SigningType> {
    vec![SigningType::Development, SigningType::AppStore]
}

fn is_truthy(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "y"
    )
}

fn env_nonempty(names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| {
        std::env::var(name)
            .ok()
            .filter(|value| !value.trim().is_empty())
    })
}

fn normalize_pem_env(value: &str) -> Vec<u8> {
    let trimmed = value.trim();
    if trimmed.contains("BEGIN ") {
        let mut pem = trimmed.replace("\\n", "\n");
        if !pem.ends_with('\n') {
            pem.push('\n');
        }
        return pem.into_bytes();
    }
    trimmed.as_bytes().to_vec()
}
