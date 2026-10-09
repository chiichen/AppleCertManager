//! Install decrypted identities and provisioning profiles on the machine
//! that will sign the build.
//!
//! Provisioning profiles are ordinary files. On macOS they are also copied
//! into Xcode's profile directory, and the PKCS#12 identity is imported with
//! Security.framework. Other hosts keep the profiles written next to
//! `signing.env` and leave the keychain alone.

use acm_config::SyncConfig;
use acm_engine::SyncReport;
use acm_error::Result;

mod partition;

#[cfg(target_os = "macos")]
mod macos;

pub use partition::{partition_acl_description, SIGNING_PARTITIONS};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallOutcome {
    pub profiles_installed: usize,
    pub identities_installed: usize,
    pub note: Option<String>,
}

pub fn install_into_system(report: &SyncReport, sync: &SyncConfig) -> Result<InstallOutcome> {
    install_with(report, sync)
}

#[cfg(target_os = "macos")]
fn install_with(report: &SyncReport, sync: &SyncConfig) -> Result<InstallOutcome> {
    macos::install(report, sync)
}

#[cfg(not(target_os = "macos"))]
fn install_with(report: &SyncReport, sync: &SyncConfig) -> Result<InstallOutcome> {
    Ok(InstallOutcome {
        profiles_installed: 0,
        identities_installed: 0,
        note: Some(format!(
            "Security.framework would import {} identities into {}. Signing files were written on this host.",
            report.certificates.len(),
            sync.keychain_name
        )),
    })
}
