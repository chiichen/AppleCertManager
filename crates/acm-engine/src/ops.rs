use std::fs;
use std::path::{Path, PathBuf};

use acm_crypto::{self as crypto, encryption_version};
use acm_error::{Error, Result};
use acm_portal::Portal;
use acm_storage::{self as storage, Repo};
use acm_types::{Platform, SigningType};

#[derive(Debug, Clone)]
pub struct NukeRequest {
    pub signing_types: Vec<SigningType>,
    pub platforms: Vec<Platform>,
    pub confirmed: bool,
    pub legacy_encryption: bool,
}

pub fn nuke<P: Portal>(
    repo: &mut Repo,
    portal: Option<&P>,
    password: &str,
    request: &NukeRequest,
) -> Result<()> {
    crypto::require_password(password)?;
    if !request.confirmed {
        return Err(Error::msg(
            "refusing to revoke certificates. Pass confirmed: true or --yes",
        ));
    }
    let work = repo.open()?;
    crypto::decrypt_tree(&work, password)?;
    let platforms = if request.platforms.is_empty() {
        vec![
            Platform::Ios,
            Platform::Macos,
            Platform::Tvos,
            Platform::Catalyst,
        ]
    } else {
        request.platforms.clone()
    };
    for signing in &request.signing_types {
        remove_files(&work.join("certs").join(signing.cert_folder()))?;
        if let Some(folder) = signing.profile_folder() {
            remove_files(&work.join("profiles").join(folder))?;
        }
        if let Some(portal) = portal {
            let mut types = Vec::new();
            for platform in &platforms {
                for certificate_type in signing.apple_certificate_types(*platform) {
                    if !types.contains(certificate_type) {
                        types.push(certificate_type);
                    }
                }
            }
            for certificate in portal.list_certificates()? {
                if types.contains(&certificate.certificate_type.as_str()) {
                    portal.revoke_certificate(&certificate.id)?;
                }
            }
            let mut profile_types = Vec::new();
            for platform in &platforms {
                if let Some(profile_type) = signing.apple_profile_type(*platform) {
                    profile_types.push(profile_type);
                }
            }
            for profile in portal.list_profiles()? {
                if profile_types.contains(&profile.profile_type.as_str()) {
                    portal.delete_profile(&profile.id)?;
                }
            }
        }
    }
    crypto::encrypt_tree(
        &work,
        password,
        encryption_version(request.legacy_encryption),
    )?;
    repo.commit("Revoke certificates and provisioning profiles")?;
    Ok(())
}

pub fn import(
    repo: &mut Repo,
    password: &str,
    signing: SigningType,
    legacy: bool,
    files: &[PathBuf],
) -> Result<()> {
    crypto::require_password(password)?;
    if files.is_empty() {
        return Err(Error::msg(
            "import needs at least one certificate or profile",
        ));
    }
    let work = repo.open()?;
    crypto::decrypt_tree(&work, password)?;
    for file in files {
        let name = file
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| Error::msg(format!("cannot use {}", file.display())))?;
        let extension = file.extension().and_then(|ext| ext.to_str()).unwrap_or("");
        let destination = match extension {
            "cer" | "p12" => work.join("certs").join(signing.cert_folder()).join(name),
            "mobileprovision" | "provisionprofile" => {
                let folder = signing.profile_folder().ok_or_else(|| {
                    Error::msg(format!("{signing} does not use provisioning profiles"))
                })?;
                work.join("profiles").join(folder).join(name)
            }
            _ => {
                return Err(Error::msg(format!(
                    "{} is not a .cer, .p12, .mobileprovision, or .provisionprofile",
                    file.display()
                )))
            }
        };
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(file, destination)?;
    }
    crypto::encrypt_tree(&work, password, encryption_version(legacy))?;
    repo.commit("Import certificates and provisioning profiles")?;
    Ok(())
}

pub fn change_password(
    repo: &mut Repo,
    old_password: &str,
    new_password: &str,
    legacy: bool,
) -> Result<()> {
    crypto::require_password(old_password)?;
    crypto::require_password(new_password)?;
    let work = repo.open()?;
    crypto::decrypt_tree(&work, old_password)?;
    crypto::encrypt_tree(&work, new_password, encryption_version(legacy))?;
    repo.commit("Change certificate repository password")?;
    Ok(())
}

pub fn migrate(
    source: &mut Repo,
    destination: &mut Repo,
    password: &str,
    legacy: bool,
) -> Result<()> {
    crypto::require_password(password)?;
    let from = source.open()?;
    crypto::decrypt_tree(&from, password)?;
    let to = destination.open()?;
    clear_worktree(&to)?;
    storage::copy_tree(&from, &to)?;
    crypto::encrypt_tree(&to, password, encryption_version(legacy))?;
    destination.commit("Migrate certificates and provisioning profiles")?;
    Ok(())
}

fn remove_files(dir: &Path) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_file() {
            fs::remove_file(path)?;
        }
    }
    Ok(())
}

fn clear_worktree(dir: &Path) -> Result<()> {
    if !dir.exists() {
        fs::create_dir_all(dir)?;
        return Ok(());
    }
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.file_name().is_some_and(|name| name == ".git") {
            continue;
        }
        if path.is_dir() {
            fs::remove_dir_all(path)?;
        } else {
            fs::remove_file(path)?;
        }
    }
    Ok(())
}
