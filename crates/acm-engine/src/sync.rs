use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use acm_config::Config;
use acm_crypto::{
    self as crypto, encryption_version, inspect_certificate, EncryptionVersion, KeyMaterial,
};
use acm_devices::DeviceRecord;
use acm_error::{Error, Result};
use acm_portal::{CreateProfile, Portal, PortalCertificate, PortalDevice};
use acm_storage::Repo;
use acm_types::{Platform, SigningType};

use super::profile::{self, ParsedProfile};

const REPO_README: &str = "\
# Certificates

This repository is managed by `acm` and uses the fastlane match layout.
The `.cer`, `.p12`, and provisioning profile files are encrypted.
`devices.txt` lists devices to register and stays in this repository.
Set `MATCH_PASSWORD` before running `acm sync`.
";

#[derive(Debug, Clone)]
pub struct AppPlan {
    pub name: String,
    pub bundle_id: String,
    pub platforms: Vec<Platform>,
    pub types: Vec<SigningType>,
    pub profile_name: Option<String>,
    pub extra_cert_types: Vec<SigningType>,
}

#[derive(Debug, Clone)]
pub struct SyncPlan {
    pub apps: Vec<AppPlan>,
    pub devices: Vec<DeviceRecord>,
    pub team_id: String,
    pub readonly: bool,
    pub force: bool,
    pub force_for_new_devices: bool,
    pub renew_expired: bool,
    pub include_all_certificates: bool,
    pub legacy_encryption: bool,
    pub certificate_id: Option<String>,
    pub p12_password: String,
    pub skip_profiles: bool,
}

impl SyncPlan {
    pub fn from_config(config: &Config, devices: Vec<DeviceRecord>) -> Self {
        Self {
            apps: config
                .apps
                .iter()
                .map(|app| AppPlan {
                    name: app.display_name().to_string(),
                    bundle_id: app.bundle_id.clone(),
                    platforms: app.platforms.clone(),
                    types: app.types.clone(),
                    profile_name: app.profile_name.clone(),
                    extra_cert_types: app.extra_cert_types.clone(),
                })
                .collect(),
            devices,
            team_id: config.apple.team_id.clone(),
            readonly: config.sync.readonly,
            force: config.sync.force,
            force_for_new_devices: config.sync.force_for_new_devices,
            renew_expired: config.sync.renew_expired,
            include_all_certificates: config.sync.include_all_certificates,
            legacy_encryption: config.sync.force_legacy_encryption,
            certificate_id: config.sync.certificate_id.clone(),
            p12_password: config.sync.p12_password.clone(),
            skip_profiles: config.sync.skip_profiles,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncedCertificate {
    pub id: String,
    pub signing: SigningType,
    pub common_name: String,
    pub der: Vec<u8>,
    pub p12: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncedProfile {
    pub bundle_id: String,
    pub platform: Platform,
    pub signing: SigningType,
    pub uuid: String,
    pub name: String,
    pub team_id: String,
    pub certificate_name: String,
    pub certificate_id: String,
    pub content: Vec<u8>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncReport {
    pub certificates: Vec<SyncedCertificate>,
    pub profiles: Vec<SyncedProfile>,
    pub registered_devices: usize,
    pub created_bundle_ids: usize,
    pub created_certificates: usize,
    pub created_profiles: usize,
}

struct Session<'a, P: Portal> {
    repo: &'a mut Repo,
    portal: Option<&'a P>,
    password: &'a str,
    plan: &'a SyncPlan,
    work: PathBuf,
    version: EncryptionVersion,
    report: SyncReport,
    dirty: bool,
}

pub fn sync<P: Portal>(
    repo: &mut Repo,
    portal: Option<&P>,
    password: &str,
    plan: &SyncPlan,
) -> Result<SyncReport> {
    crypto::require_password(password)?;
    let work = repo.open()?;
    crypto::decrypt_tree(&work, password)?;
    let mut session = Session {
        repo,
        portal,
        password,
        plan,
        work,
        version: encryption_version(plan.legacy_encryption),
        report: SyncReport::default(),
        dirty: false,
    };
    if !session.plan.readonly {
        session.ensure_metadata()?;
        if session.portal.is_some() {
            session.register_devices()?;
        }
    }
    let apps = session.plan.apps.clone();
    for app in &apps {
        session.sync_app(app)?;
    }
    if session.dirty && !plan.readonly {
        session.checkpoint("Update certificates and provisioning profiles")?;
    }
    Ok(session.report)
}

impl<'a, P: Portal> Session<'a, P> {
    fn sync_app(&mut self, app: &AppPlan) -> Result<()> {
        for platform in app.platforms.clone() {
            if !self.plan.readonly {
                self.ensure_bundle(app, platform)?;
            }
            for signing in app.types.clone() {
                let certificate = self.ensure_certificate(signing, platform)?;
                if !self.plan.skip_profiles && signing.apple_profile_type(platform).is_some() {
                    self.ensure_profile(app, platform, signing, &certificate)?;
                }
            }
            for signing in &app.extra_cert_types {
                if !app.types.contains(signing) {
                    self.ensure_certificate(*signing, platform)?;
                }
            }
        }
        Ok(())
    }

    fn register_devices(&mut self) -> Result<()> {
        let devices = self.plan.devices.clone();
        let added = {
            let portal = self.portal_ref()?;
            let mut known: HashSet<String> = portal
                .list_devices()?
                .into_iter()
                .map(|device| device.udid.to_ascii_lowercase())
                .collect();
            let mut added = 0;
            for device in devices {
                let key = device.udid.to_ascii_lowercase();
                if known.contains(&key) {
                    continue;
                }
                portal.register_device(&device.name, &device.udid, &device.platform)?;
                known.insert(key);
                added += 1;
            }
            added
        };
        self.report.registered_devices += added;
        if added > 0 {
            self.dirty = true;
        }
        Ok(())
    }

    fn ensure_bundle(&mut self, app: &AppPlan, platform: Platform) -> Result<()> {
        let name = app.name.clone();
        let bundle_id = app.bundle_id.clone();
        let created = {
            let portal = self.portal_ref()?;
            if portal
                .list_bundle_ids()?
                .iter()
                .any(|bundle| bundle.identifier == bundle_id)
            {
                false
            } else {
                portal.create_bundle_id(&name, &bundle_id, platform.bundle_id_platform())?;
                true
            }
        };
        if created {
            self.report.created_bundle_ids += 1;
            self.dirty = true;
        }
        Ok(())
    }

    fn ensure_certificate(
        &mut self,
        signing: SigningType,
        platform: Platform,
    ) -> Result<SyncedCertificate> {
        if let Some(existing) = self
            .report
            .certificates
            .iter()
            .find(|certificate| {
                certificate.signing == signing && certificate_matches_platform(signing, platform)
            })
            .cloned()
        {
            // Development on iOS and macOS share a folder but not a certificate type.
            // Reuse only when this lane's Apple types include the cert we already made.
            if self.portal_accepts(&existing, signing, platform)? {
                return Ok(existing);
            }
        }
        self.retire_expired(signing)?;
        let allowed = signing.apple_certificate_types(platform);
        let mut candidates = local_certificates(&self.work, signing)?;
        if self.plan.renew_expired {
            candidates.retain(|certificate| certificate.valid);
        }
        if !self.plan.readonly {
            if let Some(portal) = self.portal {
                let remote = portal.list_certificates()?;
                candidates.retain(|certificate| {
                    remote_match(&remote, &certificate.id, &certificate.der, allowed)
                });
            }
        }
        if let Some(pinned) = &self.plan.certificate_id {
            if let Some(found) = candidates
                .iter()
                .find(|certificate| &certificate.id == pinned)
            {
                return self.remember_local(found, signing);
            }
            return Err(Error::msg(format!(
                "certificate `{pinned}` is not available for {signing} {platform}"
            )));
        }
        if let Some(found) = candidates.last() {
            return self.remember_local(found, signing);
        }
        if self.plan.readonly {
            return Err(Error::msg(format!(
                "no {signing} certificate for {platform} is in the repository. Run acm sync without readonly so it can be created"
            )));
        }
        let created = self.create_certificate(signing, platform)?;
        self.checkpoint(&format!("Add {signing} certificate {}", created.id))?;
        Ok(created)
    }

    fn portal_accepts(
        &self,
        certificate: &SyncedCertificate,
        signing: SigningType,
        platform: Platform,
    ) -> Result<bool> {
        let Some(portal) = self.portal else {
            return Ok(true);
        };
        if self.plan.readonly {
            return Ok(true);
        }
        let remote = portal.list_certificates()?;
        Ok(remote_match(
            &remote,
            &certificate.id,
            &certificate.der,
            signing.apple_certificate_types(platform),
        ))
    }

    fn retire_expired(&mut self, signing: SigningType) -> Result<()> {
        if !self.plan.renew_expired || self.plan.readonly {
            return Ok(());
        }
        let locals = local_certificates(&self.work, signing)?;
        for certificate in locals.into_iter().filter(|certificate| !certificate.valid) {
            let _ = fs::remove_file(&certificate.cer_path);
            let _ = fs::remove_file(&certificate.p12_path);
            if let Some(portal) = self.portal {
                if portal
                    .list_certificates()?
                    .iter()
                    .any(|remote| remote.id == certificate.id)
                {
                    portal.revoke_certificate(&certificate.id)?;
                }
            }
            self.dirty = true;
        }
        Ok(())
    }

    fn create_certificate(
        &mut self,
        signing: SigningType,
        platform: Platform,
    ) -> Result<SyncedCertificate> {
        let certificate_type = signing
            .preferred_certificate_type(platform)
            .ok_or_else(|| {
                Error::msg(format!(
                    "{signing} has no App Store Connect certificate type on {platform}"
                ))
            })?;
        let key = KeyMaterial::generate()?;
        let csr = key.csr_pem("Apple Certificate")?;
        let created = self.portal_ref()?.create_certificate(certificate_type, &csr).map_err(|err| {
            if signing == SigningType::DeveloperId
                || signing == SigningType::DeveloperIdInstaller
            {
                Error::msg(format!(
                    "{err}. Developer ID certificates cannot be created with an API key. Import an existing .p12 with `acm import`"
                ))
            } else {
                err
            }
        })?;
        let der = created.certificate_der;
        let p12 = key.export_p12(&der, &self.plan.p12_password)?;
        let folder = self.work.join("certs").join(signing.cert_folder());
        fs::create_dir_all(&folder)?;
        fs::write(folder.join(format!("{}.cer", created.id)), &der)?;
        fs::write(folder.join(format!("{}.p12", created.id)), &p12)?;
        let info = inspect_certificate(&der)?;
        let synced = SyncedCertificate {
            id: created.id,
            signing,
            common_name: info.common_name,
            der,
            p12,
        };
        self.report.created_certificates += 1;
        self.remember(synced.clone());
        self.dirty = true;
        Ok(synced)
    }

    fn remember_local(
        &mut self,
        certificate: &LocalCertificate,
        signing: SigningType,
    ) -> Result<SyncedCertificate> {
        let synced = SyncedCertificate {
            id: certificate.id.clone(),
            signing,
            common_name: certificate.common_name.clone(),
            der: certificate.der.clone(),
            p12: fs::read(&certificate.p12_path)?,
        };
        self.remember(synced.clone());
        Ok(synced)
    }

    fn remember(&mut self, certificate: SyncedCertificate) {
        if !self
            .report
            .certificates
            .iter()
            .any(|existing| existing.id == certificate.id)
        {
            self.report.certificates.push(certificate);
        }
    }

    fn ensure_profile(
        &mut self,
        app: &AppPlan,
        platform: Platform,
        signing: SigningType,
        certificate: &SyncedCertificate,
    ) -> Result<()> {
        let folder_name = signing
            .profile_folder()
            .ok_or_else(|| Error::msg(format!("{signing} has no provisioning profile")))?;
        let filename = signing.profile_filename(&app.bundle_id, platform);
        let path = self.work.join("profiles").join(folder_name).join(&filename);
        let portal_name = app
            .profile_name
            .clone()
            .unwrap_or_else(|| signing.portal_profile_name(&app.bundle_id, platform));
        let existing = if path.exists() {
            Some(profile::parse_profile(&fs::read(&path)?)?)
        } else {
            None
        };
        let refresh = self.profile_needs_refresh(signing, platform, existing.as_ref())?;
        if let Some(parsed) = existing.filter(|_| !refresh) {
            self.report.profiles.push(synced_profile(
                app,
                platform,
                signing,
                &certificate.id,
                &parsed,
                fs::read(&path)?,
            ));
            return Ok(());
        }
        if self.plan.readonly {
            return Err(Error::msg(format!(
                "provisioning profile {filename} is missing. Run acm sync without readonly so it can be created"
            )));
        }
        let bundle_id = app.bundle_id.clone();
        let certificate_id = certificate.id.clone();
        let include_all = self.plan.include_all_certificates;
        let created = {
            let portal = self.portal_ref()?;
            if let Some(current) = portal
                .list_profiles()?
                .into_iter()
                .find(|profile| profile.name == portal_name)
            {
                portal.delete_profile(&current.id)?;
            }
            let devices = if signing.includes_devices() {
                portal
                    .list_devices()?
                    .into_iter()
                    .filter(|device| {
                        device.enabled && device.platform == platform.device_platform()
                    })
                    .map(|device| device.id)
                    .collect()
            } else {
                Vec::new()
            };
            let bundle = portal
                .list_bundle_ids()?
                .into_iter()
                .find(|bundle| bundle.identifier == bundle_id)
                .ok_or_else(|| {
                    Error::msg(format!(
                        "bundle id {bundle_id} is not registered for {platform}"
                    ))
                })?;
            let certificate_ids = if include_all {
                certificate_ids_for(portal, signing, platform)?
            } else {
                vec![certificate_id]
            };
            portal.create_profile(&CreateProfile {
                name: portal_name,
                profile_type: signing.apple_profile_type(platform).unwrap().to_string(),
                bundle_id_id: bundle.id,
                certificate_ids,
                device_ids: devices,
            })?
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, &created.content)?;
        let parsed = profile::parse_profile(&created.content)?;
        self.report.profiles.push(synced_profile(
            app,
            platform,
            signing,
            &certificate.id,
            &parsed,
            created.content,
        ));
        self.report.created_profiles += 1;
        self.dirty = true;
        Ok(())
    }

    fn profile_needs_refresh(
        &self,
        signing: SigningType,
        platform: Platform,
        parsed: Option<&ParsedProfile>,
    ) -> Result<bool> {
        let Some(parsed) = parsed else {
            return Ok(true);
        };
        if self.plan.force || parsed.expired || parsed.uuid.is_empty() {
            return Ok(true);
        }
        let Some(portal) = self.portal else {
            return Ok(false);
        };
        if !self.plan.readonly
            && !portal
                .list_profiles()?
                .iter()
                .any(|profile| profile.uuid == parsed.uuid)
        {
            return Ok(true);
        }
        if self.plan.force_for_new_devices && signing.includes_devices() && !self.plan.readonly {
            let devices = portal.list_devices()?;
            if devices_missing(&devices, platform, &parsed.devices) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn ensure_metadata(&mut self) -> Result<()> {
        let readme = self.work.join("README.md");
        if !readme.exists() {
            fs::write(readme, REPO_README)?;
            self.dirty = true;
        }
        let version_path = self.work.join("acm_version.txt");
        let version = format!("{}\n", env!("CARGO_PKG_VERSION"));
        if fs::read_to_string(&version_path).ok().as_deref() != Some(version.as_str()) {
            fs::write(version_path, version)?;
            self.dirty = true;
        }
        Ok(())
    }

    fn checkpoint(&mut self, message: &str) -> Result<()> {
        crypto::encrypt_tree(&self.work, self.password, self.version)?;
        self.repo.commit(message)?;
        crypto::decrypt_tree(&self.work, self.password)?;
        self.dirty = false;
        Ok(())
    }

    fn portal_ref(&self) -> Result<&P> {
        self.portal.ok_or_else(|| {
            Error::msg(
                "App Store Connect credentials are required to create certificates or profiles"
                    .to_string(),
            )
        })
    }
}

struct LocalCertificate {
    id: String,
    cer_path: PathBuf,
    p12_path: PathBuf,
    der: Vec<u8>,
    common_name: String,
    valid: bool,
}

fn local_certificates(work: &Path, signing: SigningType) -> Result<Vec<LocalCertificate>> {
    let folder = work.join("certs").join(signing.cert_folder());
    if !folder.exists() {
        return Ok(Vec::new());
    }
    let mut paths: Vec<PathBuf> = fs::read_dir(&folder)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("cer"))
        .collect();
    paths.sort();
    let mut certificates = Vec::new();
    for cer_path in paths {
        let p12_path = cer_path.with_extension("p12");
        if !p12_path.exists() {
            continue;
        }
        let der = fs::read(&cer_path)?;
        let (common_name, valid) = match inspect_certificate(&der) {
            Ok(info) => (info.common_name, info.valid),
            Err(_) => (String::new(), false),
        };
        certificates.push(LocalCertificate {
            id: cer_path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .unwrap_or_default()
                .to_string(),
            cer_path,
            p12_path,
            der,
            common_name,
            valid,
        });
    }
    Ok(certificates)
}

fn remote_match(remote: &[PortalCertificate], id: &str, der: &[u8], allowed: &[&str]) -> bool {
    remote.iter().any(|certificate| {
        allowed.contains(&certificate.certificate_type.as_str())
            && (certificate.id == id || (!der.is_empty() && certificate.certificate_der == der))
    })
}

fn certificate_ids_for<P: Portal>(
    portal: &P,
    signing: SigningType,
    platform: Platform,
) -> Result<Vec<String>> {
    let allowed = signing.apple_certificate_types(platform);
    Ok(portal
        .list_certificates()?
        .into_iter()
        .filter(|certificate| allowed.contains(&certificate.certificate_type.as_str()))
        .map(|certificate| certificate.id)
        .collect())
}

fn devices_missing(devices: &[PortalDevice], platform: Platform, profile_udids: &[String]) -> bool {
    devices.iter().any(|device| {
        device.enabled
            && device.platform == platform.device_platform()
            && !profile_udids
                .iter()
                .any(|udid| udid.eq_ignore_ascii_case(&device.udid))
    })
}

fn certificate_matches_platform(signing: SigningType, platform: Platform) -> bool {
    signing.preferred_certificate_type(platform).is_some()
}

fn synced_profile(
    app: &AppPlan,
    platform: Platform,
    signing: SigningType,
    certificate_id: &str,
    parsed: &ParsedProfile,
    content: Vec<u8>,
) -> SyncedProfile {
    SyncedProfile {
        bundle_id: app.bundle_id.clone(),
        platform,
        signing,
        uuid: parsed.uuid.clone(),
        name: parsed.name.clone(),
        team_id: parsed.team_ids.first().cloned().unwrap_or_default(),
        certificate_name: parsed
            .certificate_names
            .first()
            .cloned()
            .unwrap_or_default(),
        certificate_id: certificate_id.to_string(),
        content,
    }
}
