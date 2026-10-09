use std::sync::Mutex;

use openssl::asn1::Asn1Time;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::x509::{X509NameBuilder, X509Req, X509};

use super::model::{
    CreateProfile, Portal, PortalBundleId, PortalCertificate, PortalDevice, PortalProfile,
};
use crate::{Error, Result};

struct State {
    certificates: Vec<PortalCertificate>,
    bundles: Vec<PortalBundleId>,
    devices: Vec<PortalDevice>,
    profiles: Vec<PortalProfile>,
    next_id: u64,
}

/// In-memory App Store Connect.
///
/// Certificate requests are signed into a real X.509 certificate so the
/// caller's private key can be packed into a PKCS#12 file.
pub struct FakePortal {
    team_id: String,
    state: Mutex<State>,
    ca: PKey<openssl::pkey::Private>,
}

impl FakePortal {
    pub fn new(team_id: impl Into<String>) -> Result<Self> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let ca = PKey::from_ec_key(EcKey::generate(&group)?)?;
        Ok(Self {
            team_id: team_id.into(),
            state: Mutex::new(State {
                certificates: Vec::new(),
                bundles: Vec::new(),
                devices: Vec::new(),
                profiles: Vec::new(),
                next_id: 1,
            }),
            ca,
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().expect("fake portal lock")
    }
}

impl Portal for FakePortal {
    fn list_certificates(&self) -> Result<Vec<PortalCertificate>> {
        Ok(self.lock().certificates.clone())
    }

    fn create_certificate(
        &self,
        certificate_type: &str,
        csr_pem: &str,
    ) -> Result<PortalCertificate> {
        let der = issue_csr(csr_pem, &self.ca)?;
        let mut state = self.lock();
        let id = state.alloc_id("CERT");
        let certificate = PortalCertificate {
            id,
            certificate_type: certificate_type.to_string(),
            display_name: display_name(certificate_type).to_string(),
            certificate_der: der,
        };
        state.certificates.push(certificate.clone());
        Ok(certificate)
    }

    fn revoke_certificate(&self, id: &str) -> Result<()> {
        let mut state = self.lock();
        let before = state.certificates.len();
        state
            .certificates
            .retain(|certificate| certificate.id != id);
        if state.certificates.len() == before {
            return Err(Error::Portal(format!("certificate `{id}` was not found")));
        }
        state
            .profiles
            .retain(|profile| !profile.certificate_ids.iter().any(|cert| cert == id));
        Ok(())
    }

    fn list_bundle_ids(&self) -> Result<Vec<PortalBundleId>> {
        Ok(self.lock().bundles.clone())
    }

    fn create_bundle_id(
        &self,
        name: &str,
        identifier: &str,
        platform: &str,
    ) -> Result<PortalBundleId> {
        let mut state = self.lock();
        if let Some(existing) = state
            .bundles
            .iter()
            .find(|bundle| bundle.identifier == identifier)
        {
            return Ok(existing.clone());
        }
        let bundle = PortalBundleId {
            id: state.alloc_id("BID"),
            name: name.to_string(),
            identifier: identifier.to_string(),
            platform: platform.to_string(),
        };
        state.bundles.push(bundle.clone());
        Ok(bundle)
    }

    fn list_devices(&self) -> Result<Vec<PortalDevice>> {
        Ok(self.lock().devices.clone())
    }

    fn register_device(&self, name: &str, udid: &str, platform: &str) -> Result<PortalDevice> {
        let mut state = self.lock();
        if let Some(existing) = state
            .devices
            .iter()
            .find(|device| device.udid.eq_ignore_ascii_case(udid))
        {
            return Ok(existing.clone());
        }
        let device = PortalDevice {
            id: state.alloc_id("DEV"),
            name: name.to_string(),
            udid: udid.to_string(),
            platform: platform.to_string(),
            enabled: true,
        };
        state.devices.push(device.clone());
        Ok(device)
    }

    fn list_profiles(&self) -> Result<Vec<PortalProfile>> {
        Ok(self.lock().profiles.clone())
    }

    fn create_profile(&self, request: &CreateProfile) -> Result<PortalProfile> {
        let mut state = self.lock();
        let bundle = state
            .bundles
            .iter()
            .find(|bundle| bundle.id == request.bundle_id_id)
            .cloned()
            .ok_or_else(|| {
                Error::Portal(format!(
                    "bundle id `{}` was not found",
                    request.bundle_id_id
                ))
            })?;
        if state
            .profiles
            .iter()
            .any(|profile| profile.name == request.name)
        {
            return Err(Error::Portal(format!(
                "profile name `{}` is already taken",
                request.name
            )));
        }
        for certificate_id in &request.certificate_ids {
            if !state
                .certificates
                .iter()
                .any(|certificate| &certificate.id == certificate_id)
            {
                return Err(Error::Portal(format!(
                    "certificate `{certificate_id}` was not found"
                )));
            }
        }
        let uuid = state.alloc_uuid();
        let udids: Vec<String> = request
            .device_ids
            .iter()
            .filter_map(|id| {
                state
                    .devices
                    .iter()
                    .find(|device| &device.id == id)
                    .map(|device| device.udid.clone())
            })
            .collect();
        let cert_ders: Vec<Vec<u8>> = request
            .certificate_ids
            .iter()
            .filter_map(|id| {
                state
                    .certificates
                    .iter()
                    .find(|certificate| &certificate.id == id)
                    .map(|certificate| certificate.certificate_der.clone())
            })
            .collect();
        let content = render_profile_plist(&request.name, &uuid, &self.team_id, &udids, &cert_ders);
        let profile = PortalProfile {
            id: state.alloc_id("PROF"),
            name: request.name.clone(),
            profile_type: request.profile_type.clone(),
            uuid,
            bundle_identifier: bundle.identifier,
            bundle_id_id: bundle.id,
            certificate_ids: request.certificate_ids.clone(),
            device_ids: request.device_ids.clone(),
            content,
        };
        state.profiles.push(profile.clone());
        Ok(profile)
    }

    fn delete_profile(&self, id: &str) -> Result<()> {
        let mut state = self.lock();
        let before = state.profiles.len();
        state.profiles.retain(|profile| profile.id != id);
        if state.profiles.len() == before {
            return Err(Error::Portal(format!("profile `{id}` was not found")));
        }
        Ok(())
    }
}

impl State {
    fn alloc_id(&mut self, prefix: &str) -> String {
        let id = format!("{prefix}{}", self.next_id);
        self.next_id += 1;
        id
    }

    fn alloc_uuid(&mut self) -> String {
        let id = self.next_id;
        self.next_id += 1;
        format!("00000000-0000-4000-8000-{id:012x}")
    }
}

fn issue_csr(csr_pem: &str, ca: &PKey<openssl::pkey::Private>) -> Result<Vec<u8>> {
    let request = X509Req::from_pem(csr_pem.as_bytes())?;
    let mut issuer = X509NameBuilder::new()?;
    issuer.append_entry_by_text("CN", "Fake Apple Worldwide Developer Relations")?;
    let issuer = issuer.build();
    let public_key = request.public_key()?;
    let mut builder = X509::builder()?;
    builder.set_version(2)?;
    builder.set_subject_name(request.subject_name())?;
    builder.set_issuer_name(&issuer)?;
    builder.set_pubkey(&public_key)?;
    builder.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
    builder.set_not_after(Asn1Time::days_from_now(365)?.as_ref())?;
    builder.sign(ca, MessageDigest::sha256())?;
    Ok(builder.build().to_der()?)
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn display_name(certificate_type: &str) -> &'static str {
    match certificate_type {
        "IOS_DEVELOPMENT" | "MAC_APP_DEVELOPMENT" | "DEVELOPMENT" => "Apple Development",
        "DEVELOPER_ID_APPLICATION" | "DEVELOPER_ID_APPLICATION_G2" => "Developer ID Application",
        "DEVELOPER_ID_INSTALLER" => "Developer ID Installer",
        "MAC_INSTALLER_DISTRIBUTION" => "Mac Installer Distribution",
        _ => "Apple Distribution",
    }
}

fn render_profile_plist(
    name: &str,
    uuid: &str,
    team_id: &str,
    udids: &[String],
    certificates: &[Vec<u8>],
) -> Vec<u8> {
    let name = xml_escape(name);
    let uuid = xml_escape(uuid);
    let team_id = xml_escape(team_id);
    let mut body = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Name</key><string>{name}</string>
<key>UUID</key><string>{uuid}</string>
<key>TeamIdentifier</key><array><string>{team_id}</string></array>
<key>ExpirationDate</key><date>2099-01-01T00:00:00Z</date>
"#
    );
    if !udids.is_empty() {
        body.push_str("<key>ProvisionedDevices</key><array>");
        for udid in udids {
            body.push_str(&format!("<string>{}</string>", xml_escape(udid)));
        }
        body.push_str("</array>");
    }
    body.push_str("<key>DeveloperCertificates</key><array>");
    for certificate in certificates {
        body.push_str("<data>");
        body.push_str(&base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            certificate,
        ));
        body.push_str("</data>");
    }
    body.push_str("</array></dict></plist>");
    body.into_bytes()
}
