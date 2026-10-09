use acm_crypto::{self as crypto, looks_encrypted, self_signed_certificate, KeyMaterial};
use acm_devices::DeviceRecord;
use acm_engine::{change_password, import, migrate, nuke, sync, AppPlan, NukeRequest, SyncPlan};
use acm_portal::{FakePortal, Portal};
use acm_storage::{LocalRepo, Repo};
use acm_types::{Platform, SigningType};

fn device(name: &str, udid: &str) -> DeviceRecord {
    DeviceRecord {
        name: name.into(),
        udid: udid.into(),
        platform: "IOS".into(),
    }
}

fn plan(devices: Vec<DeviceRecord>, readonly: bool) -> SyncPlan {
    SyncPlan {
        apps: vec![AppPlan {
            name: "政务门户".into(),
            bundle_id: "com.example.portal".into(),
            platforms: vec![Platform::Ios],
            types: vec![
                SigningType::Development,
                SigningType::AdHoc,
                SigningType::AppStore,
            ],
            profile_name: None,
            extra_cert_types: vec![],
        }],
        devices,
        team_id: "TEAMID1234".into(),
        readonly,
        force: false,
        force_for_new_devices: true,
        renew_expired: true,
        include_all_certificates: false,
        legacy_encryption: false,
        certificate_id: None,
        p12_password: String::new(),
        skip_profiles: false,
    }
}

#[test]
fn sync_registers_devices_and_refreshes_only_device_profiles() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("certs");
    let portal = FakePortal::new("TEAMID1234").unwrap();
    let phone = "00008030-001C25E40A68802E";
    let devices = vec![device("Front Desk", phone)];
    let mut repo = Repo::Local(LocalRepo::new(root.clone()));
    let report = sync(
        &mut repo,
        Some(&portal),
        "secret",
        &plan(devices.clone(), false),
    )
    .unwrap();

    assert_eq!(report.registered_devices, 1);
    assert_eq!(report.created_bundle_ids, 1);
    assert_eq!(report.created_certificates, 2);
    assert_eq!(report.created_profiles, 3);
    assert_eq!(portal.list_certificates().unwrap().len(), 2);
    let development = profile(&report, SigningType::Development);
    let adhoc = profile(&report, SigningType::AdHoc);
    let appstore = profile(&report, SigningType::AppStore);
    assert!(text(development).contains(phone));
    assert!(text(adhoc).contains(phone));
    assert!(!text(appstore).contains("ProvisionedDevices"));
    assert!(root.join("README.md").exists());

    let dev_cert = report
        .certificates
        .iter()
        .find(|certificate| certificate.signing == SigningType::Development)
        .unwrap();
    let stored_path = root.join(format!("certs/development/{}.cer", dev_cert.id));
    let stored = std::fs::read(&stored_path).unwrap();
    assert!(looks_encrypted(&stored));

    let mut repo = Repo::Local(LocalRepo::new(root.clone()));
    let again = sync(&mut repo, Some(&portal), "secret", &plan(devices, false)).unwrap();
    assert_eq!(again.created_certificates, 0);
    assert_eq!(again.created_profiles, 0);
    assert_eq!(again.registered_devices, 0);
    assert_eq!(std::fs::read(&stored_path).unwrap(), stored);

    let pad = "00008030-001A35E12612802E";
    let with_pad = vec![device("Front Desk", phone), device("Counter", pad)];
    let mut repo = Repo::Local(LocalRepo::new(root.clone()));
    let refreshed = sync(&mut repo, Some(&portal), "secret", &plan(with_pad, false)).unwrap();
    assert_eq!(refreshed.registered_devices, 1);
    assert_eq!(refreshed.created_certificates, 0);
    assert_eq!(refreshed.created_profiles, 2);
    assert_ne!(
        profile(&refreshed, SigningType::Development).uuid,
        development.uuid
    );
    assert_eq!(
        profile(&refreshed, SigningType::AppStore).uuid,
        appstore.uuid
    );
    assert!(text(profile(&refreshed, SigningType::AdHoc)).contains(pad));
}

#[test]
fn nuke_keeps_distribution_material() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("certs");
    let portal = FakePortal::new("TEAMID1234").unwrap();
    let devices = vec![device("Front Desk", "00008030-001C25E40A68802E")];
    let mut repo = Repo::Local(LocalRepo::new(root.clone()));
    sync(&mut repo, Some(&portal), "secret", &plan(devices, false)).unwrap();

    let mut repo = Repo::Local(LocalRepo::new(root.clone()));
    nuke(
        &mut repo,
        Some(&portal),
        "secret",
        &NukeRequest {
            signing_types: vec![SigningType::Development],
            platforms: vec![Platform::Ios],
            confirmed: true,
            legacy_encryption: false,
        },
    )
    .unwrap();

    assert!(portal
        .list_certificates()
        .unwrap()
        .iter()
        .all(|certificate| certificate.certificate_type != "IOS_DEVELOPMENT"));
    assert!(portal
        .list_certificates()
        .unwrap()
        .iter()
        .any(|certificate| certificate.certificate_type == "IOS_DISTRIBUTION"));
    assert!(portal
        .list_profiles()
        .unwrap()
        .iter()
        .all(|profile| profile.profile_type != "IOS_APP_DEVELOPMENT"));
    assert_eq!(portal.list_profiles().unwrap().len(), 2);

    let mut repo = Repo::Local(LocalRepo::new(root.clone()));
    let work = repo.open().unwrap();
    crypto::decrypt_tree(&work, "secret").unwrap();
    assert!(std::fs::read_dir(work.join("certs/development"))
        .map(|entries| entries.count() == 0)
        .unwrap_or(true));
    assert!(std::fs::read_dir(work.join("certs/distribution"))
        .unwrap()
        .next()
        .is_some());
}

#[test]
fn readonly_does_not_create_missing_material() {
    let dir = tempfile::tempdir().unwrap();
    let portal = FakePortal::new("TEAMID1234").unwrap();
    let mut repo = Repo::Local(LocalRepo::new(dir.path().join("certs")));
    let error = sync(&mut repo, Some(&portal), "secret", &plan(Vec::new(), true)).unwrap_err();
    assert!(error.to_string().contains("readonly"), "{error}");
    assert!(portal.list_certificates().unwrap().is_empty());
}

#[test]
fn import_password_change_and_migrate_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let source_root = dir.path().join("source");
    let key = KeyMaterial::generate().unwrap();
    let der = self_signed_certificate(&key, "Apple Distribution: Gov (TEAMID1234)").unwrap();
    let p12 = key.export_p12(&der, "").unwrap();
    let cer_path = dir.path().join("ABC123.cer");
    let p12_path = dir.path().join("ABC123.p12");
    std::fs::write(&cer_path, &der).unwrap();
    std::fs::write(&p12_path, &p12).unwrap();

    let mut source = Repo::Local(LocalRepo::new(source_root.clone()));
    import(
        &mut source,
        "old-password",
        SigningType::AppStore,
        false,
        &[cer_path, p12_path],
    )
    .unwrap();

    let mut source = Repo::Local(LocalRepo::new(source_root.clone()));
    change_password(&mut source, "old-password", "new-password", false).unwrap();

    let dest_root = dir.path().join("dest");
    let mut source = Repo::Local(LocalRepo::new(source_root.clone()));
    let mut dest = Repo::Local(LocalRepo::new(dest_root.clone()));
    migrate(&mut source, &mut dest, "new-password", false).unwrap();

    let mut dest = Repo::Local(LocalRepo::new(dest_root));
    let work = dest.open().unwrap();
    crypto::decrypt_tree(&work, "new-password").unwrap();
    assert_eq!(
        std::fs::read(work.join("certs/distribution/ABC123.cer")).unwrap(),
        der
    );
    let old = std::fs::read(source_root.join("certs/distribution/ABC123.cer")).unwrap();
    assert!(looks_encrypted(&old));
    assert!(crypto::decrypt_file(
        &source_root.join("certs/distribution/ABC123.cer"),
        "old-password"
    )
    .is_err());
}

fn profile(report: &acm_engine::SyncReport, signing: SigningType) -> &acm_engine::SyncedProfile {
    report
        .profiles
        .iter()
        .find(|profile| profile.signing == signing)
        .unwrap()
}

fn text(profile: &acm_engine::SyncedProfile) -> String {
    String::from_utf8(profile.content.clone()).unwrap()
}
