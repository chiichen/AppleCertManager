use std::io::Cursor;

use apple_cert_manager::engine::{SyncReport, SyncedProfile};
use apple_cert_manager::install::{partition_acl_description, SIGNING_PARTITIONS};
use apple_cert_manager::signing::write_signing_files;
use apple_cert_manager::types::{Platform, SigningType};

fn profile(
    bundle: &str,
    platform: Platform,
    signing: SigningType,
    uuid: &str,
    name: &str,
) -> SyncedProfile {
    SyncedProfile {
        bundle_id: bundle.into(),
        platform,
        signing,
        uuid: uuid.into(),
        name: name.into(),
        team_id: "TEAMID1234".into(),
        certificate_name: "Apple Development: Example".into(),
        certificate_id: "CERT1".into(),
        content: b"profile-bytes".to_vec(),
    }
}

#[test]
fn signing_files_follow_sigh_names() {
    let dir = tempfile::tempdir().unwrap();
    let report = SyncReport {
        profiles: vec![
            profile(
                "com.example.portal",
                Platform::Ios,
                SigningType::Development,
                "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE",
                "match Development com.example.portal",
            ),
            profile(
                "com.example.portal",
                Platform::Macos,
                SigningType::AppStore,
                "BBBBBBBB-BBBB-CCCC-DDDD-EEEEEEEEEEEE",
                "match AppStore com.example.portal macos",
            ),
        ],
        ..SyncReport::default()
    };
    let written = write_signing_files(&report, &dir.path().join("signing")).unwrap();
    let env = std::fs::read_to_string(&written.env_path).unwrap();
    assert!(env
        .contains("sigh_com.example.portal_development=\"AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE\""));
    assert!(env.contains(
        "sigh_com.example.portal_development_profile-name=\"match Development com.example.portal\""
    ));
    assert!(env.contains(
        "sigh_com.example.portal_appstore_macos=\"BBBBBBBB-BBBB-CCCC-DDDD-EEEEEEEEEEEE\""
    ));
    assert!(env.contains(
        "sigh_com.example.portal_development_certificate-name=\"Apple Development: Example\""
    ));

    let ios = dir
        .path()
        .join("signing/com.example.portal/development/Signing.xcconfig");
    let xcconfig = std::fs::read_to_string(&ios).unwrap();
    assert!(xcconfig.contains("DEVELOPMENT_TEAM = TEAMID1234"));
    assert!(xcconfig.contains("CODE_SIGN_STYLE = Manual"));
    assert!(xcconfig.contains("CODE_SIGN_IDENTITY = \"Apple Development: Example\""));
    assert!(xcconfig
        .contains("PROVISIONING_PROFILE_SPECIFIER = \"match Development com.example.portal\""));

    let export = dir
        .path()
        .join("signing/com.example.portal/development/ExportOptions.plist");
    let plist = plist::Value::from_reader(Cursor::new(std::fs::read(&export).unwrap())).unwrap();
    let dict = plist.as_dictionary().unwrap();
    assert_eq!(dict.get("method").unwrap().as_string(), Some("development"));
    assert_eq!(
        dict.get("signingStyle").unwrap().as_string(),
        Some("manual")
    );
    assert_eq!(dict.get("teamID").unwrap().as_string(), Some("TEAMID1234"));

    let mac_export = dir
        .path()
        .join("signing/com.example.portal/appstore_macos/ExportOptions.plist");
    let mac = plist::Value::from_reader(Cursor::new(std::fs::read(&mac_export).unwrap())).unwrap();
    assert_eq!(
        mac.as_dictionary()
            .unwrap()
            .get("method")
            .unwrap()
            .as_string(),
        Some("app-store")
    );
    let profile_path = dir
        .path()
        .join("signing/profiles/AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE.mobileprovision");
    assert_eq!(std::fs::read(profile_path).unwrap(), b"profile-bytes");
    assert!(env.contains("AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE.mobileprovision"));
}

#[test]
fn partition_list_plist_matches_match() {
    let encoded = partition_acl_description(SIGNING_PARTITIONS).unwrap();
    let xml = hex::decode(encoded).unwrap();
    let text = String::from_utf8(xml).unwrap();
    assert!(text.contains("<key>Partitions</key>"));
    assert!(text.contains("<string>apple-tool:</string>"));
    assert!(text.contains("<string>apple:</string>"));
    assert!(text.contains("<string>codesign:</string>"));
}
