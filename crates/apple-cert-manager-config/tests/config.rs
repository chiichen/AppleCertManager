use std::sync::Mutex;

use apple_cert_manager_config::{Config, StorageMode, SAMPLE_CONFIG};
use apple_cert_manager_types::{Platform, SigningType};

static ENV_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn sample_config_parses() {
    let config = Config::parse(SAMPLE_CONFIG).unwrap();
    config.validate_storage().unwrap();
    assert_eq!(config.storage_mode, StorageMode::Local);
    assert_eq!(config.apps.len(), 1);
    assert_eq!(config.apps[0].bundle_id, "com.example.portal");
    assert_eq!(config.apps[0].display_name(), "政务门户");
    assert_eq!(config.apps[0].platforms, vec![Platform::Ios]);
    assert_eq!(
        config.apps[0].types,
        vec![
            SigningType::Development,
            SigningType::AdHoc,
            SigningType::AppStore
        ]
    );
    assert_eq!(
        config.devices_relative_path().unwrap(),
        std::path::Path::new("devices.txt")
    );
    assert!(config.sync.force_for_new_devices);
    assert!(config.sync.renew_expired);
    assert!(!config.sync.readonly);
    assert!(config.require_apple().is_ok());
}

#[test]
fn env_overrides_git_and_apple_ids() {
    let _guard = ENV_LOCK.lock().unwrap();
    let previous = snapshot(&[
        "MATCH_GIT_URL",
        "MATCH_READONLY",
        "APP_STORE_CONNECT_API_KEY_KEY_ID",
        "FASTLANE_TEAM_ID",
    ]);
    std::env::set_var("MATCH_GIT_URL", "git@git.internal:certs.git");
    std::env::remove_var("MATCH_GIT_BRANCH");
    std::env::set_var("MATCH_READONLY", "true");
    std::env::set_var("APP_STORE_CONNECT_API_KEY_KEY_ID", "ENVKEYID99");
    std::env::set_var("FASTLANE_TEAM_ID", "ENVTEAMID");

    let mut config = Config::parse(SAMPLE_CONFIG).unwrap();
    config.apply_env();
    assert_eq!(config.storage_mode, StorageMode::Git);
    assert_eq!(
        config.git.as_ref().unwrap().url,
        "git@git.internal:certs.git"
    );
    assert_eq!(config.git.as_ref().unwrap().branch, "main");
    assert!(config.sync.readonly);
    assert_eq!(config.apple.key_id, "ENVKEYID99");
    assert_eq!(config.apple.team_id, "ENVTEAMID");

    restore(&previous);
}

#[test]
fn git_branch_override_applies_when_git_section_exists() {
    let _guard = ENV_LOCK.lock().unwrap();
    let previous = snapshot(&["MATCH_GIT_URL", "MATCH_GIT_BRANCH"]);
    std::env::set_var("MATCH_GIT_URL", "ssh://git.internal/certs.git");
    std::env::set_var("MATCH_GIT_BRANCH", "certificates");
    let mut config = Config::parse(SAMPLE_CONFIG).unwrap();
    config.apply_env();
    assert_eq!(config.git.as_ref().unwrap().branch, "certificates");
    restore(&previous);
}

#[test]
fn devices_file_must_stay_inside_the_certificate_repository() {
    let mut config = Config::parse(SAMPLE_CONFIG).unwrap();
    config.devices_file = std::path::PathBuf::from("/tmp/devices.txt");
    assert!(config.devices_relative_path().is_err());
    config.devices_file = std::path::PathBuf::from("../devices.txt");
    assert!(config.devices_relative_path().is_err());
    config.devices_file = std::path::PathBuf::from("team/devices.txt");
    assert_eq!(
        config.devices_relative_path().unwrap(),
        std::path::Path::new("team/devices.txt")
    );
}

#[cfg(windows)]
#[test]
fn windows_drive_and_root_devices_paths_are_rejected() {
    let mut config = Config::parse(SAMPLE_CONFIG).unwrap();
    for path in [
        r"C:\devices.txt",
        r"\devices.txt",
        r"\\server\share\devices.txt",
    ] {
        config.devices_file = std::path::PathBuf::from(path);
        assert!(
            config.devices_relative_path().is_err(),
            "{path} must stay inside the certificate repository"
        );
    }
}

#[test]
fn missing_storage_section_is_rejected() {
    let config = Config::parse("storage_mode = \"s3\"\n").unwrap();
    assert!(config.validate_storage().is_err());
}

fn snapshot(names: &[&str]) -> Vec<(String, Option<String>)> {
    names
        .iter()
        .map(|name| ((*name).to_string(), std::env::var(name).ok()))
        .collect()
}

fn restore(values: &[(String, Option<String>)]) {
    for (name, value) in values {
        match value {
            Some(value) => std::env::set_var(name, value),
            None => std::env::remove_var(name),
        }
    }
}
