use std::fs;
use std::path::Path;
use std::process::Command;

use apple_cert_manager_crypto::{self as crypto, self_signed_certificate, KeyMaterial};
use base64::Engine;

fn cmd(dir: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_apple-cert-manager"));
    command.current_dir(dir);
    command
}

fn output(command: &mut Command) -> (bool, String) {
    let output = command.output().unwrap();
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    (output.status.success(), text)
}

#[test]
fn help_lists_the_sync_commands() {
    let dir = tempfile::tempdir().unwrap();
    let (ok, text) = output(cmd(dir.path()).arg("--help"));
    assert!(ok, "{text}");
    assert!(text.contains("sync"));
    assert!(text.contains("nuke"));
    assert!(text.contains("change-password"));
    assert!(text.contains("doctor"));
}

#[test]
fn init_doctor_encrypt_and_readonly_sync() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let (ok, text) = output(cmd(root).arg("init"));
    assert!(ok, "{text}");
    assert!(root.join("acm.toml").is_file());
    assert!(!root.join("devices.txt").exists());
    assert!(root.join("certs/devices.txt").is_file());
    assert!(fs::read_to_string(root.join("acm.toml"))
        .unwrap()
        .contains("MATCH_PASSWORD"));

    let (ok, text) = output(cmd(root).args(["doctor"]));
    assert!(!ok, "{text}");
    assert!(text.contains("MATCH_PASSWORD"));
    assert!(text.contains("AuthKey.p8"));

    fs::write(root.join("AuthKey.p8"), b"not-a-real-key").unwrap();
    let (ok, text) = output(cmd(root).args(["doctor"]).env("MATCH_PASSWORD", "secret"));
    assert!(ok, "{text}");
    assert!(text.contains("MATCH_PASSWORD is set"));
    assert!(text.contains("0 devices in devices.txt"));
    assert!(text.contains("Security.framework"));

    fs::write(
        root.join("devices.txt"),
        "00008030001C25E40A68802E\tApp repo iPhone\tios\n",
    )
    .unwrap();
    fs::write(
        root.join("certs/devices.txt"),
        "00008030001C25E40A68802F\tCert repo iPhone\tios\n",
    )
    .unwrap();
    let (ok, text) = output(cmd(root).args(["doctor"]).env("MATCH_PASSWORD", "secret"));
    assert!(ok, "{text}");
    assert!(text.contains("1 device in devices.txt"));

    fs::write(root.join("plain.cer"), b"certificate-bytes").unwrap();
    let (ok, text) = output(
        cmd(root)
            .args(["encrypt", "plain.cer"])
            .env("MATCH_PASSWORD", "secret"),
    );
    assert!(ok, "{text}");
    let encrypted = fs::read(root.join("plain.cer")).unwrap();
    assert_ne!(encrypted, b"certificate-bytes");
    assert!(crypto::looks_encrypted(&encrypted));
    let (ok, text) = output(
        cmd(root)
            .args(["decrypt", "plain.cer"])
            .env("MATCH_PASSWORD", "secret"),
    );
    assert!(ok, "{text}");
    assert_eq!(
        fs::read(root.join("plain.cer")).unwrap(),
        b"certificate-bytes"
    );

    let (ok, text) = output(
        cmd(root)
            .args(["nuke", "--type", "development"])
            .env("MATCH_PASSWORD", "secret"),
    );
    assert!(!ok, "{text}");
    assert!(text.contains("refusing"));
}

#[test]
fn import_then_readonly_sync_writes_signing_env() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    fs::write(
        root.join("acm.toml"),
        r#"
storage_mode = "local"
[local]
path = "./certs"
[apple]
team_id = "TEAMID1234"
[sync]
output_dir = "./signing"
[[apps]]
name = "政务门户"
bundle_id = "com.example.portal"
platforms = ["ios"]
types = ["development"]
"#,
    )
    .unwrap();

    let key = KeyMaterial::generate().unwrap();
    let der = self_signed_certificate(&key, "Apple Development: Test").unwrap();
    let p12 = key.export_p12(&der, "").unwrap();
    fs::write(root.join("DEV.cer"), &der).unwrap();
    fs::write(root.join("DEV.p12"), &p12).unwrap();
    let cert_b64 = base64::engine::general_purpose::STANDARD.encode(&der);
    fs::write(
        root.join("Development_com.example.portal.mobileprovision"),
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Name</key><string>match Development com.example.portal</string>
<key>UUID</key><string>AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE</string>
<key>TeamIdentifier</key><array><string>TEAMID1234</string></array>
<key>ExpirationDate</key><date>2099-01-01T00:00:00Z</date>
<key>DeveloperCertificates</key><array><data>{cert_b64}</data></array>
</dict></plist>"#
        ),
    )
    .unwrap();

    let (ok, text) = output(
        cmd(root)
            .args([
                "import",
                "--type",
                "development",
                "DEV.cer",
                "DEV.p12",
                "Development_com.example.portal.mobileprovision",
            ])
            .env("MATCH_PASSWORD", "old-secret"),
    );
    assert!(ok, "{text}");

    let (ok, text) = output(
        cmd(root)
            .args(["change-password"])
            .env("MATCH_PASSWORD", "old-secret")
            .env("MATCH_PASSWORD_NEW", "new-secret"),
    );
    assert!(ok, "{text}");

    let (ok, text) = output(
        cmd(root)
            .args(["sync", "--readonly"])
            .env("MATCH_PASSWORD", "old-secret"),
    );
    assert!(!ok, "{text}");

    let (ok, text) = output(
        cmd(root)
            .args(["sync", "--readonly"])
            .env("MATCH_PASSWORD", "new-secret"),
    );
    assert!(ok, "{text}");
    assert!(text.contains("signing.env"));
    assert!(text.contains("Security.framework"));
    let env = fs::read_to_string(root.join("signing/signing.env")).unwrap();
    assert!(env
        .contains("sigh_com.example.portal_development=\"AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE\""));
    assert!(env.contains("Apple Development: Test"));
    assert!(env.contains("match Development com.example.portal"));
    assert!(root
        .join("signing/com.example.portal/development/Signing.xcconfig")
        .is_file());
    assert!(root
        .join("signing/com.example.portal/development/ExportOptions.plist")
        .is_file());
    assert!(root
        .join("signing/profiles/AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE.mobileprovision")
        .is_file());
}
