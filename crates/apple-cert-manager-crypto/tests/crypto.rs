use apple_cert_manager_crypto::{
    decrypt, encrypt, encrypt_with_salt, inspect_certificate, self_signed_certificate,
    EncryptionVersion, KeyMaterial,
};

#[test]
fn v2_roundtrip_and_rejects_wrong_password() {
    let plain = b"provisioning-profile-bytes";
    let encoded = encrypt(plain, "correct horse", EncryptionVersion::V2).unwrap();
    assert!(encoded.contains('\n'));
    assert_eq!(decrypt(&encoded, "correct horse").unwrap(), plain);
    assert!(decrypt(&encoded, "wrong").is_err());
}

#[test]
fn v1_roundtrip_with_fixed_salt() {
    let salt = [1u8, 2, 3, 4, 5, 6, 7, 8];
    let plain = b"certificate-der";
    let encoded = encrypt_with_salt(plain, "match-password", EncryptionVersion::V1, &salt).unwrap();
    assert_eq!(decrypt(&encoded, "match-password").unwrap(), plain);
    let again = encrypt_with_salt(plain, "match-password", EncryptionVersion::V1, &salt).unwrap();
    assert_eq!(encoded, again);
}

#[test]
fn v1_matches_openssl_command() {
    let dir = tempfile::tempdir().unwrap();
    let plain_path = dir.path().join("plain.bin");
    let openssl_path = dir.path().join("openssl.b64");
    let sha_path = dir.path().join("sha.b64");
    let ours_path = dir.path().join("ours.b64");
    let decoded_path = dir.path().join("decoded.bin");
    let plain = b"match repo payload \0 still binary";
    std::fs::write(&plain_path, plain).unwrap();

    // OpenSSL 3 omits the Salted__ header when -S is passed explicitly, so the
    // interop check uses a random salt. The header is what match repositories store.
    assert!(openssl_enc(&plain_path, &openssl_path, "md5"));
    let openssl_body = std::fs::read_to_string(&openssl_path).unwrap();
    assert!(openssl_body.starts_with("U2FsdGVkX1"), "{openssl_body}");
    assert_eq!(decrypt(&openssl_body, "test-password").unwrap(), plain);

    assert!(openssl_enc(&plain_path, &sha_path, "sha256"));
    let sha_body = std::fs::read_to_string(&sha_path).unwrap();
    assert_eq!(decrypt(&sha_body, "test-password").unwrap(), plain);

    let salt_bytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let ours =
        encrypt_with_salt(plain, "test-password", EncryptionVersion::V1, &salt_bytes).unwrap();
    std::fs::write(&ours_path, &ours).unwrap();
    let status = std::process::Command::new("openssl")
        .args([
            "enc",
            "-d",
            "-aes-256-cbc",
            "-md",
            "md5",
            "-k",
            "test-password",
            "-a",
            "-in",
        ])
        .arg(&ours_path)
        .arg("-out")
        .arg(&decoded_path)
        .status()
        .expect("openssl");
    assert!(status.success());
    assert_eq!(std::fs::read(&decoded_path).unwrap(), plain);
}

fn openssl_enc(plain: &std::path::Path, output: &std::path::Path, digest: &str) -> bool {
    std::process::Command::new("openssl")
        .args([
            "enc",
            "-aes-256-cbc",
            "-md",
            digest,
            "-k",
            "test-password",
            "-salt",
            "-a",
            "-in",
        ])
        .arg(plain)
        .arg("-out")
        .arg(output)
        .status()
        .expect("openssl")
        .success()
}

#[test]
fn tree_roundtrip_skips_plaintext_and_readme() {
    let dir = tempfile::tempdir().unwrap();
    let certs = dir.path().join("certs/distribution");
    std::fs::create_dir_all(&certs).unwrap();
    std::fs::write(certs.join("ABC.cer"), b"\x30cer").unwrap();
    std::fs::write(certs.join("ABC.p12"), b"p12-bytes").unwrap();
    std::fs::write(dir.path().join("README.md"), b"docs").unwrap();

    apple_cert_manager_crypto::encrypt_tree(dir.path(), "pw", EncryptionVersion::V2).unwrap();
    let stored = std::fs::read(certs.join("ABC.cer")).unwrap();
    assert!(apple_cert_manager_crypto::looks_encrypted(&stored));
    assert_eq!(
        std::fs::read(dir.path().join("README.md")).unwrap(),
        b"docs"
    );

    apple_cert_manager_crypto::decrypt_tree(dir.path(), "pw").unwrap();
    assert_eq!(std::fs::read(certs.join("ABC.cer")).unwrap(), b"\x30cer");
    apple_cert_manager_crypto::decrypt_tree(dir.path(), "pw").unwrap();
}

#[test]
fn certificate_and_p12_roundtrip() {
    let key = KeyMaterial::generate().unwrap();
    let csr = key.csr_pem("Apple Distribution").unwrap();
    assert!(csr.contains("BEGIN CERTIFICATE REQUEST"));
    let der = self_signed_certificate(&key, "Apple Distribution: Gov (TEAMID1234)").unwrap();
    let info = inspect_certificate(&der).unwrap();
    assert_eq!(info.common_name, "Apple Distribution: Gov (TEAMID1234)");
    assert!(info.valid);

    let p12 = key.export_p12(&der, "").unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("id.p12");
    std::fs::write(&path, &p12).unwrap();
    let output = std::process::Command::new("openssl")
        .args(["pkcs12", "-in"])
        .arg(&path)
        .args(["-nokeys", "-passin", "pass:", "-clcerts"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "openssl pkcs12 failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let pem = String::from_utf8_lossy(&output.stdout);
    assert!(pem.contains("BEGIN CERTIFICATE"));
}
