//! Match-compatible encryption and certificate material.
//!
//! Match v2 is AES-256-GCM with PBKDF2-HMAC-SHA256 (10_000 iterations).
//! Match v1 is OpenSSL `EVP_BytesToKey` AES-256-CBC. Files written by OpenSSL
//! 1.0 use MD5; OpenSSL 1.1+ use SHA-256. Decryption tries MD5, then SHA-256.

mod certs;
mod match_crypt;

pub use certs::{
    inspect_certificate, reprotect_p12_for_keychain, self_signed_certificate, CertificateInfo,
    KeyMaterial,
};
pub use match_crypt::{
    decrypt, decrypt_file, decrypt_tree, encrypt, encrypt_file, encrypt_tree, encrypt_with_salt,
    looks_encrypted, EncryptionVersion,
};

use apple_cert_manager_error::Result;

pub fn encryption_version(force_legacy: bool) -> EncryptionVersion {
    if force_legacy {
        EncryptionVersion::V1
    } else {
        EncryptionVersion::V2
    }
}

pub fn require_password(password: &str) -> Result<()> {
    if password.is_empty() {
        Err(apple_cert_manager_error::Error::Crypto(
            "encryption password is empty. Set MATCH_PASSWORD".into(),
        ))
    } else {
        Ok(())
    }
}
