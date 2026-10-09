use std::fs;
use std::path::Path;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use openssl::hash::MessageDigest;
use openssl::pkcs5::pbkdf2_hmac;
use openssl::symm::{Cipher, Crypter, Mode};

use acm_error::{Error, Result};

const V1_PREFIX: &[u8] = b"Salted__";
const V2_PREFIX: &[u8] = b"match_encrypted_v2__";
const SIGNING_EXTENSIONS: &[&str] = &["cer", "p12", "mobileprovision", "provisionprofile"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionVersion {
    /// OpenSSL AES-256-CBC with `EVP_BytesToKey` and MD5, matching `Salted__`.
    V1,
    /// AES-256-GCM with PBKDF2-HMAC-SHA256, matching `match_encrypted_v2__`.
    V2,
}

pub fn encrypt(data: &[u8], password: &str, version: EncryptionVersion) -> Result<String> {
    let mut salt = [0u8; 8];
    openssl::rand::rand_bytes(&mut salt)?;
    encrypt_with_salt(data, password, version, &salt)
}

pub fn encrypt_with_salt(
    data: &[u8],
    password: &str,
    version: EncryptionVersion,
    salt: &[u8],
) -> Result<String> {
    super::require_password(password)?;
    if salt.len() != 8 {
        return Err(Error::Crypto("match salt must be 8 bytes".into()));
    }
    let body = match version {
        EncryptionVersion::V1 => encrypt_v1(data, password.as_bytes(), salt)?,
        EncryptionVersion::V2 => encrypt_v2(data, password.as_bytes(), salt)?,
    };
    Ok(encode_match_base64(&body))
}

pub fn decrypt(encoded: &str, password: &str) -> Result<Vec<u8>> {
    super::require_password(password)?;
    let stored = decode_match_base64(encoded)?;
    if stored.starts_with(V2_PREFIX) {
        decrypt_v2(&stored, password.as_bytes())
    } else if stored.starts_with(V1_PREFIX) {
        decrypt_v1(&stored, password.as_bytes())
    } else {
        Err(Error::Crypto(
            "file is not a match-encrypted payload".into(),
        ))
    }
}

pub fn looks_encrypted(bytes: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    let Ok(stored) = decode_match_base64(text) else {
        return false;
    };
    stored.starts_with(V2_PREFIX) || stored.starts_with(V1_PREFIX)
}

pub fn encrypt_file(path: &Path, password: &str, version: EncryptionVersion) -> Result<()> {
    let data = fs::read(path)?;
    if looks_encrypted(&data) {
        return Ok(());
    }
    let encoded = encrypt(&data, password, version)?;
    fs::write(path, encoded)?;
    Ok(())
}

pub fn decrypt_file(path: &Path, password: &str) -> Result<()> {
    let data = fs::read(path)?;
    if !looks_encrypted(&data) {
        return Ok(());
    }
    let text = std::str::from_utf8(&data)
        .map_err(|_| Error::Crypto(format!("{} is not valid text", path.display())))?;
    let plain = decrypt(text, password)
        .map_err(|err| Error::Crypto(format!("cannot decrypt {}: {err}", path.display())))?;
    fs::write(path, plain)?;
    Ok(())
}

pub fn encrypt_tree(dir: &Path, password: &str, version: EncryptionVersion) -> Result<()> {
    for path in signing_files(dir)? {
        encrypt_file(&path, password, version)?;
    }
    Ok(())
}

pub fn decrypt_tree(dir: &Path, password: &str) -> Result<()> {
    for path in signing_files(dir)? {
        decrypt_file(&path, password)?;
    }
    Ok(())
}

pub fn signing_files(dir: &Path) -> Result<Vec<std::path::PathBuf>> {
    let mut files = Vec::new();
    collect_signing_files(dir, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_signing_files(dir: &Path, files: &mut Vec<std::path::PathBuf>) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_signing_files(&path, files)?;
        } else if is_signing_file(&path) {
            files.push(path);
        }
    }
    Ok(())
}

fn is_signing_file(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| SIGNING_EXTENSIONS.iter().any(|candidate| candidate == &ext))
}

fn encrypt_v1(data: &[u8], password: &[u8], salt: &[u8]) -> Result<Vec<u8>> {
    let (key, iv) = evp_bytes_to_key(password, salt, MessageDigest::md5(), 32, 16)?;
    let ciphertext = aes_256_cbc_encrypt(&key, &iv, data)?;
    let mut body = Vec::with_capacity(16 + ciphertext.len());
    body.extend_from_slice(V1_PREFIX);
    body.extend_from_slice(salt);
    body.extend_from_slice(&ciphertext);
    Ok(body)
}

fn decrypt_v1(stored: &[u8], password: &[u8]) -> Result<Vec<u8>> {
    if stored.len() < 16 {
        return Err(Error::Crypto("truncated Salted__ payload".into()));
    }
    let salt = &stored[8..16];
    let ciphertext = &stored[16..];
    let md5 = decrypt_v1_with(password, salt, ciphertext, MessageDigest::md5());
    if let Ok(plain) = md5 {
        return Ok(plain);
    }
    decrypt_v1_with(password, salt, ciphertext, MessageDigest::sha256())
        .map_err(|_| Error::Crypto("cannot decrypt Salted__ payload. Check MATCH_PASSWORD".into()))
}

fn decrypt_v1_with(
    password: &[u8],
    salt: &[u8],
    ciphertext: &[u8],
    digest: MessageDigest,
) -> Result<Vec<u8>> {
    let (key, iv) = evp_bytes_to_key(password, salt, digest, 32, 16)?;
    aes_256_cbc_decrypt(&key, &iv, ciphertext)
}

fn encrypt_v2(data: &[u8], password: &[u8], salt: &[u8]) -> Result<Vec<u8>> {
    let (key, iv, aad) = derive_v2(password, salt)?;
    let (ciphertext, tag) = aes_256_gcm_encrypt(&key, &iv, &aad, data)?;
    let mut body = Vec::with_capacity(V2_PREFIX.len() + 8 + 16 + ciphertext.len());
    body.extend_from_slice(V2_PREFIX);
    body.extend_from_slice(salt);
    body.extend_from_slice(&tag);
    body.extend_from_slice(&ciphertext);
    Ok(body)
}

fn decrypt_v2(stored: &[u8], password: &[u8]) -> Result<Vec<u8>> {
    if stored.len() < V2_PREFIX.len() + 8 + 16 {
        return Err(Error::Crypto(
            "truncated match_encrypted_v2__ payload".into(),
        ));
    }
    let salt = &stored[V2_PREFIX.len()..V2_PREFIX.len() + 8];
    let tag = &stored[V2_PREFIX.len() + 8..V2_PREFIX.len() + 24];
    let ciphertext = &stored[V2_PREFIX.len() + 24..];
    let (key, iv, aad) = derive_v2(password, salt)?;
    aes_256_gcm_decrypt(&key, &iv, &aad, ciphertext, tag)
        .map_err(|_| Error::Crypto("cannot decrypt match v2 payload. Check MATCH_PASSWORD".into()))
}

fn derive_v2(password: &[u8], salt: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let mut material = vec![0u8; 32 + 12 + 24];
    pbkdf2_hmac(
        password,
        salt,
        10_000,
        MessageDigest::sha256(),
        &mut material,
    )?;
    let key = material[..32].to_vec();
    let iv = material[32..44].to_vec();
    let aad = material[44..].to_vec();
    Ok((key, iv, aad))
}

/// OpenSSL `EVP_BytesToKey` with the requested digest and a single iteration.
fn evp_bytes_to_key(
    password: &[u8],
    salt: &[u8],
    digest: MessageDigest,
    key_len: usize,
    iv_len: usize,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut derived = Vec::new();
    let mut previous = Vec::new();
    while derived.len() < key_len + iv_len {
        let mut hasher = openssl::hash::Hasher::new(digest)?;
        if !previous.is_empty() {
            hasher.update(&previous)?;
        }
        hasher.update(password)?;
        hasher.update(salt)?;
        previous = hasher.finish()?.to_vec();
        derived.extend_from_slice(&previous);
    }
    let key = derived[..key_len].to_vec();
    let iv = derived[key_len..key_len + iv_len].to_vec();
    Ok((key, iv))
}

fn aes_256_cbc_encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let cipher = Cipher::aes_256_cbc();
    let mut crypter = Crypter::new(cipher, Mode::Encrypt, key, Some(iv))?;
    let mut out = vec![0u8; data.len() + cipher.block_size()];
    let mut written = crypter.update(data, &mut out)?;
    written += crypter.finalize(&mut out[written..])?;
    out.truncate(written);
    Ok(out)
}

fn aes_256_cbc_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let cipher = Cipher::aes_256_cbc();
    let mut crypter = Crypter::new(cipher, Mode::Decrypt, key, Some(iv))?;
    let mut out = vec![0u8; data.len() + cipher.block_size()];
    let mut written = crypter.update(data, &mut out)?;
    written += crypter.finalize(&mut out[written..])?;
    out.truncate(written);
    Ok(out)
}

fn aes_256_gcm_encrypt(
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    data: &[u8],
) -> Result<(Vec<u8>, [u8; 16])> {
    let cipher = Cipher::aes_256_gcm();
    let mut crypter = Crypter::new(cipher, Mode::Encrypt, key, Some(iv))?;
    crypter.aad_update(aad)?;
    let mut out = vec![0u8; data.len() + cipher.block_size()];
    let mut written = crypter.update(data, &mut out)?;
    written += crypter.finalize(&mut out[written..])?;
    out.truncate(written);
    let mut tag = [0u8; 16];
    crypter.get_tag(&mut tag)?;
    Ok((out, tag))
}

fn aes_256_gcm_decrypt(
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    data: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Cipher::aes_256_gcm();
    let mut crypter = Crypter::new(cipher, Mode::Decrypt, key, Some(iv))?;
    crypter.aad_update(aad)?;
    let mut out = vec![0u8; data.len() + cipher.block_size()];
    let mut written = crypter.update(data, &mut out)?;
    crypter.set_tag(tag)?;
    written += crypter.finalize(&mut out[written..])?;
    out.truncate(written);
    Ok(out)
}

/// Ruby `Base64.encode64`: 60-character lines and a trailing newline.
fn encode_match_base64(data: &[u8]) -> String {
    let raw = STANDARD.encode(data);
    let mut out = String::with_capacity(raw.len() + raw.len() / 60 + 1);
    for (index, chunk) in raw.as_bytes().chunks(60).enumerate() {
        if index > 0 {
            out.push('\n');
        }
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ascii"));
    }
    out.push('\n');
    out
}

fn decode_match_base64(text: &str) -> Result<Vec<u8>> {
    let cleaned: String = text.chars().filter(|ch| !ch.is_whitespace()).collect();
    STANDARD
        .decode(cleaned)
        .map_err(|err| Error::Crypto(format!("payload is not base64: {err}")))
}
