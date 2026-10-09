use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkcs12::Pkcs12;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::{X509NameBuilder, X509ReqBuilder, X509};

use apple_cert_manager_error::Result;

/// RSA key kept as PKCS#8 PEM so it can live only in memory while a
/// certificate is requested from Apple.
pub struct KeyMaterial {
    pem: Vec<u8>,
}

impl KeyMaterial {
    pub fn generate() -> Result<Self> {
        let rsa = Rsa::generate(2048)?;
        let pkey = PKey::from_rsa(rsa)?;
        Ok(Self {
            pem: pkey.private_key_to_pem_pkcs8()?,
        })
    }

    pub fn csr_pem(&self, common_name: &str) -> Result<String> {
        let pkey = self.pkey()?;
        let mut name = X509NameBuilder::new()?;
        name.append_entry_by_text("CN", common_name)?;
        let mut builder = X509ReqBuilder::new()?;
        builder.set_pubkey(&pkey)?;
        builder.set_subject_name(&name.build())?;
        builder.sign(&pkey, MessageDigest::sha256())?;
        let pem = builder.build().to_pem()?;
        String::from_utf8(pem).map_err(|err| apple_cert_manager_error::Error::msg(err.to_string()))
    }

    /// Build a PKCS#12 archive. Match stores these with an empty password and
    /// then encrypts the file with `MATCH_PASSWORD`.
    ///
    /// OpenSSL 3 encrypts new archives with PBES2 AES-256 and a SHA-256 MAC.
    /// `SecPKCS12Import` rejects that as a wrong passphrase. The SHA-1 / 3DES
    /// algorithms are what `openssl pkcs12 -legacy` emits and what the macOS
    /// keychain imports.
    pub fn export_p12(&self, certificate: &[u8], password: &str) -> Result<Vec<u8>> {
        let pkey = self.pkey()?;
        let cert = parse_certificate(certificate)?;
        let mut builder = Pkcs12::builder();
        builder
            .name("apple-cert-manager")
            .pkey(&pkey)
            .cert(&cert)
            .key_algorithm(Nid::PBE_WITHSHA1AND3_KEY_TRIPLEDES_CBC)
            .cert_algorithm(Nid::PBE_WITHSHA1AND3_KEY_TRIPLEDES_CBC)
            .mac_md(MessageDigest::sha1());
        let p12 = builder.build2(password)?;
        Ok(p12.to_der()?)
    }

    fn pkey(&self) -> Result<PKey<Private>> {
        Ok(PKey::private_key_from_pem(&self.pem)?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateInfo {
    pub common_name: String,
    pub organization_unit: String,
    pub not_before: String,
    pub not_after: String,
    pub valid: bool,
}

pub fn inspect_certificate(bytes: &[u8]) -> Result<CertificateInfo> {
    let cert = parse_certificate(bytes)?;
    let now = Asn1Time::days_from_now(0)?;
    let not_before = cert.not_before();
    let not_after = cert.not_after();
    let started = not_before.compare(&now)? != std::cmp::Ordering::Greater;
    let unexpired = not_after.compare(&now)? == std::cmp::Ordering::Greater;
    Ok(CertificateInfo {
        common_name: name_entry(&cert, Nid::COMMONNAME),
        organization_unit: name_entry(&cert, Nid::ORGANIZATIONALUNITNAME),
        not_before: not_before.to_string(),
        not_after: not_after.to_string(),
        valid: started && unexpired,
    })
}

pub fn self_signed_certificate(key: &KeyMaterial, common_name: &str) -> Result<Vec<u8>> {
    let pkey = key.pkey()?;
    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_text("CN", common_name)?;
    name.append_entry_by_text("OU", "TEAMID1234")?;
    let name = name.build();
    let mut builder = X509::builder()?;
    builder.set_version(2)?;
    builder.set_subject_name(&name)?;
    builder.set_issuer_name(&name)?;
    builder.set_pubkey(&pkey)?;
    builder.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
    builder.set_not_after(Asn1Time::days_from_now(365)?.as_ref())?;
    builder.sign(&pkey, MessageDigest::sha256())?;
    Ok(builder.build().to_der()?)
}

fn parse_certificate(bytes: &[u8]) -> Result<X509> {
    if bytes.starts_with(b"-----BEGIN") {
        Ok(X509::from_pem(bytes)?)
    } else {
        Ok(X509::from_der(bytes)?)
    }
}

fn name_entry(cert: &X509, nid: Nid) -> String {
    cert.subject_name()
        .entries_by_nid(nid)
        .find_map(|entry| entry.data().to_string().ok())
        .unwrap_or_default()
}
