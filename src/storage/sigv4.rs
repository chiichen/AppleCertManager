use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

pub struct SignInput<'a> {
    pub method: &'a str,
    pub uri: &'a str,
    pub query: &'a [(&'a str, &'a str)],
    pub host: &'a str,
    pub extra_headers: &'a [(&'a str, &'a str)],
    pub payload: &'a [u8],
    pub access_key: &'a str,
    pub secret_key: &'a str,
    pub region: &'a str,
    pub service: &'a str,
    /// `YYYYMMDDTHHMMSSZ`.
    pub amz_date: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedHeaders {
    pub authorization: String,
    pub content_sha256: String,
    pub amz_date: String,
    pub signature: String,
    pub canonical_request: String,
}

pub fn sign_request(input: &SignInput<'_>) -> SignedHeaders {
    let content_sha256 = hex::encode(Sha256::digest(input.payload));
    let mut headers = vec![
        ("host", input.host.trim()),
        ("x-amz-content-sha256", content_sha256.as_str()),
        ("x-amz-date", input.amz_date),
    ];
    for (name, value) in input.extra_headers {
        headers.push((name, value.trim()));
    }
    headers.sort_by(|left, right| {
        left.0
            .to_ascii_lowercase()
            .cmp(&right.0.to_ascii_lowercase())
    });

    let canonical_headers = headers
        .iter()
        .map(|(name, value)| format!("{}:{value}\n", name.to_ascii_lowercase()))
        .collect::<String>();
    let signed_headers = headers
        .iter()
        .map(|(name, _)| name.to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(";");
    let canonical_query = canonical_query(input.query);
    let canonical_request = format!(
        "{}\n{}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{content_sha256}",
        input.method,
        canonical_uri(input.uri)
    );
    let date = &input.amz_date[..8];
    let scope = format!("{date}/{}/{}/aws4_request", input.region, input.service);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{scope}\n{}",
        input.amz_date,
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );
    let signing_key = signing_key(input.secret_key, date, input.region, input.service);
    let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes()));
    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
        input.access_key
    );
    SignedHeaders {
        authorization,
        content_sha256,
        amz_date: input.amz_date.to_string(),
        signature,
        canonical_request,
    }
}

pub(crate) fn canonical_uri(path: &str) -> String {
    let path = if path.is_empty() { "/" } else { path };
    let encoded = path
        .split('/')
        .map(|segment| uri_encode(segment, true))
        .collect::<Vec<_>>()
        .join("/");
    if encoded.starts_with('/') {
        encoded
    } else {
        format!("/{encoded}")
    }
}

pub(crate) fn uri_encode(value: &str, encode_slash: bool) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            b'/' if !encode_slash => out.push('/'),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn canonical_query(query: &[(&str, &str)]) -> String {
    let mut pairs = query
        .iter()
        .map(|(name, value)| (uri_encode(name, true), uri_encode(value, true)))
        .collect::<Vec<_>>();
    pairs.sort();
    pairs
        .into_iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn signing_key(secret: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let date_key = hmac_sha256(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    let region_key = hmac_sha256(&date_key, region.as_bytes());
    let service_key = hmac_sha256(&region_key, service.as_bytes());
    hmac_sha256(&service_key, b"aws4_request")
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}
