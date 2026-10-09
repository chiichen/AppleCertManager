use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};

use acm_error::Result;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    iss: String,
    iat: i64,
    exp: i64,
    aud: String,
}

/// Build the ES256 bearer token Apple expects.
///
/// `now` is a unix timestamp. The token expires 15 minutes later, inside
/// Apple's 20 minute limit.
pub fn issue_token(key_id: &str, issuer_id: &str, pem: &[u8], now: i64) -> Result<String> {
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(key_id.to_string());
    header.typ = Some("JWT".to_string());
    let claims = Claims {
        iss: issuer_id.to_string(),
        iat: now,
        exp: now + 15 * 60,
        aud: "appstoreconnect-v1".to_string(),
    };
    Ok(encode(&header, &claims, &EncodingKey::from_ec_pem(pem)?)?)
}
