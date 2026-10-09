use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

use apple_cert_manager::crypto::KeyMaterial;
use apple_cert_manager::portal::{CreateProfile, FakePortal, Portal};
use apple_cert_manager::{portal::issue_token, portal::ConnectClient};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::PKey;
use serde::Deserialize;

#[test]
fn token_is_an_es256_jwt_for_app_store_connect() {
    let pem = p256_pem();
    let public_pem = {
        let key = PKey::private_key_from_pem(&pem).unwrap();
        key.public_key_to_pem().unwrap()
    };
    let token = issue_token("KEYID123456", "issuer-1", &pem, 1_700_000_000).unwrap();
    assert_eq!(token.split('.').count(), 3);

    #[derive(Deserialize)]
    struct Claims {
        iss: String,
        aud: String,
        iat: i64,
        exp: i64,
    }
    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_issuer(&["issuer-1"]);
    validation.set_audience(&["appstoreconnect-v1"]);
    validation.validate_exp = false;
    let header = jsonwebtoken::decode_header(&token).unwrap();
    assert_eq!(header.kid.as_deref(), Some("KEYID123456"));
    let data = decode::<Claims>(
        &token,
        &DecodingKey::from_ec_pem(&public_pem).unwrap(),
        &validation,
    )
    .unwrap();
    assert_eq!(data.claims.iss, "issuer-1");
    assert_eq!(data.claims.aud, "appstoreconnect-v1");
    assert_eq!(data.claims.exp - data.claims.iat, 15 * 60);
}

#[test]
fn fake_portal_signs_the_csr_and_builds_a_profile() {
    let portal = FakePortal::new("TEAMID1234").unwrap();
    let key = KeyMaterial::generate().unwrap();
    let csr = key.csr_pem("Apple Development: Gov").unwrap();
    let certificate = portal.create_certificate("IOS_DEVELOPMENT", &csr).unwrap();
    let p12 = key.export_p12(&certificate.certificate_der, "").unwrap();
    assert!(!p12.is_empty());

    let bundle = portal
        .create_bundle_id("政务门户", "com.example.portal", "IOS")
        .unwrap();
    assert_eq!(
        portal
            .create_bundle_id("again", "com.example.portal", "IOS")
            .unwrap()
            .id,
        bundle.id
    );
    let device = portal
        .register_device("iPhone of Gov", "00008030-001C25E40A68802E", "IOS")
        .unwrap();
    assert_eq!(
        portal
            .register_device("renamed", "00008030-001c25e40a68802e", "IOS")
            .unwrap()
            .id,
        device.id
    );

    let profile = portal
        .create_profile(&CreateProfile {
            name: "match Development com.example.portal".into(),
            profile_type: "IOS_APP_DEVELOPMENT".into(),
            bundle_id_id: bundle.id.clone(),
            certificate_ids: vec![certificate.id.clone()],
            device_ids: vec![device.id.clone()],
        })
        .unwrap();
    let text = String::from_utf8(profile.content.clone()).unwrap();
    assert!(text.contains(&profile.uuid));
    assert!(text.contains("00008030-001C25E40A68802E"));
    assert!(text.contains("TEAMID1234"));
    assert!(portal
        .create_profile(&CreateProfile {
            name: profile.name.clone(),
            profile_type: profile.profile_type.clone(),
            bundle_id_id: bundle.id,
            certificate_ids: vec![certificate.id.clone()],
            device_ids: vec![device.id],
        })
        .is_err());

    portal.revoke_certificate(&certificate.id).unwrap();
    assert!(portal.list_certificates().unwrap().is_empty());
    assert!(portal.list_profiles().unwrap().is_empty());
}

#[test]
fn connect_client_follows_certificate_pages() {
    let pem = p256_pem();
    let base = serve(2, |request| {
        assert!(request.authorization.starts_with("Bearer "));
        assert_eq!(request.authorization.split('.').count(), 3);
        if request.path.contains("cursor=2") {
            json_response(
                200,
                r#"{"data":[{"type":"certificates","id":"CERTB","attributes":{"certificateType":"IOS_DISTRIBUTION","displayName":"Apple Distribution","certificateContent":"aGVsbG8="}}]}"#,
            )
        } else {
            json_response(
                200,
                r#"{"data":[{"type":"certificates","id":"CERTA","attributes":{"certificateType":"IOS_DEVELOPMENT","displayName":"Apple Development","certificateContent":""}}],"links":{"next":"/v1/certificates?cursor=2"}}"#,
            )
        }
    });
    let client = ConnectClient::new("KEYID123456".into(), "issuer-1".into(), pem)
        .unwrap()
        .with_base_url(base);
    let certificates = client.list_certificates().unwrap();
    assert_eq!(certificates.len(), 2);
    assert_eq!(certificates[0].id, "CERTA");
    assert_eq!(certificates[1].certificate_type, "IOS_DISTRIBUTION");
    assert_eq!(certificates[1].certificate_der, b"hello");
}

#[test]
fn connect_client_reuses_an_existing_device_after_conflict() {
    let pem = p256_pem();
    let base = serve(2, |request| {
        if request.method == "POST" {
            json_response(
                409,
                r#"{"errors":[{"title":"Conflict","detail":"A device with this UDID already exists."}]}"#,
            )
        } else {
            json_response(
                200,
                r#"{"data":[{"type":"devices","id":"DEV1","attributes":{"name":"iPhone of Gov","udid":"00008030-001C25E40A68802E","platform":"IOS","status":"ENABLED"}}]}"#,
            )
        }
    });
    let client = ConnectClient::new("KEYID123456".into(), "issuer-1".into(), pem)
        .unwrap()
        .with_base_url(base);
    let device = client
        .register_device("iPhone of Gov", "00008030-001C25E40A68802E", "IOS")
        .unwrap();
    assert_eq!(device.id, "DEV1");
    assert!(device.enabled);
}

#[test]
fn connect_client_posts_a_certificate_request() {
    let pem = p256_pem();
    let base = serve(1, |request| {
        assert_eq!(request.method, "POST");
        assert!(request.path.starts_with("/v1/certificates"));
        let body = String::from_utf8(request.body.clone()).unwrap();
        assert!(body.contains("IOS_DISTRIBUTION"), "{body}");
        assert!(body.contains("BEGIN CERTIFICATE REQUEST"), "{body}");
        json_response(
            201,
            r#"{"data":{"type":"certificates","id":"CERT9","attributes":{"certificateType":"IOS_DISTRIBUTION","displayName":"Apple Distribution","certificateContent":"Y2VydA=="}}}"#,
        )
    });
    let client = ConnectClient::new("KEYID123456".into(), "issuer-1".into(), pem)
        .unwrap()
        .with_base_url(base);
    let certificate = client
        .create_certificate(
            "IOS_DISTRIBUTION",
            "-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----\n",
        )
        .unwrap();
    assert_eq!(certificate.id, "CERT9");
    assert_eq!(certificate.certificate_der, b"cert");
}

struct Incoming {
    method: String,
    path: String,
    authorization: String,
    body: Vec<u8>,
}

fn serve(accepts: usize, handler: impl Fn(&Incoming) -> (u16, String) + Send + 'static) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for _ in 0..accepts {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let request = read_http(&mut socket).unwrap();
            let (status, body) = handler(&request);
            let header = format!(
                "HTTP/1.1 {status} OK\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: application/json\r\n\r\n",
                body.len()
            );
            socket.write_all(header.as_bytes()).unwrap();
            socket.write_all(body.as_bytes()).unwrap();
        }
    });
    format!("http://127.0.0.1:{port}")
}

fn json_response(status: u16, body: &str) -> (u16, String) {
    (status, body.to_string())
}

fn read_http(socket: &mut impl Read) -> std::io::Result<Incoming> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        if socket.read(&mut byte)? == 0 {
            break;
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let header = String::from_utf8_lossy(&buf).into_owned();
    let mut lines = header.lines();
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();
    let mut content_length = 0usize;
    let mut authorization = String::new();
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value.trim().parse().unwrap_or(0);
        } else if name.eq_ignore_ascii_case("authorization") {
            authorization = value.trim().to_string();
        }
    }
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        socket.read_exact(&mut body)?;
    }
    Ok(Incoming {
        method,
        path,
        authorization,
        body,
    })
}

fn p256_pem() -> Vec<u8> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let key = EcKey::generate(&group).unwrap();
    PKey::from_ec_key(key)
        .unwrap()
        .private_key_to_pem_pkcs8()
        .unwrap()
}
