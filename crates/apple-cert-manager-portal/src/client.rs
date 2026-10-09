use std::sync::Mutex;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::Utc;
use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde_json::{json, Value};

use super::jwt::issue_token;
use super::model::{
    CreateProfile, Portal, PortalBundleId, PortalCertificate, PortalDevice, PortalProfile,
};
use apple_cert_manager_config::Config;
use apple_cert_manager_error::{Error, Result};

const TOKEN_TTL_SECS: i64 = 15 * 60;

struct CachedToken {
    value: String,
    exp: i64,
}

pub struct ConnectClient {
    base_url: String,
    key_id: String,
    issuer_id: String,
    key_pem: Vec<u8>,
    http: Client,
    token: Mutex<Option<CachedToken>>,
}

impl ConnectClient {
    pub fn from_config(config: &Config) -> Result<Self> {
        config.require_apple()?;
        Self::new(
            config.apple.key_id.clone(),
            config.apple.issuer_id.clone(),
            config.apple_key_pem()?,
        )
    }

    pub fn new(key_id: String, issuer_id: String, key_pem: Vec<u8>) -> Result<Self> {
        if key_id.is_empty() || issuer_id.is_empty() || key_pem.is_empty() {
            return Err(Error::Config(
                "App Store Connect key id, issuer id, and API key are required".into(),
            ));
        }
        let http = Client::builder()
            .timeout(Duration::from_secs(60))
            .no_proxy()
            .build()?;
        Ok(Self {
            base_url: "https://api.appstoreconnect.apple.com".into(),
            key_id,
            issuer_id,
            key_pem,
            http,
            token: Mutex::new(None),
        })
    }

    /// Point the client at a stand-in server. The path layout stays `/v1/...`.
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into().trim_end_matches('/').to_string();
        self
    }

    fn bearer(&self) -> Result<String> {
        let now = Utc::now().timestamp();
        let mut cached = self.token.lock().expect("token lock");
        if let Some(token) = cached.as_ref() {
            if token.exp - 60 > now {
                return Ok(token.value.clone());
            }
        }
        let value = issue_token(&self.key_id, &self.issuer_id, &self.key_pem, now)?;
        *cached = Some(CachedToken {
            value: value.clone(),
            exp: now + TOKEN_TTL_SECS,
        });
        Ok(value)
    }

    fn send(
        &self,
        method: &str,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> Result<(StatusCode, Vec<u8>)> {
        let token = self.bearer()?;
        let http_method = reqwest::Method::from_bytes(method.as_bytes())
            .map_err(|err| Error::Portal(format!("{err}")))?;
        let mut request = self
            .http
            .request(http_method, url)
            .header("Authorization", format!("Bearer {token}"))
            .header("Accept", "application/json");
        if let Some(body) = body {
            request = request
                .header("Content-Type", "application/json")
                .body(body);
        }
        let response = request.send()?;
        let status = response.status();
        let bytes = response.bytes()?.to_vec();
        if status.is_success() {
            return Ok((status, bytes));
        }
        let detail = api_error_message(&bytes);
        Err(Error::Portal(format!("{status} {detail}")))
    }

    fn get_collection(&self, path_and_query: &str) -> Result<Vec<Value>> {
        let mut url = format!("{}{path_and_query}", self.base_url);
        let mut items = Vec::new();
        for _ in 0..200 {
            let (_status, body) = self.send("GET", &url, None)?;
            let value: Value = serde_json::from_slice(&body)?;
            if let Some(data) = value.get("data").and_then(Value::as_array) {
                items.extend(data.clone());
            }
            let next = value
                .get("links")
                .and_then(|links| links.get("next"))
                .and_then(Value::as_str)
                .filter(|next| !next.is_empty());
            match next {
                Some(next) => url = self.absolute(next),
                None => break,
            }
        }
        Ok(items)
    }

    fn post_resource(&self, path: &str, body: Value) -> Result<Value> {
        let url = format!("{}{path}", self.base_url);
        let (_status, bytes) = self.send("POST", &url, Some(serde_json::to_vec(&body)?))?;
        let value: Value = serde_json::from_slice(&bytes)?;
        value
            .get("data")
            .cloned()
            .ok_or_else(|| Error::Portal(format!("Apple response for {path} has no data")))
    }

    fn delete_resource(&self, path: &str) -> Result<()> {
        let url = format!("{}{path}", self.base_url);
        self.send("DELETE", &url, None)?;
        Ok(())
    }

    fn absolute(&self, url: &str) -> String {
        if url.starts_with("http://") || url.starts_with("https://") {
            url.to_string()
        } else if let Some(path) = url.strip_prefix('/') {
            format!("{}/{path}", self.base_url)
        } else {
            format!("{}/{url}", self.base_url)
        }
    }

    fn is_conflict(err: &Error) -> bool {
        matches!(err, Error::Portal(message) if message.starts_with("409"))
    }
}

impl Portal for ConnectClient {
    fn list_certificates(&self) -> Result<Vec<PortalCertificate>> {
        self.get_collection("/v1/certificates?limit=200")?
            .iter()
            .map(parse_certificate)
            .collect()
    }

    fn create_certificate(
        &self,
        certificate_type: &str,
        csr_pem: &str,
    ) -> Result<PortalCertificate> {
        let body = json!({
            "data": {
                "type": "certificates",
                "attributes": {
                    "certificateType": certificate_type,
                    "csrContent": csr_pem,
                }
            }
        });
        parse_certificate(&self.post_resource("/v1/certificates", body)?)
    }

    fn revoke_certificate(&self, id: &str) -> Result<()> {
        self.delete_resource(&format!("/v1/certificates/{id}"))
    }

    fn list_bundle_ids(&self) -> Result<Vec<PortalBundleId>> {
        self.get_collection("/v1/bundleIds?limit=200")?
            .iter()
            .map(parse_bundle_id)
            .collect()
    }

    fn create_bundle_id(
        &self,
        name: &str,
        identifier: &str,
        platform: &str,
    ) -> Result<PortalBundleId> {
        let body = json!({
            "data": {
                "type": "bundleIds",
                "attributes": {
                    "name": name,
                    "identifier": identifier,
                    "platform": platform,
                }
            }
        });
        match self.post_resource("/v1/bundleIds", body) {
            Ok(resource) => parse_bundle_id(&resource),
            Err(err) if Self::is_conflict(&err) => self
                .list_bundle_ids()?
                .into_iter()
                .find(|bundle| bundle.identifier == identifier)
                .ok_or(err),
            Err(err) => Err(err),
        }
    }

    fn list_devices(&self) -> Result<Vec<PortalDevice>> {
        self.get_collection("/v1/devices?limit=200")?
            .iter()
            .map(parse_device)
            .collect()
    }

    fn register_device(&self, name: &str, udid: &str, platform: &str) -> Result<PortalDevice> {
        let body = json!({
            "data": {
                "type": "devices",
                "attributes": {
                    "name": name,
                    "udid": udid,
                    "platform": platform,
                }
            }
        });
        match self.post_resource("/v1/devices", body) {
            Ok(resource) => parse_device(&resource),
            Err(err) if Self::is_conflict(&err) => self
                .list_devices()?
                .into_iter()
                .find(|device| device.udid.eq_ignore_ascii_case(udid))
                .ok_or(err),
            Err(err) => Err(err),
        }
    }

    fn list_profiles(&self) -> Result<Vec<PortalProfile>> {
        let url = "/v1/profiles?limit=200&include=bundleId,certificates,devices";
        let mut page = format!("{}{url}", self.base_url);
        let mut profiles = Vec::new();
        for _ in 0..200 {
            let (_status, body) = self.send("GET", &page, None)?;
            let value: Value = serde_json::from_slice(&body)?;
            let included = value
                .get("included")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            if let Some(data) = value.get("data").and_then(Value::as_array) {
                for resource in data {
                    profiles.push(parse_profile(resource, &included)?);
                }
            }
            let next = value
                .get("links")
                .and_then(|links| links.get("next"))
                .and_then(Value::as_str)
                .filter(|next| !next.is_empty());
            match next {
                Some(next) => page = self.absolute(next),
                None => break,
            }
        }
        Ok(profiles)
    }

    fn create_profile(&self, request: &CreateProfile) -> Result<PortalProfile> {
        let certificates: Vec<Value> = request
            .certificate_ids
            .iter()
            .map(|id| json!({"type": "certificates", "id": id}))
            .collect();
        let mut relationships = json!({
            "bundleId": {"data": {"type": "bundleIds", "id": request.bundle_id_id}},
            "certificates": {"data": certificates},
        });
        if !request.device_ids.is_empty() {
            let devices: Vec<Value> = request
                .device_ids
                .iter()
                .map(|id| json!({"type": "devices", "id": id}))
                .collect();
            relationships["devices"] = json!({"data": devices});
        }
        let body = json!({
            "data": {
                "type": "profiles",
                "attributes": {
                    "name": request.name,
                    "profileType": request.profile_type,
                },
                "relationships": relationships,
            }
        });
        let resource = self.post_resource("/v1/profiles", body)?;
        parse_profile(&resource, &[])
    }

    fn delete_profile(&self, id: &str) -> Result<()> {
        self.delete_resource(&format!("/v1/profiles/{id}"))
    }
}

fn parse_certificate(value: &Value) -> Result<PortalCertificate> {
    let attributes = &value["attributes"];
    Ok(PortalCertificate {
        id: required_id(value)?,
        certificate_type: attr_string(attributes, "certificateType"),
        display_name: attr_string(attributes, "displayName"),
        certificate_der: decode_content(attributes, "certificateContent")?,
    })
}

fn parse_bundle_id(value: &Value) -> Result<PortalBundleId> {
    let attributes = &value["attributes"];
    Ok(PortalBundleId {
        id: required_id(value)?,
        name: attr_string(attributes, "name"),
        identifier: attr_string(attributes, "identifier"),
        platform: attr_string(attributes, "platform"),
    })
}

fn parse_device(value: &Value) -> Result<PortalDevice> {
    let attributes = &value["attributes"];
    let status = attr_string(attributes, "status");
    Ok(PortalDevice {
        id: required_id(value)?,
        name: attr_string(attributes, "name"),
        udid: attr_string(attributes, "udid"),
        platform: attr_string(attributes, "platform"),
        enabled: status.is_empty() || status.eq_ignore_ascii_case("enabled"),
    })
}

fn parse_profile(value: &Value, included: &[Value]) -> Result<PortalProfile> {
    let attributes = &value["attributes"];
    let bundle_id_id = relationship_id(value, "bundleId").unwrap_or_default();
    let bundle_identifier = included
        .iter()
        .find(|item| item["type"] == "bundleIds" && item["id"] == bundle_id_id)
        .map(|item| attr_string(&item["attributes"], "identifier"))
        .unwrap_or_default();
    Ok(PortalProfile {
        id: required_id(value)?,
        name: attr_string(attributes, "name"),
        profile_type: attr_string(attributes, "profileType"),
        uuid: attr_string(attributes, "uuid"),
        bundle_identifier,
        bundle_id_id,
        certificate_ids: relationship_ids(value, "certificates"),
        device_ids: relationship_ids(value, "devices"),
        content: decode_content(attributes, "profileContent")?,
    })
}

fn required_id(value: &Value) -> Result<String> {
    value
        .get("id")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| Error::Portal("Apple resource is missing an id".into()))
}

fn attr_string(attributes: &Value, name: &str) -> String {
    attributes
        .get(name)
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

fn relationship_id(value: &Value, name: &str) -> Option<String> {
    value["relationships"][name]["data"]["id"]
        .as_str()
        .map(str::to_string)
}

fn relationship_ids(value: &Value, name: &str) -> Vec<String> {
    value["relationships"][name]["data"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.get("id").and_then(Value::as_str).map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn decode_content(attributes: &Value, name: &str) -> Result<Vec<u8>> {
    let Some(content) = attributes.get(name).and_then(Value::as_str) else {
        return Ok(Vec::new());
    };
    if content.is_empty() {
        return Ok(Vec::new());
    }
    let cleaned: String = content.chars().filter(|ch| !ch.is_whitespace()).collect();
    STANDARD
        .decode(cleaned)
        .map_err(|err| Error::Portal(format!("cannot decode {name}: {err}")))
}

fn api_error_message(body: &[u8]) -> String {
    let Ok(value) = serde_json::from_slice::<Value>(body) else {
        let text = String::from_utf8_lossy(body);
        return text.chars().take(400).collect();
    };
    let Some(errors) = value.get("errors").and_then(Value::as_array) else {
        return "request failed".into();
    };
    errors
        .iter()
        .map(|error| {
            let title = error.get("title").and_then(Value::as_str).unwrap_or("");
            let detail = error.get("detail").and_then(Value::as_str).unwrap_or("");
            format!("{title} {detail}").trim().to_string()
        })
        .collect::<Vec<_>>()
        .join("; ")
}
