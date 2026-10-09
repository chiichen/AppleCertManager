use std::time::Duration;

use chrono::{DateTime, Utc};
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue};

use super::object::ObjectStore;
use super::sigv4::{sign_request, SignInput};
use apple_cert_manager_config::S3StorageConfig;
use apple_cert_manager_error::{Error, Result};

pub struct S3Client {
    bucket: String,
    region: String,
    endpoint: String,
    host: String,
    path_style: bool,
    access_key: String,
    secret_key: String,
    http: Client,
}

impl S3Client {
    pub fn from_config(config: &S3StorageConfig) -> Result<Self> {
        let access_key = std::env::var(&config.access_key_env).map_err(|_| {
            Error::Config(format!(
                "S3 access key is missing. Set {}",
                config.access_key_env
            ))
        })?;
        let secret_key = std::env::var(&config.secret_key_env).map_err(|_| {
            Error::Config(format!(
                "S3 secret key is missing. Set {}",
                config.secret_key_env
            ))
        })?;
        if access_key.is_empty() || secret_key.is_empty() {
            return Err(Error::Config(
                "S3 credentials are empty. Set the access key and secret key environment variables"
                    .into(),
            ));
        }
        Self::new(
            config.bucket.clone(),
            config.region.clone(),
            config.endpoint.clone(),
            config.use_path_style(),
            access_key,
            secret_key,
        )
    }

    pub fn new(
        bucket: String,
        region: String,
        endpoint: Option<String>,
        path_style: bool,
        access_key: String,
        secret_key: String,
    ) -> Result<Self> {
        let (endpoint, host) = match endpoint {
            Some(endpoint) => {
                let host = endpoint
                    .trim_end_matches('/')
                    .split("://")
                    .nth(1)
                    .unwrap_or(endpoint.trim_end_matches('/'))
                    .to_string();
                (endpoint.trim_end_matches('/').to_string(), host)
            }
            None if path_style => {
                let host = format!("s3.{region}.amazonaws.com");
                (format!("https://{host}"), host)
            }
            None => {
                let host = format!("{bucket}.s3.{region}.amazonaws.com");
                (format!("https://{host}"), host)
            }
        };
        let http = Client::builder()
            .timeout(Duration::from_secs(60))
            .no_proxy()
            .build()?;
        Ok(Self {
            bucket,
            region,
            endpoint,
            host,
            path_style,
            access_key,
            secret_key,
            http,
        })
    }

    fn request(
        &self,
        method: &str,
        uri: &str,
        query: &[(&str, &str)],
        body: &[u8],
        content_type: Option<&str>,
    ) -> Result<Vec<u8>> {
        let now: DateTime<Utc> = Utc::now();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let extra: Vec<(&str, &str)> = match content_type {
            Some(value) => vec![("content-type", value)],
            None => Vec::new(),
        };
        let signed = sign_request(&SignInput {
            method,
            uri,
            query,
            host: &self.host,
            extra_headers: &extra,
            payload: body,
            access_key: &self.access_key,
            secret_key: &self.secret_key,
            region: &self.region,
            service: "s3",
            amz_date: &amz_date,
        });
        let mut headers = HeaderMap::new();
        headers.insert(
            "host",
            HeaderValue::from_str(&self.host).map_err(header_err)?,
        );
        headers.insert(
            "x-amz-date",
            HeaderValue::from_str(&signed.amz_date).map_err(header_err)?,
        );
        headers.insert(
            "x-amz-content-sha256",
            HeaderValue::from_str(&signed.content_sha256).map_err(header_err)?,
        );
        headers.insert(
            "authorization",
            HeaderValue::from_str(&signed.authorization).map_err(header_err)?,
        );
        if let Some(content_type) = content_type {
            headers.insert(
                "content-type",
                HeaderValue::from_str(content_type).map_err(header_err)?,
            );
        }
        let url = self.url(uri, query);
        let http_method = reqwest::Method::from_bytes(method.as_bytes())
            .map_err(|err| super::storage_err(format!("{err}")))?;
        let response = self
            .http
            .request(http_method, url)
            .headers(headers)
            .body(body.to_vec())
            .send()?;
        let status = response.status();
        let bytes = response.bytes()?.to_vec();
        if !status.is_success() {
            let detail = String::from_utf8_lossy(&bytes);
            let detail: String = detail.chars().take(500).collect();
            return Err(super::storage_err(format!(
                "S3 {method} returned {status}: {detail}"
            )));
        }
        Ok(bytes)
    }

    fn url(&self, uri: &str, query: &[(&str, &str)]) -> String {
        let mut url = format!("{}{uri}", self.endpoint.trim_end_matches('/'));
        if !query.is_empty() {
            let encoded = query
                .iter()
                .map(|(name, value)| {
                    format!(
                        "{}={}",
                        super::sigv4::uri_encode(name, true),
                        super::sigv4::uri_encode(value, true)
                    )
                })
                .collect::<Vec<_>>()
                .join("&");
            url.push('?');
            url.push_str(&encoded);
        }
        url
    }

    fn root_uri(&self) -> String {
        if self.path_style {
            format!("/{}", super::sigv4::uri_encode(&self.bucket, true))
        } else {
            "/".into()
        }
    }

    fn object_uri(&self, key: &str) -> String {
        let encoded = key
            .split('/')
            .map(|segment| super::sigv4::uri_encode(segment, true))
            .collect::<Vec<_>>()
            .join("/");
        if self.path_style {
            format!(
                "/{}/{encoded}",
                super::sigv4::uri_encode(&self.bucket, true)
            )
        } else {
            format!("/{encoded}")
        }
    }
}

impl ObjectStore for S3Client {
    fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let uri = self.root_uri();
        let mut keys = Vec::new();
        let mut token: Option<String> = None;
        for _ in 0..1_000 {
            let mut query = vec![("list-type", "2"), ("max-keys", "1000"), ("prefix", prefix)];
            if let Some(token) = token.as_deref() {
                query.push(("continuation-token", token));
            }
            let body = self.request("GET", &uri, &query, &[], None)?;
            let text = String::from_utf8_lossy(&body);
            keys.extend(xml_values(&text, "Key"));
            if !text.contains("<IsTruncated>true</IsTruncated>") {
                break;
            }
            token = xml_values(&text, "NextContinuationToken")
                .into_iter()
                .next();
            if token.is_none() {
                break;
            }
        }
        Ok(keys)
    }

    fn get(&self, key: &str) -> Result<Vec<u8>> {
        self.request("GET", &self.object_uri(key), &[], &[], None)
    }

    fn put(&self, key: &str, body: &[u8]) -> Result<()> {
        self.request(
            "PUT",
            &self.object_uri(key),
            &[],
            body,
            Some("application/octet-stream"),
        )?;
        Ok(())
    }

    fn delete(&self, key: &str) -> Result<()> {
        self.request("DELETE", &self.object_uri(key), &[], &[], None)?;
        Ok(())
    }
}

fn header_err(err: impl std::fmt::Display) -> Error {
    super::storage_err(format!("invalid HTTP header: {err}"))
}

fn xml_values(body: &str, tag: &str) -> Vec<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut values = Vec::new();
    let mut rest = body;
    while let Some(start) = rest.find(&open) {
        rest = &rest[start + open.len()..];
        let Some(end) = rest.find(&close) else {
            break;
        };
        values.push(xml_unescape(&rest[..end]));
        rest = &rest[end + close.len()..];
    }
    values
}

fn xml_unescape(value: &str) -> String {
    value
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}
