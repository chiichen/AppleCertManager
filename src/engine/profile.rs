use std::io::Cursor;
use std::time::SystemTime;

use crate::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedProfile {
    pub name: String,
    pub uuid: String,
    pub team_ids: Vec<String>,
    pub devices: Vec<String>,
    pub certificate_names: Vec<String>,
    pub expired: bool,
}

pub fn parse_profile(bytes: &[u8]) -> Result<ParsedProfile> {
    let xml = extract_plist(bytes)?;
    let root = plist::Value::from_reader(Cursor::new(xml.as_bytes()))
        .map_err(|err| Error::msg(format!("cannot parse provisioning profile: {err}")))?;
    let dict = root
        .as_dictionary()
        .ok_or_else(|| Error::msg("provisioning profile is not a plist dictionary"))?;
    let certificate_names = dict
        .get("DeveloperCertificates")
        .and_then(plist::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(plist::Value::as_data)
                .filter_map(|der| crate::crypto::inspect_certificate(der).ok())
                .map(|info| info.common_name)
                .collect()
        })
        .unwrap_or_default();
    Ok(ParsedProfile {
        name: plist_string(dict, "Name"),
        uuid: plist_string(dict, "UUID"),
        team_ids: plist_strings(dict, "TeamIdentifier"),
        devices: plist_strings(dict, "ProvisionedDevices"),
        certificate_names,
        expired: dict
            .get("ExpirationDate")
            .and_then(plist::Value::as_date)
            .is_some_and(|date| SystemTime::from(date) <= SystemTime::now()),
    })
}

fn plist_string(dict: &plist::Dictionary, key: &str) -> String {
    dict.get(key)
        .and_then(plist::Value::as_string)
        .unwrap_or("")
        .to_string()
}

fn plist_strings(dict: &plist::Dictionary, key: &str) -> Vec<String> {
    dict.get(key)
        .and_then(plist::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(plist::Value::as_string)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn extract_plist(bytes: &[u8]) -> Result<String> {
    let start = bytes
        .windows(5)
        .position(|window| window == b"<?xml")
        .ok_or_else(|| Error::msg("provisioning profile does not contain a plist"))?;
    let end = bytes[start..]
        .windows(8)
        .position(|window| window == b"</plist>")
        .ok_or_else(|| Error::msg("provisioning profile plist is truncated"))?;
    String::from_utf8(bytes[start..start + end + 8].to_vec())
        .map_err(|err| Error::msg(format!("provisioning profile plist is not UTF-8: {err}")))
}
