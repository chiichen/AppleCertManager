//! Partition-list payload stored in a keychain ACL description.
//!
//! Apple's `security set-key-partition-list` hex-encodes an XML plist
//! `{"Partitions": [...]}` and writes that string into the ACL whose
//! authorization is `CSSM_ACL_AUTHORIZATION_PARTITION_ID`.

use acm_error::{Error, Result};

/// Partitions fastlane match grants to `codesign` and the other Apple tools.
pub const SIGNING_PARTITIONS: &[&str] = &["apple-tool:", "apple:", "codesign:"];

pub fn partition_acl_description(partitions: &[&str]) -> Result<String> {
    let values = partitions
        .iter()
        .map(|partition| plist::Value::String((*partition).to_string()))
        .collect();
    let mut dict = plist::Dictionary::new();
    dict.insert("Partitions".into(), plist::Value::Array(values));
    let mut xml = Vec::new();
    plist::Value::Dictionary(dict)
        .to_writer_xml(&mut xml)
        .map_err(|err| Error::msg(format!("cannot encode key partition list: {err}")))?;
    Ok(hex::encode(xml))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn description_round_trips_the_match_partitions() {
        let encoded = partition_acl_description(SIGNING_PARTITIONS).unwrap();
        let xml = hex::decode(encoded).unwrap();
        let root = plist::Value::from_reader_xml(xml.as_slice()).unwrap();
        let partitions = root
            .as_dictionary()
            .unwrap()
            .get("Partitions")
            .unwrap()
            .as_array()
            .unwrap();
        let names: Vec<&str> = partitions
            .iter()
            .filter_map(plist::Value::as_string)
            .collect();
        assert_eq!(names, SIGNING_PARTITIONS);
    }
}
