use std::fs;
use std::path::Path;

use acm_error::{Error, Result};

/// One row from a fastlane-compatible device list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRecord {
    pub name: String,
    pub udid: String,
    pub platform: String,
}

pub fn load_devices(path: &Path) -> Result<Vec<DeviceRecord>> {
    let text = fs::read_to_string(path)
        .map_err(|err| Error::msg(format!("cannot read device list {}: {err}", path.display())))?;
    parse_devices(&text)
}

/// Accepts the tab-separated file used by `fastlane register_devices`.
///
/// A header row is optional. Without one, a column that looks like a UDID is
/// the identifier and the other column is the display name. Platform defaults
/// to `IOS`.
pub fn parse_devices(text: &str) -> Result<Vec<DeviceRecord>> {
    let mut rows = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        rows.push((index + 1, split_row(line)));
    }
    if rows.is_empty() {
        return Ok(Vec::new());
    }

    let mut records = Vec::new();
    let (udid_idx, name_idx, platform_idx, start) = if let Some(header) = header_columns(&rows[0].1)
    {
        (header.0, header.1, header.2, 1)
    } else {
        (usize::MAX, usize::MAX, None, 0)
    };

    for (line_no, cells) in rows.into_iter().skip(start) {
        let record = if start == 1 {
            record_from_header(line_no, &cells, udid_idx, name_idx, platform_idx)?
        } else {
            record_from_inferred(line_no, &cells)?
        };
        if records
            .iter()
            .any(|existing: &DeviceRecord| udid_eq(&existing.udid, &record.udid))
        {
            return Err(Error::msg(format!(
                "device list line {line_no} repeats UDID {}",
                record.udid
            )));
        }
        records.push(record);
    }
    Ok(records)
}

fn record_from_header(
    line_no: usize,
    cells: &[String],
    udid_idx: usize,
    name_idx: usize,
    platform_idx: Option<usize>,
) -> Result<DeviceRecord> {
    let udid = cells.get(udid_idx).map(String::as_str).unwrap_or("").trim();
    let name = cells.get(name_idx).map(String::as_str).unwrap_or("").trim();
    if udid.is_empty() || name.is_empty() {
        return Err(Error::msg(format!(
            "device list line {line_no} needs both a name and a UDID"
        )));
    }
    let platform = match platform_idx.and_then(|index| cells.get(index)) {
        Some(value) if !value.trim().is_empty() => normalize_platform(value)?,
        _ => "IOS".to_string(),
    };
    Ok(DeviceRecord {
        name: name.to_string(),
        udid: udid.to_string(),
        platform,
    })
}

fn record_from_inferred(line_no: usize, cells: &[String]) -> Result<DeviceRecord> {
    if cells.len() < 2 {
        return Err(Error::msg(format!(
            "device list line {line_no} needs a name and a UDID"
        )));
    }
    let (cells, platform) = match cells.last() {
        Some(last) if cells.len() >= 3 && normalize_platform(last).is_ok() => {
            (&cells[..cells.len() - 1], normalize_platform(last)?)
        }
        _ => (cells, "IOS".to_string()),
    };
    let Some(udid_index) = cells.iter().position(|cell| looks_like_udid(cell)) else {
        return Err(Error::msg(format!(
            "device list line {line_no} has no UDID"
        )));
    };
    let name = cells
        .iter()
        .enumerate()
        .filter(|(index, _)| *index != udid_index)
        .map(|(_, cell)| cell.as_str())
        .collect::<Vec<_>>()
        .join(" ");
    if name.is_empty() {
        return Err(Error::msg(format!(
            "device list line {line_no} needs a device name"
        )));
    }
    Ok(DeviceRecord {
        name,
        udid: cells[udid_index].clone(),
        platform,
    })
}

fn header_columns(cells: &[String]) -> Option<(usize, usize, Option<usize>)> {
    let lower: Vec<String> = cells.iter().map(|cell| cell.to_ascii_lowercase()).collect();
    let looks_like_header = lower.iter().any(|cell| {
        cell.contains("device") || cell.contains("udid") || cell.contains("identifier")
    });
    if !looks_like_header {
        return None;
    }
    let udid = lower.iter().position(|cell| {
        cell.contains("udid") || cell.contains("identifier") || cell.contains("device id")
    })?;
    let name = lower.iter().position(|cell| cell.contains("name"))?;
    let platform = lower.iter().position(|cell| cell.contains("platform"));
    Some((udid, name, platform))
}

fn split_row(line: &str) -> Vec<String> {
    let parts: Vec<String> = if line.contains('\t') {
        line.split('\t')
            .map(|cell| cell.trim().to_string())
            .filter(|cell| !cell.is_empty())
            .collect()
    } else if line.contains(',') {
        split_csv(line)
    } else {
        line.split_whitespace()
            .map(|cell| cell.to_string())
            .collect()
    };
    parts
}

fn split_csv(line: &str) -> Vec<String> {
    let mut cells = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    for ch in line.chars() {
        match ch {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                let cell = current.trim().to_string();
                if !cell.is_empty() {
                    cells.push(cell);
                }
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    let cell = current.trim().to_string();
    if !cell.is_empty() {
        cells.push(cell);
    }
    cells
}

pub fn looks_like_udid(value: &str) -> bool {
    let compact: String = value.chars().filter(|ch| *ch != '-').collect();
    compact.len() >= 24 && compact.len() <= 40 && compact.chars().all(|ch| ch.is_ascii_hexdigit())
}

pub fn normalize_platform(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase().replace('-', "_");
    match normalized.as_str() {
        "ios" | "iphone" | "ipad" => Ok("IOS".to_string()),
        "macos" | "mac" | "osx" | "mac_os" => Ok("MAC_OS".to_string()),
        "tvos" | "tv" | "appletv" | "apple_tv" => Ok("TVOS".to_string()),
        other => Err(Error::msg(format!(
            "unknown device platform '{other}'. Expected ios, macos, or tvos"
        ))),
    }
}

fn udid_eq(left: &str, right: &str) -> bool {
    left.eq_ignore_ascii_case(right)
}
