use serde::{Deserialize, Deserializer, Serialize, Serializer};

use acm_error::{Error, Result};

/// A fastlane match signing lane.
///
/// Several lanes share one certificate directory. Ad Hoc and App Store both
/// use `certs/distribution`, while their profiles stay in separate folders.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SigningType {
    Development,
    AdHoc,
    AppStore,
    Enterprise,
    DeveloperId,
    MacInstallerDistribution,
    DeveloperIdInstaller,
}

impl SigningType {
    pub fn parse(value: &str) -> Result<Self> {
        let normalized = value.trim().to_ascii_lowercase().replace('-', "_");
        match normalized.as_str() {
            "development" | "dev" => Ok(Self::Development),
            "adhoc" | "ad_hoc" => Ok(Self::AdHoc),
            "appstore" | "app_store" => Ok(Self::AppStore),
            "enterprise" | "inhouse" | "in_house" => Ok(Self::Enterprise),
            "developer_id" | "developerid" | "direct" => Ok(Self::DeveloperId),
            "mac_installer_distribution" => Ok(Self::MacInstallerDistribution),
            "developer_id_installer" => Ok(Self::DeveloperIdInstaller),
            other => Err(Error::msg(format!(
                "unknown signing type '{other}'. Expected development, adhoc, appstore, enterprise, developer_id, mac_installer_distribution, or developer_id_installer"
            ))),
        }
    }

    /// Match's `type` string, also used in `sigh_*` variable names.
    pub fn as_match_str(self) -> &'static str {
        match self {
            Self::Development => "development",
            Self::AdHoc => "adhoc",
            Self::AppStore => "appstore",
            Self::Enterprise => "enterprise",
            Self::DeveloperId => "developer_id",
            Self::MacInstallerDistribution => "mac_installer_distribution",
            Self::DeveloperIdInstaller => "developer_id_installer",
        }
    }

    /// `certs/<folder>` directory used by match's `cert_type_sym`.
    pub fn cert_folder(self) -> &'static str {
        match self {
            Self::Development => "development",
            Self::AdHoc | Self::AppStore => "distribution",
            Self::Enterprise => "enterprise",
            Self::DeveloperId => "developer_id_application",
            Self::MacInstallerDistribution => "mac_installer_distribution",
            Self::DeveloperIdInstaller => "developer_id_installer",
        }
    }

    /// `profiles/<folder>`. Installer certificates have no provisioning profile.
    pub fn profile_folder(self) -> Option<&'static str> {
        match self {
            Self::MacInstallerDistribution | Self::DeveloperIdInstaller => None,
            other => Some(other.as_match_str()),
        }
    }

    /// File-name prefix used by sigh (`Development`, `AdHoc`, `AppStore`, `InHouse`, `Direct`).
    pub fn profile_type_name(self) -> &'static str {
        match self {
            Self::Development => "Development",
            Self::AdHoc => "AdHoc",
            Self::AppStore => "AppStore",
            Self::Enterprise => "InHouse",
            Self::DeveloperId => "Direct",
            Self::MacInstallerDistribution | Self::DeveloperIdInstaller => "Unknown",
        }
    }

    /// Name stored in the Apple portal and inside the profile plist.
    ///
    /// iOS keeps the historical three-part name. Every other platform appends
    /// its match platform string: `match Development com.example.app macos`.
    pub fn portal_profile_name(self, bundle_id: &str, platform: Platform) -> String {
        let mut parts = vec![
            "match".to_string(),
            self.profile_type_name().to_string(),
            bundle_id.to_string(),
        ];
        if platform != Platform::Ios {
            parts.push(platform.as_str().to_string());
        }
        parts.join(" ")
    }

    /// On-disk file name, matching sigh's `download_profile`.
    pub fn profile_filename(self, bundle_id: &str, platform: Platform) -> String {
        let mut name = format!("{}_{}", self.profile_type_name(), bundle_id);
        if matches!(platform, Platform::Tvos | Platform::Catalyst) {
            name.push('_');
            name.push_str(platform.as_str());
        }
        name.push_str(match platform {
            Platform::Macos | Platform::Catalyst => ".provisionprofile",
            Platform::Ios | Platform::Tvos => ".mobileprovision",
        });
        name
    }

    pub fn includes_devices(self) -> bool {
        matches!(self, Self::Development | Self::AdHoc)
    }

    /// `xcodebuild -exportArchive` method for this lane.
    pub fn export_method(self) -> Option<&'static str> {
        match self {
            Self::Development => Some("development"),
            Self::AdHoc => Some("ad-hoc"),
            Self::AppStore => Some("app-store"),
            Self::Enterprise => Some("enterprise"),
            Self::DeveloperId => Some("developer-id"),
            Self::MacInstallerDistribution | Self::DeveloperIdInstaller => None,
        }
    }

    pub fn sigh_prefix(self, bundle_id: &str, platform: Platform) -> String {
        if platform == Platform::Ios {
            format!("sigh_{}_{}", bundle_id, self.as_match_str())
        } else {
            format!(
                "sigh_{}_{}_{}",
                bundle_id,
                self.as_match_str(),
                platform.as_str()
            )
        }
    }

    /// App Store Connect profile type. `None` when this lane has no profile.
    pub fn apple_profile_type(self, platform: Platform) -> Option<&'static str> {
        Some(match (platform, self) {
            (Platform::Ios, Self::Development) => "IOS_APP_DEVELOPMENT",
            (Platform::Ios, Self::AdHoc) => "IOS_APP_ADHOC",
            (Platform::Ios, Self::AppStore) => "IOS_APP_STORE",
            (Platform::Ios, Self::Enterprise) => "IOS_APP_INHOUSE",
            (Platform::Tvos, Self::Development) => "TVOS_APP_DEVELOPMENT",
            (Platform::Tvos, Self::AdHoc) => "TVOS_APP_ADHOC",
            (Platform::Tvos, Self::AppStore) => "TVOS_APP_STORE",
            (Platform::Tvos, Self::Enterprise) => "TVOS_APP_INHOUSE",
            (Platform::Macos, Self::Development) => "MAC_APP_DEVELOPMENT",
            (Platform::Macos, Self::AppStore) => "MAC_APP_STORE",
            (Platform::Macos, Self::Enterprise) => "MAC_APP_INHOUSE",
            (Platform::Macos, Self::DeveloperId) => "MAC_APP_DIRECT",
            (Platform::Catalyst, Self::Development) => "MAC_CATALYST_APP_DEVELOPMENT",
            (Platform::Catalyst, Self::AppStore) => "MAC_CATALYST_APP_STORE",
            (Platform::Catalyst, Self::Enterprise) => "MAC_CATALYST_APP_INHOUSE",
            (Platform::Catalyst, Self::DeveloperId) => "MAC_CATALYST_APP_DIRECT",
            _ => return None,
        })
    }

    /// Certificate types accepted for an existing cert, newest API name first.
    pub fn apple_certificate_types(self, platform: Platform) -> &'static [&'static str] {
        match (self, platform) {
            (Self::Development, Platform::Ios | Platform::Tvos) => {
                &["IOS_DEVELOPMENT", "DEVELOPMENT"]
            }
            (Self::Development, Platform::Macos | Platform::Catalyst) => {
                &["MAC_APP_DEVELOPMENT", "DEVELOPMENT"]
            }
            (Self::AdHoc | Self::AppStore, Platform::Ios | Platform::Tvos) => {
                &["IOS_DISTRIBUTION", "DISTRIBUTION"]
            }
            (Self::Enterprise, Platform::Ios | Platform::Tvos) => &["IOS_DISTRIBUTION"],
            (Self::AdHoc | Self::AppStore, Platform::Macos | Platform::Catalyst) => {
                &["MAC_APP_DISTRIBUTION", "DISTRIBUTION"]
            }
            (Self::Enterprise, Platform::Macos | Platform::Catalyst) => &["MAC_APP_DISTRIBUTION"],
            (Self::DeveloperId, _) => &["DEVELOPER_ID_APPLICATION", "DEVELOPER_ID_APPLICATION_G2"],
            (Self::DeveloperIdInstaller, _) => &["DEVELOPER_ID_INSTALLER"],
            (Self::MacInstallerDistribution, _) => &["MAC_INSTALLER_DISTRIBUTION"],
        }
    }

    pub fn preferred_certificate_type(self, platform: Platform) -> Option<&'static str> {
        self.apple_certificate_types(platform).first().copied()
    }
}

impl std::fmt::Display for SigningType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_match_str())
    }
}

impl Serialize for SigningType {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_match_str())
    }
}

impl<'de> Deserialize<'de> for SigningType {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        SigningType::parse(&value).map_err(serde::de::Error::custom)
    }
}

/// Apple platform, using match's names (`ios`, `macos`, `tvos`, `catalyst`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Platform {
    Ios,
    Macos,
    Tvos,
    Catalyst,
}

impl Platform {
    pub fn parse(value: &str) -> Result<Self> {
        let normalized = value.trim().to_ascii_lowercase().replace('-', "_");
        match normalized.as_str() {
            "ios" | "iphone" | "ipad" => Ok(Self::Ios),
            "macos" | "mac" | "osx" => Ok(Self::Macos),
            "tvos" | "tv" | "appletv" => Ok(Self::Tvos),
            "catalyst" | "mac_catalyst" | "maccatalyst" => Ok(Self::Catalyst),
            other => Err(Error::msg(format!(
                "unknown platform '{other}'. Expected ios, macos, tvos, or catalyst"
            ))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ios => "ios",
            Self::Macos => "macos",
            Self::Tvos => "tvos",
            Self::Catalyst => "catalyst",
        }
    }

    /// Platform sent to `POST /v1/bundleIds`.
    pub fn bundle_id_platform(self) -> &'static str {
        match self {
            Self::Ios | Self::Catalyst => "IOS",
            Self::Macos => "MAC_OS",
            Self::Tvos => "TVOS",
        }
    }

    /// Device platform included in this destination's profiles.
    pub fn device_platform(self) -> &'static str {
        match self {
            Self::Ios => "IOS",
            Self::Tvos => "TVOS",
            Self::Macos | Self::Catalyst => "MAC_OS",
        }
    }
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for Platform {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Platform {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Platform::parse(&value).map_err(serde::de::Error::custom)
    }
}
