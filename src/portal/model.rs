use crate::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortalCertificate {
    pub id: String,
    pub certificate_type: String,
    pub display_name: String,
    pub certificate_der: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortalBundleId {
    pub id: String,
    pub name: String,
    pub identifier: String,
    pub platform: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortalDevice {
    pub id: String,
    pub name: String,
    pub udid: String,
    pub platform: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortalProfile {
    pub id: String,
    pub name: String,
    pub profile_type: String,
    pub uuid: String,
    pub bundle_identifier: String,
    pub bundle_id_id: String,
    pub certificate_ids: Vec<String>,
    pub device_ids: Vec<String>,
    pub content: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct CreateProfile {
    pub name: String,
    pub profile_type: String,
    pub bundle_id_id: String,
    pub certificate_ids: Vec<String>,
    pub device_ids: Vec<String>,
}

pub trait Portal {
    fn list_certificates(&self) -> Result<Vec<PortalCertificate>>;
    fn create_certificate(
        &self,
        certificate_type: &str,
        csr_pem: &str,
    ) -> Result<PortalCertificate>;
    fn revoke_certificate(&self, id: &str) -> Result<()>;

    fn list_bundle_ids(&self) -> Result<Vec<PortalBundleId>>;
    fn create_bundle_id(
        &self,
        name: &str,
        identifier: &str,
        platform: &str,
    ) -> Result<PortalBundleId>;

    fn list_devices(&self) -> Result<Vec<PortalDevice>>;
    fn register_device(&self, name: &str, udid: &str, platform: &str) -> Result<PortalDevice>;

    fn list_profiles(&self) -> Result<Vec<PortalProfile>>;
    fn create_profile(&self, request: &CreateProfile) -> Result<PortalProfile>;
    fn delete_profile(&self, id: &str) -> Result<()>;
}
