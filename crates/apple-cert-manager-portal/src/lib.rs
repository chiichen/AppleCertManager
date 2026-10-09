//! App Store Connect portal.
//!
//! `ConnectClient` talks to Apple. `FakePortal` is the in-memory stand-in used
//! by tests and by any caller that wants the same trait without network.

mod client;
mod fake;
mod jwt;
mod model;

pub use client::ConnectClient;
pub use fake::FakePortal;
pub use jwt::issue_token;
pub use model::{
    CreateProfile, Portal, PortalBundleId, PortalCertificate, PortalDevice, PortalProfile,
};
