//! Apple certificate manager.
//!
//! The on-disk repository matches fastlane match: the same certificate and
//! profile paths, the same `sigh_*` environment variables, and both match
//! encryption formats (legacy `Salted__` AES-256-CBC and `match_encrypted_v2__`
//! AES-256-GCM).

pub mod config;
pub mod crypto;
pub mod devices;
pub mod engine;
pub mod error;
pub mod portal;
pub mod storage;
pub mod types;

pub use error::{Error, Result};
