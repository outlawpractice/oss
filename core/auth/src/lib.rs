//! Authentication utilities for Q SDK
#![warn(missing_docs)]

#[cfg(feature = "std")]
pub use core_types::{Error, Result};

/// Authentication token
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Token {
    /// Access token value
    pub access_token: String,
    /// Optional refresh token
    pub refresh_token: Option<String>,
    /// Token expiry in seconds
    pub expires_in: Option<u64>,
}
