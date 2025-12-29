//! AWS connector for Q SDK
//!
//! Provides connectors for various AWS services:
//! - S3 (storage)
//! - SES (email sending)
//! - SNS (notifications)
#![warn(missing_docs)]

pub use connector_sdk::{Connector, Error, Result};

/// AWS SES email sending module
#[cfg(feature = "ses")]
pub mod ses;

/// AWS SNS notification handling module
#[cfg(feature = "sns")]
pub mod sns;

/// AWS S3 connector
#[cfg(feature = "s3")]
pub struct S3Connector {
    _client: Option<aws_sdk_s3::Client>,
}

#[cfg(feature = "s3")]
impl S3Connector {
    /// Create a new S3 connector
    pub fn new() -> Self {
        Self { _client: None }
    }
}

#[cfg(feature = "s3")]
impl Default for S3Connector {
    fn default() -> Self {
        Self::new()
    }
}
