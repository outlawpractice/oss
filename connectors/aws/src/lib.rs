//! AWS connector for Q SDK
#![warn(missing_docs)]

pub use connector_sdk::{Connector, Error, Result};

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
