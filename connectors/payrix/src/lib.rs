//! Payrix payment connector for Q SDK
#![warn(missing_docs)]

pub use connector_sdk::{Connector, Error, Result};

/// Payrix connector
pub struct PayrixConnector {
    _api_key: String,
}

impl PayrixConnector {
    /// Create a new Payrix connector
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            _api_key: api_key.into(),
        }
    }
}
