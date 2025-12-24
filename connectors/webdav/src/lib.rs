//! WebDAV connector for Q SDK
#![warn(missing_docs)]

pub use connector_sdk::{Connector, Error, Result};

/// WebDAV connector
pub struct WebDavConnector {
    _base_url: String,
}

impl WebDavConnector {
    /// Create a new WebDAV connector
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            _base_url: base_url.into(),
        }
    }
}
