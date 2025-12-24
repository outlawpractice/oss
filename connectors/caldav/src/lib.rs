//! CalDAV connector for Q SDK
#![warn(missing_docs)]

pub use connector_sdk::{Connector, Error, Result};

/// CalDAV connector
pub struct CalDavConnector {
    _base_url: String,
}

impl CalDavConnector {
    /// Create a new CalDAV connector
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            _base_url: base_url.into(),
        }
    }
}
