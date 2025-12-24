//! SMTP connector for Q SDK
#![warn(missing_docs)]

pub use connector_sdk::{Connector, Error, Result};

/// SMTP connector
pub struct SmtpConnector {
    _host: String,
    _port: u16,
}

impl SmtpConnector {
    /// Create a new SMTP connector
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            _host: host.into(),
            _port: port,
        }
    }
}
