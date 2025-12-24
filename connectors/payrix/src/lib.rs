//! Payrix payment connector for Q SDK
//!
//! This connector bridges the Payrix payment SDK with Q's connector infrastructure.
#![warn(missing_docs)]

pub use connector_sdk::{Connector, Error, Result};
pub use payrix::{PayrixClient, Environment};

/// Payrix connector for Q automation engine
pub struct PayrixConnector {
    client: PayrixClient,
}

impl PayrixConnector {
    /// Create a new Payrix connector for the test environment
    ///
    /// # Errors
    /// Returns an error if the client cannot be initialized
    pub fn new_test(api_key: impl Into<String>) -> std::result::Result<Self, payrix::Error> {
        Ok(Self {
            client: PayrixClient::new(api_key, Environment::Test)?,
        })
    }

    /// Create a new Payrix connector for the production environment
    ///
    /// # Errors
    /// Returns an error if the client cannot be initialized
    pub fn new_production(api_key: impl Into<String>) -> std::result::Result<Self, payrix::Error> {
        Ok(Self {
            client: PayrixClient::new(api_key, Environment::Production)?,
        })
    }

    /// Get a reference to the underlying Payrix client
    pub fn client(&self) -> &PayrixClient {
        &self.client
    }

    /// Get a mutable reference to the underlying Payrix client
    pub fn client_mut(&mut self) -> &mut PayrixClient {
        &mut self.client
    }
}
