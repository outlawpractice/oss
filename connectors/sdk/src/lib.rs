//! Connector SDK for building Q integrations
#![warn(missing_docs)]

pub use core_types::{Error, Result};

/// Connector trait for implementing service integrations
#[async_trait::async_trait]
pub trait Connector: Send + Sync {
    /// Connect to the service
    async fn connect(&self) -> Result<()>;

    /// Disconnect from the service
    async fn disconnect(&self) -> Result<()>;

    /// Check if connected
    fn is_connected(&self) -> bool;
}
