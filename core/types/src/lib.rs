//! Core types for Q SDK
#![warn(missing_docs)]

use thiserror::Error;

/// Core error type
#[derive(Debug, Error)]
pub enum Error {
    /// Generic error
    #[error("{0}")]
    Generic(String),
}

/// Result alias
pub type Result<T> = std::result::Result<T, Error>;
