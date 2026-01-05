//! Authentication and OAuth utilities for Q SDK
//!
//! This crate provides:
//! - Credential types for OAuth, Basic Auth, and S3
//! - Generic `OAuthProvider` trait for implementing providers
//! - Built-in provider implementations (Google, Microsoft, Dropbox, Box)
//! - OAuth operations (token exchange, refresh, validation)
//! - PKCE support for secure client-side OAuth flows
//!
//! # Feature Flags
//!
//! - `std` (default): Standard library support
//! - `serde`: Serialization/deserialization support
//! - `http`: OAuth HTTP operations (token exchange, refresh)
//! - `pkce`: PKCE code challenge support
//! - `providers`: Built-in provider implementations
//! - `full`: All features enabled
//!
//! # Example
//!
//! ```ignore
//! use core_auth::providers::Google;
//! use core_auth::provider::{OAuthProvider, OAuthClientConfig};
//! use core_auth::oauth::{generate_auth_url, exchange_code};
//! use core_auth::pkce::PkceParams;
//!
//! // Generate PKCE parameters
//! let pkce = PkceParams::generate();
//!
//! // Create OAuth client config
//! let client = OAuthClientConfig::new(
//!     "client_id",
//!     "client_secret",
//!     "https://example.com/callback",
//! );
//!
//! // Generate authorization URL
//! let auth_url = generate_auth_url(
//!     &Google,
//!     &client,
//!     &pkce.state,
//!     None,
//!     Some(&pkce.challenge),
//! );
//!
//! // After user authorizes, exchange code for tokens
//! let tokens = exchange_code(&Google, &client, "auth_code", Some(&pkce.verifier)).await?;
//! ```

#![warn(missing_docs)]
// Note: no_std support removed because thiserror requires std

// Error types (always available)
pub mod error;
pub use error::{OAuthError, OAuthErrorKind, OAuthResult};

// Credential types (always available)
pub mod types;
pub use types::{
    BasicCredentials, OAuthCredentials, OAuthTokens, S3Credentials, SharePointConfig,
    TokenResponse,
};

// Provider trait (always available)
pub mod provider;
pub use provider::{OAuthClientConfig, OAuthProvider};

// PKCE support (optional)
#[cfg(feature = "pkce")]
pub mod pkce;
#[cfg(feature = "pkce")]
pub use pkce::{generate_code_challenge, generate_code_verifier, generate_state, PkceParams};

// OAuth HTTP operations (optional)
#[cfg(feature = "http")]
pub mod oauth;
#[cfg(feature = "http")]
pub use oauth::{exchange_code, generate_auth_url, refresh_token, revoke_token, validate_token};

// Built-in providers (optional)
#[cfg(feature = "providers")]
pub mod providers;

// Legacy Token type for backward compatibility
/// Authentication token (legacy type, prefer OAuthTokens)
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

impl From<OAuthTokens> for Token {
    fn from(tokens: OAuthTokens) -> Self {
        Self {
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
            expires_in: None, // OAuthTokens uses expires_at (RFC3339), not expires_in
        }
    }
}
