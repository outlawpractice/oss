//! OAuth error types

use core::time::Duration;

/// Classification of OAuth errors to determine appropriate action
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthErrorKind {
    /// Refresh token is invalid - user must re-authenticate
    RefreshTokenInvalid,
    /// Transient error - can retry with backoff
    TransientError,
    /// Rate limited - should back off before retrying
    RateLimited,
    /// Unknown error - treat as transient
    Unknown,
}

/// OAuth-specific errors
#[derive(Debug, thiserror::Error)]
pub enum OAuthError {
    /// Token refresh required - user must re-authenticate
    #[error("Refresh token invalid or revoked: {0}")]
    RefreshTokenInvalid(String),

    /// Provider rate limited
    #[error("Rate limited by provider")]
    RateLimited {
        /// Suggested retry delay, if provided by provider
        retry_after: Option<Duration>,
    },

    /// Provider temporarily unavailable
    #[error("Provider temporarily unavailable: {0}")]
    ProviderUnavailable(String),

    /// Network error during OAuth operation
    #[error("Network error: {0}")]
    Network(String),

    /// Invalid response from provider
    #[error("Invalid response from provider: {0}")]
    InvalidResponse(String),

    /// PKCE error
    #[cfg(feature = "pkce")]
    #[error("PKCE error: {0}")]
    PkceError(String),

    /// Token exchange failed
    #[error("Token exchange failed: {0}")]
    TokenExchangeFailed(String),

    /// Missing required field
    #[error("Missing required field: {0}")]
    MissingField(String),
}

impl OAuthError {
    /// Get the classification of this error
    ///
    /// This helps consumers determine the appropriate action:
    /// - `RefreshTokenInvalid` - User must re-authenticate
    /// - `RateLimited` - Should back off before retrying
    /// - `TransientError` - Can retry with backoff
    /// - `Unknown` - Treat as transient
    pub fn kind(&self) -> OAuthErrorKind {
        match self {
            OAuthError::RefreshTokenInvalid(_) => OAuthErrorKind::RefreshTokenInvalid,
            OAuthError::RateLimited { .. } => OAuthErrorKind::RateLimited,
            OAuthError::ProviderUnavailable(_) => OAuthErrorKind::TransientError,
            OAuthError::Network(_) => OAuthErrorKind::TransientError,
            OAuthError::InvalidResponse(_) => OAuthErrorKind::Unknown,
            #[cfg(feature = "pkce")]
            OAuthError::PkceError(_) => OAuthErrorKind::Unknown,
            OAuthError::TokenExchangeFailed(_) => OAuthErrorKind::Unknown,
            OAuthError::MissingField(_) => OAuthErrorKind::Unknown,
        }
    }
}

/// Result type for OAuth operations
pub type OAuthResult<T> = Result<T, OAuthError>;

#[cfg(feature = "http")]
impl From<reqwest::Error> for OAuthError {
    fn from(err: reqwest::Error) -> Self {
        if err.is_timeout() {
            OAuthError::ProviderUnavailable("Request timed out".to_string())
        } else if err.is_connect() {
            OAuthError::Network(format!("Connection failed: {}", err))
        } else {
            OAuthError::Network(err.to_string())
        }
    }
}
