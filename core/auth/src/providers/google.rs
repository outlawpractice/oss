//! Google OAuth provider
//!
//! Supports Google Drive, Google Calendar, and other Google APIs.
//!
//! # Token Expiration
//!
//! - Access tokens expire after 1 hour
//! - Refresh tokens expire after 6 months of non-use
//! - Refresh tokens are invalidated when user revokes access or changes password
//! - Maximum 50 refresh tokens per user per client (oldest are invalidated)

use crate::error::OAuthErrorKind;
use crate::provider::OAuthProvider;
use crate::types::OAuthErrorResponse;

/// Google OAuth provider
///
/// # Example
///
/// ```
/// use core_auth::providers::Google;
/// use core_auth::provider::OAuthProvider;
///
/// let provider = Google;
/// assert_eq!(provider.id(), "google");
/// assert_eq!(provider.auth_url(), "https://accounts.google.com/o/oauth2/v2/auth");
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct Google;

impl OAuthProvider for Google {
    fn id(&self) -> &str {
        "google"
    }

    fn display_name(&self) -> &str {
        "Google"
    }

    fn auth_url(&self) -> &str {
        "https://accounts.google.com/o/oauth2/v2/auth"
    }

    fn token_url(&self) -> &str {
        "https://oauth2.googleapis.com/token"
    }

    fn default_scopes(&self) -> &[&str] {
        // Common scopes for Google Drive access
        &["https://www.googleapis.com/auth/drive"]
    }

    fn auth_params(&self) -> Vec<(&str, &str)> {
        // access_type=offline is required to get a refresh token
        // prompt=consent forces re-consent to ensure we get a refresh token
        vec![("access_type", "offline"), ("prompt", "consent")]
    }

    fn classify_error(&self, _status: u16, body: &str) -> OAuthErrorKind {
        let error: OAuthErrorResponse = serde_json::from_str(body).unwrap_or_default();

        match error.error.as_str() {
            // invalid_grant means refresh token is invalid:
            // - User revoked access
            // - Refresh token expired (6 months non-use)
            // - Token limit exceeded (50 per user per client)
            "invalid_grant" => OAuthErrorKind::RefreshTokenInvalid,
            "rate_limit_exceeded" => OAuthErrorKind::RateLimited,
            "temporarily_unavailable" | "server_error" => OAuthErrorKind::TransientError,
            _ => OAuthErrorKind::Unknown,
        }
    }

    fn validation_endpoint(&self) -> Option<&str> {
        // Lightweight endpoint to validate tokens
        Some("https://www.googleapis.com/drive/v3/about?fields=user")
    }

    fn revoke_url(&self) -> Option<&str> {
        Some("https://oauth2.googleapis.com/revoke")
    }
}

/// Google with specific scopes
#[derive(Debug, Clone)]
pub struct GoogleWithScopes {
    scopes: Vec<&'static str>,
}

impl GoogleWithScopes {
    /// Create a Google provider with Drive scopes
    pub fn drive() -> Self {
        Self {
            scopes: vec!["https://www.googleapis.com/auth/drive"],
        }
    }

    /// Create a Google provider with Calendar scopes
    pub fn calendar() -> Self {
        Self {
            scopes: vec!["https://www.googleapis.com/auth/calendar"],
        }
    }

    /// Create a Google provider with custom scopes
    pub fn with_scopes(scopes: Vec<&'static str>) -> Self {
        Self { scopes }
    }
}

impl OAuthProvider for GoogleWithScopes {
    fn id(&self) -> &str {
        "google"
    }

    fn display_name(&self) -> &str {
        "Google"
    }

    fn auth_url(&self) -> &str {
        Google.auth_url()
    }

    fn token_url(&self) -> &str {
        Google.token_url()
    }

    fn default_scopes(&self) -> &[&str] {
        &self.scopes
    }

    fn auth_params(&self) -> Vec<(&str, &str)> {
        Google.auth_params()
    }

    fn classify_error(&self, status: u16, body: &str) -> OAuthErrorKind {
        Google.classify_error(status, body)
    }

    fn validation_endpoint(&self) -> Option<&str> {
        Google.validation_endpoint()
    }

    fn revoke_url(&self) -> Option<&str> {
        Google.revoke_url()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_google_provider() {
        let provider = Google;

        assert_eq!(provider.id(), "google");
        assert_eq!(provider.display_name(), "Google");
        assert!(provider.auth_url().contains("google.com"));
        assert!(provider.token_url().contains("googleapis.com"));
        assert!(!provider.default_scopes().is_empty());
    }

    #[test]
    fn test_classify_invalid_grant() {
        let provider = Google;
        let body = r#"{"error": "invalid_grant", "error_description": "Token revoked"}"#;

        assert_eq!(
            provider.classify_error(400, body),
            OAuthErrorKind::RefreshTokenInvalid
        );
    }

    #[test]
    fn test_classify_rate_limit() {
        let provider = Google;
        let body = r#"{"error": "rate_limit_exceeded"}"#;

        assert_eq!(
            provider.classify_error(429, body),
            OAuthErrorKind::RateLimited
        );
    }

    #[test]
    fn test_auth_params_include_offline() {
        let provider = Google;
        let params = provider.auth_params();

        assert!(params.contains(&("access_type", "offline")));
        assert!(params.contains(&("prompt", "consent")));
    }
}
