//! Dropbox OAuth provider
//!
//! # Token Expiration
//!
//! - Short-lived access tokens expire after 4 hours
//! - With `token_access_type=offline`, access tokens expire after 4 hours
//!   but refresh tokens NEVER expire (unless manually revoked)
//! - Dropbox requires HTTP Basic Authentication for token requests

use crate::error::OAuthErrorKind;
use crate::provider::OAuthProvider;
use crate::types::OAuthErrorResponse;

/// Dropbox OAuth provider
///
/// # Example
///
/// ```
/// use core_auth::providers::Dropbox;
/// use core_auth::provider::OAuthProvider;
///
/// let provider = Dropbox;
/// assert_eq!(provider.id(), "dropbox");
/// assert!(provider.uses_basic_auth()); // Dropbox requires Basic Auth
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct Dropbox;

impl OAuthProvider for Dropbox {
    fn id(&self) -> &str {
        "dropbox"
    }

    fn display_name(&self) -> &str {
        "Dropbox"
    }

    fn auth_url(&self) -> &str {
        "https://www.dropbox.com/oauth2/authorize"
    }

    fn token_url(&self) -> &str {
        "https://api.dropboxapi.com/oauth2/token"
    }

    fn default_scopes(&self) -> &[&str] {
        // Dropbox doesn't use traditional scopes
        // Permissions are configured in the app console
        &[]
    }

    fn auth_params(&self) -> Vec<(&str, &str)> {
        // token_access_type=offline gives us a refresh token
        // that never expires
        vec![("token_access_type", "offline")]
    }

    fn classify_error(&self, status: u16, body: &str) -> OAuthErrorKind {
        let error: OAuthErrorResponse = serde_json::from_str(body).unwrap_or_default();

        match (status, error.error.as_str()) {
            // 400 with invalid_grant - token revoked by user
            (400, "invalid_grant") => OAuthErrorKind::RefreshTokenInvalid,
            // 401 - unauthorized, token invalid
            (401, _) => OAuthErrorKind::RefreshTokenInvalid,
            // 429 - rate limited
            (429, _) => OAuthErrorKind::RateLimited,
            // 5xx - server error, transient
            (500..=599, _) => OAuthErrorKind::TransientError,
            _ => OAuthErrorKind::Unknown,
        }
    }

    fn validation_endpoint(&self) -> Option<&str> {
        // Check current account to validate token
        Some("https://api.dropboxapi.com/2/users/get_current_account")
    }

    fn uses_basic_auth(&self) -> bool {
        // Dropbox requires HTTP Basic Authentication for token requests
        true
    }

    fn revoke_url(&self) -> Option<&str> {
        Some("https://api.dropboxapi.com/2/auth/token/revoke")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dropbox_provider() {
        let provider = Dropbox;

        assert_eq!(provider.id(), "dropbox");
        assert_eq!(provider.display_name(), "Dropbox");
        assert!(provider.auth_url().contains("dropbox.com"));
        assert!(provider.token_url().contains("dropboxapi.com"));
    }

    #[test]
    fn test_uses_basic_auth() {
        let provider = Dropbox;
        assert!(provider.uses_basic_auth());
    }

    #[test]
    fn test_auth_params_offline() {
        let provider = Dropbox;
        let params = provider.auth_params();

        assert!(params.contains(&("token_access_type", "offline")));
    }

    #[test]
    fn test_classify_invalid_grant() {
        let provider = Dropbox;
        let body = r#"{"error": "invalid_grant"}"#;

        assert_eq!(
            provider.classify_error(400, body),
            OAuthErrorKind::RefreshTokenInvalid
        );
    }

    #[test]
    fn test_classify_401() {
        let provider = Dropbox;

        assert_eq!(
            provider.classify_error(401, "{}"),
            OAuthErrorKind::RefreshTokenInvalid
        );
    }

    #[test]
    fn test_classify_rate_limit() {
        let provider = Dropbox;

        assert_eq!(
            provider.classify_error(429, "{}"),
            OAuthErrorKind::RateLimited
        );
    }

    #[test]
    fn test_classify_server_error() {
        let provider = Dropbox;

        assert_eq!(
            provider.classify_error(500, "{}"),
            OAuthErrorKind::TransientError
        );
        assert_eq!(
            provider.classify_error(503, "{}"),
            OAuthErrorKind::TransientError
        );
    }
}
