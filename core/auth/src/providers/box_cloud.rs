//! Box OAuth provider
//!
//! # Token Expiration
//!
//! - Access tokens expire after 1 hour
//! - Refresh tokens expire after 60 days of non-use
//! - Each refresh generates a new refresh token (rotate tokens)

use crate::error::OAuthErrorKind;
use crate::provider::OAuthProvider;
use crate::types::OAuthErrorResponse;

/// Box OAuth provider
///
/// # Example
///
/// ```
/// use core_auth::providers::Box;
/// use core_auth::provider::OAuthProvider;
///
/// let provider = Box;
/// assert_eq!(provider.id(), "box");
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct Box;

impl OAuthProvider for Box {
    fn id(&self) -> &str {
        "box"
    }

    fn display_name(&self) -> &str {
        "Box"
    }

    fn auth_url(&self) -> &str {
        "https://account.box.com/api/oauth2/authorize"
    }

    fn token_url(&self) -> &str {
        "https://api.box.com/oauth2/token"
    }

    fn default_scopes(&self) -> &[&str] {
        // Box uses app-level permissions, not OAuth scopes
        &[]
    }

    fn classify_error(&self, _status: u16, body: &str) -> OAuthErrorKind {
        let error: OAuthErrorResponse = serde_json::from_str(body).unwrap_or_default();

        match error.error.as_str() {
            // invalid_grant - refresh token expired (60-day non-use)
            "invalid_grant" => OAuthErrorKind::RefreshTokenInvalid,
            // invalid_token - token was revoked
            "invalid_token" => OAuthErrorKind::RefreshTokenInvalid,
            // server_error - transient issue
            "server_error" => OAuthErrorKind::TransientError,
            _ => OAuthErrorKind::Unknown,
        }
    }

    fn validation_endpoint(&self) -> Option<&str> {
        // Get current user to validate token
        Some("https://api.box.com/2.0/users/me")
    }

    fn revoke_url(&self) -> Option<&str> {
        Some("https://api.box.com/oauth2/revoke")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_box_provider() {
        let provider = Box;

        assert_eq!(provider.id(), "box");
        assert_eq!(provider.display_name(), "Box");
        assert!(provider.auth_url().contains("box.com"));
        assert!(provider.token_url().contains("box.com"));
    }

    #[test]
    fn test_does_not_use_basic_auth() {
        let provider = Box;
        assert!(!provider.uses_basic_auth());
    }

    #[test]
    fn test_classify_invalid_grant() {
        let provider = Box;
        let body = r#"{"error": "invalid_grant"}"#;

        assert_eq!(
            provider.classify_error(400, body),
            OAuthErrorKind::RefreshTokenInvalid
        );
    }

    #[test]
    fn test_classify_invalid_token() {
        let provider = Box;
        let body = r#"{"error": "invalid_token"}"#;

        assert_eq!(
            provider.classify_error(401, body),
            OAuthErrorKind::RefreshTokenInvalid
        );
    }

    #[test]
    fn test_classify_server_error() {
        let provider = Box;
        let body = r#"{"error": "server_error"}"#;

        assert_eq!(
            provider.classify_error(500, body),
            OAuthErrorKind::TransientError
        );
    }

    #[test]
    fn test_has_revoke_url() {
        let provider = Box;
        assert!(provider.revoke_url().is_some());
    }
}
