//! Microsoft OAuth provider
//!
//! Supports OneDrive, SharePoint, and other Microsoft 365 APIs.
//!
//! # Token Expiration
//!
//! - Access tokens expire after 1 hour
//! - Refresh tokens have a 90-day sliding window (extended on each use)
//! - Refresh tokens are invalidated when:
//!   - User revokes access
//!   - User changes password
//!   - Admin revokes consent
//!   - 90 days pass without use

use crate::error::OAuthErrorKind;
use crate::provider::OAuthProvider;
use crate::types::OAuthErrorResponse;

/// Microsoft OAuth provider
///
/// By default, uses the "common" tenant which allows both personal and
/// organizational accounts. Use `Microsoft::with_tenant` for specific tenants.
///
/// # Example
///
/// ```
/// use core_auth::providers::Microsoft;
/// use core_auth::provider::OAuthProvider;
///
/// // Default (common tenant)
/// let provider = Microsoft::default();
/// assert_eq!(provider.id(), "microsoft");
///
/// // Specific tenant
/// let provider = Microsoft::with_tenant("contoso.onmicrosoft.com");
/// assert!(provider.auth_url().contains("contoso.onmicrosoft.com"));
/// ```
#[derive(Debug, Clone)]
pub struct Microsoft {
    /// Azure AD tenant ID or domain
    /// - "common" - any Microsoft account (default)
    /// - "organizations" - organizational accounts only
    /// - "consumers" - personal accounts only
    /// - tenant ID or domain - specific organization
    #[allow(dead_code)] // Stored for future use (e.g., tenant-specific API calls)
    tenant: String,
    auth_url: String,
    token_url: String,
}

impl Default for Microsoft {
    fn default() -> Self {
        Self::with_tenant("common")
    }
}

impl Microsoft {
    /// Create a Microsoft provider with a specific tenant
    pub fn with_tenant(tenant: impl Into<String>) -> Self {
        let tenant = tenant.into();
        Self {
            auth_url: format!(
                "https://login.microsoftonline.com/{}/oauth2/v2.0/authorize",
                tenant
            ),
            token_url: format!(
                "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
                tenant
            ),
            tenant,
        }
    }

    /// Create a provider for organizational accounts only
    pub fn organizations() -> Self {
        Self::with_tenant("organizations")
    }

    /// Create a provider for personal accounts only
    pub fn consumers() -> Self {
        Self::with_tenant("consumers")
    }
}

impl OAuthProvider for Microsoft {
    fn id(&self) -> &str {
        "microsoft"
    }

    fn display_name(&self) -> &str {
        "Microsoft"
    }

    fn auth_url(&self) -> &str {
        &self.auth_url
    }

    fn token_url(&self) -> &str {
        &self.token_url
    }

    fn default_scopes(&self) -> &[&str] {
        // offline_access is required to get a refresh token
        &["Files.ReadWrite.All", "offline_access"]
    }

    fn classify_error(&self, _status: u16, body: &str) -> OAuthErrorKind {
        let error: OAuthErrorResponse = serde_json::from_str(body).unwrap_or_default();

        match error.error.as_str() {
            // invalid_grant - refresh token expired or revoked
            "invalid_grant" => OAuthErrorKind::RefreshTokenInvalid,
            // interaction_required - user must re-authenticate
            "interaction_required" => OAuthErrorKind::RefreshTokenInvalid,
            // consent_required - app needs new permissions
            "consent_required" => OAuthErrorKind::RefreshTokenInvalid,
            // Server errors are transient
            "temporarily_unavailable" | "server_error" => OAuthErrorKind::TransientError,
            _ => OAuthErrorKind::Unknown,
        }
    }

    fn validation_endpoint(&self) -> Option<&str> {
        // Use Graph API to validate token
        Some("https://graph.microsoft.com/v1.0/me")
    }

    fn revoke_url(&self) -> Option<&str> {
        // Microsoft doesn't have a standard revocation endpoint
        // Users must revoke via account settings
        None
    }
}

/// OneDrive-specific provider (alias for Microsoft with common tenant)
pub type OneDrive = Microsoft;

/// SharePoint-specific provider configuration
#[derive(Debug, Clone)]
pub struct SharePoint {
    microsoft: Microsoft,
    /// SharePoint site URL
    pub site_url: String,
}

impl SharePoint {
    /// Create a SharePoint provider for a specific site
    pub fn new(site_url: impl Into<String>) -> Self {
        Self {
            microsoft: Microsoft::default(),
            site_url: site_url.into(),
        }
    }

    /// Create with a specific tenant
    pub fn with_tenant(tenant: impl Into<String>, site_url: impl Into<String>) -> Self {
        Self {
            microsoft: Microsoft::with_tenant(tenant),
            site_url: site_url.into(),
        }
    }
}

impl OAuthProvider for SharePoint {
    fn id(&self) -> &str {
        "sharepoint"
    }

    fn display_name(&self) -> &str {
        "SharePoint"
    }

    fn auth_url(&self) -> &str {
        self.microsoft.auth_url()
    }

    fn token_url(&self) -> &str {
        self.microsoft.token_url()
    }

    fn default_scopes(&self) -> &[&str] {
        // SharePoint requires Sites scopes
        &["Sites.ReadWrite.All", "offline_access"]
    }

    fn classify_error(&self, status: u16, body: &str) -> OAuthErrorKind {
        self.microsoft.classify_error(status, body)
    }

    fn validation_endpoint(&self) -> Option<&str> {
        self.microsoft.validation_endpoint()
    }

    fn revoke_url(&self) -> Option<&str> {
        self.microsoft.revoke_url()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_microsoft_default() {
        let provider = Microsoft::default();

        assert_eq!(provider.id(), "microsoft");
        assert!(provider.auth_url().contains("/common/"));
        assert!(provider.token_url().contains("/common/"));
    }

    #[test]
    fn test_microsoft_with_tenant() {
        let provider = Microsoft::with_tenant("contoso.onmicrosoft.com");

        assert!(provider.auth_url().contains("contoso.onmicrosoft.com"));
        assert!(provider.token_url().contains("contoso.onmicrosoft.com"));
    }

    #[test]
    fn test_classify_invalid_grant() {
        let provider = Microsoft::default();
        let body = r#"{"error": "invalid_grant", "error_description": "Token expired"}"#;

        assert_eq!(
            provider.classify_error(400, body),
            OAuthErrorKind::RefreshTokenInvalid
        );
    }

    #[test]
    fn test_classify_interaction_required() {
        let provider = Microsoft::default();
        let body = r#"{"error": "interaction_required"}"#;

        assert_eq!(
            provider.classify_error(400, body),
            OAuthErrorKind::RefreshTokenInvalid
        );
    }

    #[test]
    fn test_scopes_include_offline_access() {
        let provider = Microsoft::default();

        assert!(provider.default_scopes().contains(&"offline_access"));
    }
}
