//! OAuth provider abstraction
//!
//! Provides the `OAuthProvider` trait for implementing OAuth providers.

use core::fmt;

use crate::error::OAuthErrorKind;

/// Trait for OAuth provider implementations
///
/// Implement this trait to add support for new OAuth providers. The trait
/// provides all the information needed to perform OAuth flows (authorization
/// URL generation, token exchange, token refresh) and classify errors.
///
/// # Example
///
/// ```
/// use core_auth::provider::OAuthProvider;
/// use core_auth::error::OAuthErrorKind;
///
/// struct CustomProvider;
///
/// impl OAuthProvider for CustomProvider {
///     fn id(&self) -> &str { "custom" }
///     fn display_name(&self) -> &str { "Custom Provider" }
///     fn auth_url(&self) -> &str { "https://auth.example.com/oauth/authorize" }
///     fn token_url(&self) -> &str { "https://auth.example.com/oauth/token" }
///     fn default_scopes(&self) -> &[&str] { &["read", "write"] }
///
///     fn classify_error(&self, status: u16, body: &str) -> OAuthErrorKind {
///         if body.contains("invalid_grant") {
///             OAuthErrorKind::RefreshTokenInvalid
///         } else if status == 429 {
///             OAuthErrorKind::RateLimited
///         } else {
///             OAuthErrorKind::Unknown
///         }
///     }
/// }
/// ```
pub trait OAuthProvider: Send + Sync {
    /// Provider identifier (e.g., "google", "dropbox")
    ///
    /// This should be a lowercase, URL-safe identifier.
    fn id(&self) -> &str;

    /// Human-readable display name (e.g., "Google Drive")
    fn display_name(&self) -> &str;

    /// Authorization endpoint URL
    fn auth_url(&self) -> &str;

    /// Token endpoint URL
    fn token_url(&self) -> &str;

    /// Default scopes for this provider
    ///
    /// These scopes will be used if no custom scopes are specified.
    fn default_scopes(&self) -> &[&str];

    /// Additional authorization URL parameters
    ///
    /// Provider-specific parameters to add to the authorization URL.
    /// For example, Google requires `access_type=offline` to get a refresh token.
    fn auth_params(&self) -> Vec<(&str, &str)> {
        vec![]
    }

    /// Classify an OAuth error response
    ///
    /// Given the HTTP status code and response body, determine the type of error.
    /// This is used to decide whether to retry, re-authenticate, or fail.
    fn classify_error(&self, status: u16, body: &str) -> OAuthErrorKind;

    /// Token validation endpoint (optional)
    ///
    /// If provided, this endpoint can be used to validate tokens without
    /// making a full API request.
    fn validation_endpoint(&self) -> Option<&str> {
        None
    }

    /// Whether this provider uses HTTP Basic Auth for token requests
    ///
    /// Most providers use POST body parameters, but some (like Dropbox)
    /// require HTTP Basic Authentication.
    fn uses_basic_auth(&self) -> bool {
        false
    }

    /// Revocation endpoint (optional)
    ///
    /// If provided, this endpoint can be used to revoke tokens.
    fn revoke_url(&self) -> Option<&str> {
        None
    }
}

/// Configuration for an OAuth client
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OAuthClientConfig {
    /// OAuth client ID
    pub client_id: String,
    /// OAuth client secret
    pub client_secret: String,
    /// Redirect URI for OAuth callback
    pub redirect_uri: String,
}

impl fmt::Debug for OAuthClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthClientConfig")
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .field("redirect_uri", &self.redirect_uri)
            .finish()
    }
}

impl OAuthClientConfig {
    /// Create a new OAuth client configuration
    pub fn new(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            redirect_uri: redirect_uri.into(),
        }
    }
}
