//! Authentication credential types
//!
//! These types are designed to work in no_std environments when the `std` feature is disabled.

#[cfg(not(feature = "std"))]
use alloc::string::String;

/// OAuth2 credentials for providers that use OAuth
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OAuthCredentials {
    /// Access token for API requests
    pub access_token: String,
    /// Refresh token for obtaining new access tokens
    pub refresh_token: Option<String>,
    /// OAuth client ID (for token refresh)
    pub client_id: Option<String>,
    /// OAuth client secret (for token refresh)
    pub client_secret: Option<String>,
    /// Token expiration time (RFC3339 format)
    pub expires_at: Option<String>,
}

impl OAuthCredentials {
    /// Create credentials with just an access token
    pub fn with_token(access_token: impl Into<String>) -> Self {
        Self {
            access_token: access_token.into(),
            refresh_token: None,
            client_id: None,
            client_secret: None,
            expires_at: None,
        }
    }

    /// Create credentials with access and refresh tokens
    pub fn with_refresh(
        access_token: impl Into<String>,
        refresh_token: impl Into<String>,
    ) -> Self {
        Self {
            access_token: access_token.into(),
            refresh_token: Some(refresh_token.into()),
            client_id: None,
            client_secret: None,
            expires_at: None,
        }
    }

    /// Set the client credentials for token refresh
    pub fn with_client(
        mut self,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> Self {
        self.client_id = Some(client_id.into());
        self.client_secret = Some(client_secret.into());
        self
    }

    /// Set the expiration time
    pub fn with_expires_at(mut self, expires_at: impl Into<String>) -> Self {
        self.expires_at = Some(expires_at.into());
        self
    }

    /// Returns true if token refresh is possible
    pub fn can_refresh(&self) -> bool {
        self.refresh_token.is_some()
            && self.client_id.is_some()
            && self.client_secret.is_some()
    }
}

/// Basic auth credentials (username/password)
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BasicCredentials {
    /// Username
    pub username: String,
    /// Password
    pub password: String,
    /// Base URL for the service (required for WebDAV providers)
    pub base_url: Option<String>,
}

impl BasicCredentials {
    /// Create basic credentials
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
            base_url: None,
        }
    }

    /// Create credentials with a base URL
    pub fn with_url(
        username: impl Into<String>,
        password: impl Into<String>,
        base_url: impl Into<String>,
    ) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
            base_url: Some(base_url.into()),
        }
    }
}

/// AWS S3 credentials
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct S3Credentials {
    /// AWS Access Key ID
    pub access_key_id: String,
    /// AWS Secret Access Key
    pub secret_access_key: String,
    /// AWS region (e.g., "us-west-2")
    pub region: String,
    /// S3 bucket name
    pub bucket: String,
    /// Optional custom endpoint (for S3-compatible services like MinIO)
    pub endpoint: Option<String>,
    /// Optional session token (for temporary credentials)
    pub session_token: Option<String>,
}

impl S3Credentials {
    /// Create S3 credentials
    pub fn new(
        access_key_id: impl Into<String>,
        secret_access_key: impl Into<String>,
        region: impl Into<String>,
        bucket: impl Into<String>,
    ) -> Self {
        Self {
            access_key_id: access_key_id.into(),
            secret_access_key: secret_access_key.into(),
            region: region.into(),
            bucket: bucket.into(),
            endpoint: None,
            session_token: None,
        }
    }

    /// Set a custom endpoint (for MinIO, Backblaze B2, etc.)
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }

    /// Set a session token (for temporary credentials)
    pub fn with_session_token(mut self, token: impl Into<String>) -> Self {
        self.session_token = Some(token.into());
        self
    }
}

/// SharePoint-specific configuration
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SharePointConfig {
    /// OAuth credentials
    pub credentials: OAuthCredentials,
    /// SharePoint site URL (e.g., "https://company.sharepoint.com/sites/SiteName")
    pub site_url: String,
    /// Optional drive ID (defaults to site's default drive)
    pub drive_id: Option<String>,
}

impl SharePointConfig {
    /// Create SharePoint config
    pub fn new(credentials: OAuthCredentials, site_url: impl Into<String>) -> Self {
        Self {
            credentials,
            site_url: site_url.into(),
            drive_id: None,
        }
    }

    /// Set a specific drive ID
    pub fn with_drive(mut self, drive_id: impl Into<String>) -> Self {
        self.drive_id = Some(drive_id.into());
        self
    }
}

/// OAuth tokens returned from token exchange or refresh
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OAuthTokens {
    /// Access token for API requests
    pub access_token: String,
    /// Refresh token for obtaining new access tokens (may not be returned by all flows)
    pub refresh_token: Option<String>,
    /// Token expiration time (RFC3339 format)
    pub expires_at: Option<String>,
}

impl OAuthTokens {
    /// Convert to OAuthCredentials
    pub fn into_credentials(self) -> OAuthCredentials {
        OAuthCredentials {
            access_token: self.access_token,
            refresh_token: self.refresh_token,
            client_id: None,
            client_secret: None,
            expires_at: self.expires_at,
        }
    }

    /// Returns true if a refresh token is available
    pub fn has_refresh_token(&self) -> bool {
        self.refresh_token.is_some()
    }
}

/// OAuth token response from provider (for deserialization)
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize))]
pub struct TokenResponse {
    /// Access token
    pub access_token: String,
    /// Refresh token (may not always be returned)
    pub refresh_token: Option<String>,
    /// Token expiration in seconds
    pub expires_in: Option<i64>,
    /// Token type (usually "Bearer")
    pub token_type: Option<String>,
}

/// OAuth error response from provider (for deserialization)
#[derive(Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize))]
pub struct OAuthErrorResponse {
    /// Error code
    #[cfg_attr(feature = "serde", serde(default))]
    pub error: String,
    /// Error description
    #[cfg_attr(feature = "serde", serde(default))]
    pub error_description: Option<String>,
}
