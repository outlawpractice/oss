//! OAuth flow operations
//!
//! Implements:
//! - Authorization URL generation
//! - Token exchange (code -> tokens)
//! - Token refresh
//! - Token validation

use std::time::Duration as StdDuration;

use chrono::{Duration, Utc};

use crate::error::{OAuthError, OAuthErrorKind, OAuthResult};
use crate::provider::{OAuthClientConfig, OAuthProvider};
use crate::types::{OAuthErrorResponse, OAuthTokens, TokenResponse};

/// Default timeout for OAuth HTTP requests (30 seconds)
const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Create an HTTP client with sensible defaults for OAuth operations
fn create_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(StdDuration::from_secs(DEFAULT_TIMEOUT_SECS))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

/// Generate the authorization URL for a provider
///
/// # Arguments
///
/// * `provider` - The OAuth provider
/// * `client` - OAuth client configuration
/// * `state` - State parameter for CSRF protection
/// * `scopes` - Optional custom scopes (uses provider defaults if None)
/// * `pkce_challenge` - Optional PKCE code challenge
///
/// # Example
///
/// ```ignore
/// use core_auth::oauth::generate_auth_url;
/// use core_auth::providers::Google;
/// use core_auth::provider::OAuthClientConfig;
///
/// let client = OAuthClientConfig::new(
///     "client_id",
///     "client_secret",
///     "https://example.com/callback",
/// );
///
/// let url = generate_auth_url(&Google, &client, "random_state", None, None);
/// ```
pub fn generate_auth_url<P: OAuthProvider>(
    provider: &P,
    client: &OAuthClientConfig,
    state: &str,
    scopes: Option<&[&str]>,
    pkce_challenge: Option<&str>,
) -> String {
    let scopes_str = scopes
        .map(|s| s.join(" "))
        .unwrap_or_else(|| provider.default_scopes().join(" "));

    let mut url = format!(
        "{}?client_id={}&redirect_uri={}&response_type=code&state={}",
        provider.auth_url(),
        urlencoding::encode(&client.client_id),
        urlencoding::encode(&client.redirect_uri),
        urlencoding::encode(state),
    );

    // Add scopes if not empty
    if !scopes_str.is_empty() {
        url.push_str(&format!("&scope={}", urlencoding::encode(&scopes_str)));
    }

    // Add provider-specific parameters
    for (key, value) in provider.auth_params() {
        url.push_str(&format!(
            "&{}={}",
            urlencoding::encode(key),
            urlencoding::encode(value)
        ));
    }

    // Add PKCE challenge if provided
    if let Some(challenge) = pkce_challenge {
        url.push_str(&format!(
            "&code_challenge={}&code_challenge_method=S256",
            urlencoding::encode(challenge)
        ));
    }

    url
}

/// Exchange an authorization code for tokens
///
/// # Arguments
///
/// * `provider` - The OAuth provider
/// * `client` - OAuth client configuration
/// * `code` - Authorization code from callback
/// * `pkce_verifier` - Optional PKCE code verifier
///
/// # Errors
///
/// Returns an error if the token exchange fails.
pub async fn exchange_code<P: OAuthProvider>(
    provider: &P,
    client: &OAuthClientConfig,
    code: &str,
    pkce_verifier: Option<&str>,
) -> OAuthResult<OAuthTokens> {
    let http_client = create_http_client();

    let mut params = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", client.redirect_uri.as_str()),
    ];

    // Add PKCE verifier if provided
    let verifier_string;
    if let Some(verifier) = pkce_verifier {
        verifier_string = verifier.to_string();
        params.push(("code_verifier", &verifier_string));
    }

    let request = if provider.uses_basic_auth() {
        // Some providers (like Dropbox) require HTTP Basic Auth
        http_client
            .post(provider.token_url())
            .basic_auth(&client.client_id, Some(&client.client_secret))
            .form(&params)
    } else {
        // Most providers use POST body parameters
        params.push(("client_id", client.client_id.as_str()));
        params.push(("client_secret", client.client_secret.as_str()));
        http_client.post(provider.token_url()).form(&params)
    };

    let response = request.send().await?;
    let status = response.status().as_u16();

    if !response.status().is_success() {
        let error_text = response.text().await.unwrap_or_default();
        return Err(classify_and_create_error(provider, status, &error_text));
    }

    let token_response: TokenResponse = response.json().await.map_err(|e| {
        OAuthError::InvalidResponse(format!("Failed to parse token response: {}", e))
    })?;

    let expires_at = token_response.expires_in.map(|secs| {
        (Utc::now() + Duration::seconds(secs))
            .to_rfc3339()
    });

    Ok(OAuthTokens {
        access_token: token_response.access_token,
        refresh_token: token_response.refresh_token,
        expires_at,
    })
}

/// Refresh an access token
///
/// # Arguments
///
/// * `provider` - The OAuth provider
/// * `client` - OAuth client configuration
/// * `refresh_token` - Current refresh token
///
/// # Errors
///
/// Returns appropriate error types based on provider-specific error classification:
/// - `RefreshTokenInvalid` - User must re-authenticate
/// - `RateLimited` - Should back off before retrying
/// - `ProviderUnavailable` - Transient error, can retry
pub async fn refresh_token<P: OAuthProvider>(
    provider: &P,
    client: &OAuthClientConfig,
    refresh_token: &str,
) -> OAuthResult<OAuthTokens> {
    let http_client = create_http_client();

    let params = [
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
    ];

    let request = if provider.uses_basic_auth() {
        http_client
            .post(provider.token_url())
            .basic_auth(&client.client_id, Some(&client.client_secret))
            .form(&params)
    } else {
        http_client
            .post(provider.token_url())
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
                ("client_id", client.client_id.as_str()),
                ("client_secret", client.client_secret.as_str()),
            ])
    };

    let response = request.send().await?;
    let status = response.status().as_u16();

    if !response.status().is_success() {
        let error_text = response.text().await.unwrap_or_default();
        return Err(classify_and_create_error(provider, status, &error_text));
    }

    let token_response: TokenResponse = response.json().await.map_err(|e| {
        OAuthError::InvalidResponse(format!("Failed to parse token response: {}", e))
    })?;

    let expires_at = token_response.expires_in.map(|secs| {
        (Utc::now() + Duration::seconds(secs))
            .to_rfc3339()
    });

    // Some providers return a new refresh token, others don't
    // If no new refresh token is returned, preserve the existing one
    let new_refresh_token = token_response
        .refresh_token
        .or_else(|| Some(refresh_token.to_string()));

    Ok(OAuthTokens {
        access_token: token_response.access_token,
        refresh_token: new_refresh_token,
        expires_at,
    })
}

/// Validate an access token
///
/// Makes a lightweight API call to verify the token is valid.
/// Only works for providers that have a validation endpoint configured.
///
/// # Arguments
///
/// * `provider` - The OAuth provider
/// * `access_token` - Access token to validate
///
/// # Returns
///
/// `Ok(true)` if the token is valid, `Ok(false)` if invalid,
/// or an error if the validation request fails.
pub async fn validate_token<P: OAuthProvider>(
    provider: &P,
    access_token: &str,
) -> OAuthResult<bool> {
    let endpoint = provider.validation_endpoint().ok_or_else(|| {
        OAuthError::InvalidResponse(format!(
            "Provider {} does not support token validation",
            provider.id()
        ))
    })?;

    let http_client = create_http_client();

    let response = http_client
        .get(endpoint)
        .bearer_auth(access_token)
        .send()
        .await?;

    Ok(response.status().is_success())
}

/// Revoke a token
///
/// Revokes the given token if the provider supports revocation.
///
/// # Arguments
///
/// * `provider` - The OAuth provider
/// * `client` - OAuth client configuration
/// * `token` - Token to revoke (usually refresh token)
///
/// # Errors
///
/// Returns an error if revocation is not supported or fails.
pub async fn revoke_token<P: OAuthProvider>(
    provider: &P,
    client: &OAuthClientConfig,
    token: &str,
) -> OAuthResult<()> {
    let endpoint = provider.revoke_url().ok_or_else(|| {
        OAuthError::InvalidResponse(format!(
            "Provider {} does not support token revocation",
            provider.id()
        ))
    })?;

    let http_client = create_http_client();

    let params = [("token", token)];

    let response = if provider.uses_basic_auth() {
        http_client
            .post(endpoint)
            .basic_auth(&client.client_id, Some(&client.client_secret))
            .form(&params)
            .send()
            .await?
    } else {
        http_client
            .post(endpoint)
            .form(&[
                ("token", token),
                ("client_id", client.client_id.as_str()),
                ("client_secret", client.client_secret.as_str()),
            ])
            .send()
            .await?
    };

    if !response.status().is_success() {
        let error_text = response.text().await.unwrap_or_default();
        return Err(OAuthError::TokenExchangeFailed(format!(
            "Token revocation failed: {}",
            error_text
        )));
    }

    Ok(())
}

/// Classify an OAuth error and create the appropriate error type
fn classify_and_create_error<P: OAuthProvider>(
    provider: &P,
    status: u16,
    body: &str,
) -> OAuthError {
    let error_kind = provider.classify_error(status, body);

    // Try to parse error details
    let error_response: OAuthErrorResponse = serde_json::from_str(body).unwrap_or_default();
    let error_msg = error_response
        .error_description
        .unwrap_or_else(|| error_response.error.clone());

    match error_kind {
        OAuthErrorKind::RefreshTokenInvalid => OAuthError::RefreshTokenInvalid(format!(
            "Provider {} refresh token is invalid or revoked: {}",
            provider.id(),
            error_msg
        )),
        OAuthErrorKind::RateLimited => OAuthError::RateLimited {
            retry_after: parse_retry_after(body),
        },
        OAuthErrorKind::TransientError => OAuthError::ProviderUnavailable(format!(
            "Provider {} temporarily unavailable: {}",
            provider.id(),
            error_msg
        )),
        OAuthErrorKind::Unknown => OAuthError::TokenExchangeFailed(format!(
            "OAuth error ({}): {}",
            status, error_msg
        )),
    }
}

/// Try to parse a retry-after value from error response
fn parse_retry_after(body: &str) -> Option<core::time::Duration> {
    // Try to find retry-after in various formats
    // This is a simplified implementation
    if let Some(start) = body.find("retry_after") {
        if let Some(num_start) = body[start..].find(|c: char| c.is_ascii_digit()) {
            let num_str: String = body[start + num_start..]
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect();
            if let Ok(secs) = num_str.parse::<u64>() {
                return Some(core::time::Duration::from_secs(secs));
            }
        }
    }
    None
}
