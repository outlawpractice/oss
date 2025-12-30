//! PKCE (Proof Key for Code Exchange) support
//!
//! PKCE is an extension to OAuth 2.0 that prevents authorization code
//! interception attacks. It's required for public clients (mobile apps,
//! SPAs) and recommended for all OAuth flows.
//!
//! # Usage
//!
//! ```
//! use core_auth::pkce::{generate_code_verifier, generate_code_challenge, generate_state};
//!
//! // Generate PKCE parameters
//! let verifier = generate_code_verifier();
//! let challenge = generate_code_challenge(&verifier);
//! let state = generate_state();
//!
//! // Include challenge in auth URL: &code_challenge={challenge}&code_challenge_method=S256
//! // Store verifier securely until token exchange
//! // Include verifier in token exchange: &code_verifier={verifier}
//! ```

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sha2::{Digest, Sha256};

/// Generate a cryptographically secure code verifier
///
/// The code verifier is a random string between 43-128 characters.
/// This implementation generates 32 random bytes, resulting in a
/// 43-character base64url-encoded string.
///
/// # Example
///
/// ```
/// use core_auth::pkce::generate_code_verifier;
///
/// let verifier = generate_code_verifier();
/// assert!(verifier.len() >= 43);
/// assert!(verifier.len() <= 128);
/// ```
pub fn generate_code_verifier() -> String {
    use rand::Rng;
    let random_bytes: [u8; 32] = rand::rng().random();
    URL_SAFE_NO_PAD.encode(random_bytes)
}

/// Generate a code challenge from a code verifier
///
/// Uses the S256 method (SHA-256 hash, base64url-encoded).
/// The challenge is included in the authorization URL.
///
/// # Example
///
/// ```
/// use core_auth::pkce::{generate_code_verifier, generate_code_challenge};
///
/// let verifier = generate_code_verifier();
/// let challenge = generate_code_challenge(&verifier);
///
/// // Challenge is different from verifier
/// assert_ne!(verifier, challenge);
/// ```
pub fn generate_code_challenge(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let hash = hasher.finalize();
    URL_SAFE_NO_PAD.encode(hash)
}

/// Generate a random state parameter
///
/// The state parameter is used to prevent CSRF attacks and maintain
/// state between the authorization request and callback.
///
/// # Example
///
/// ```
/// use core_auth::pkce::generate_state;
///
/// let state = generate_state();
/// // Store this and verify it matches in the callback
/// ```
pub fn generate_state() -> String {
    use rand::Rng;
    let random_bytes: [u8; 16] = rand::rng().random();
    URL_SAFE_NO_PAD.encode(random_bytes)
}

/// PKCE parameters for an OAuth flow
#[derive(Debug, Clone)]
pub struct PkceParams {
    /// The code verifier (keep secret, use during token exchange)
    pub verifier: String,
    /// The code challenge (include in authorization URL)
    pub challenge: String,
    /// The state parameter (include in authorization URL, verify in callback)
    pub state: String,
}

impl PkceParams {
    /// Generate new PKCE parameters
    pub fn generate() -> Self {
        let verifier = generate_code_verifier();
        let challenge = generate_code_challenge(&verifier);
        let state = generate_state();

        Self {
            verifier,
            challenge,
            state,
        }
    }
}

impl Default for PkceParams {
    fn default() -> Self {
        Self::generate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_code_verifier_length() {
        let verifier = generate_code_verifier();
        // 32 bytes base64url encoded = 43 chars
        assert_eq!(verifier.len(), 43);
    }

    #[test]
    fn test_code_verifier_unique() {
        let v1 = generate_code_verifier();
        let v2 = generate_code_verifier();
        assert_ne!(v1, v2);
    }

    #[test]
    fn test_code_verifier_valid_chars() {
        let verifier = generate_code_verifier();
        // Base64url uses A-Z, a-z, 0-9, -, _
        assert!(verifier.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn test_code_challenge_deterministic() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = generate_code_challenge(verifier);
        // Known good value from RFC 7636
        assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn test_state_length() {
        let state = generate_state();
        // 16 bytes base64url encoded = 22 chars
        assert_eq!(state.len(), 22);
    }

    #[test]
    fn test_state_unique() {
        let s1 = generate_state();
        let s2 = generate_state();
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_pkce_params() {
        let params = PkceParams::generate();
        assert!(!params.verifier.is_empty());
        assert!(!params.challenge.is_empty());
        assert!(!params.state.is_empty());
        assert_ne!(params.verifier, params.challenge);
    }
}
