use aws_config::profile::{ProfileFileCredentialsProvider, ProfileFileRegionProvider};
use aws_config::{BehaviorVersion, ConfigLoader};
use aws_sdk_sns::{Client};
use base64::{engine::general_purpose, Engine as _};
use openssl::hash::MessageDigest;
use openssl::sign::Verifier;
use openssl::x509::X509;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;

/// A key/value pair from SNS Attributes section
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub enum NotificationAttribute {
    /// key and the parsed string value
    #[serde(rename = "String")]
    String(String, String),

    /// key and the parsed string array (or None if no strings)
    #[serde(rename = "String.Array")]
    StringArray(String, Vec<String>),

    /// key and the parsed number
    #[serde(rename = "Number")]
    Number(String, f64),

    /// key and the decoded Binary
    #[serde(rename = "Binary")]
    Binary(String, Vec<u8>),
}

// Full map of NotificationAttributes
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct MessageAttributes(HashMap<String, String>);

/// The full SNS message format
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct  SnsMessage {
    #[serde(rename = "Type")]
    pub message_type: String,

    #[serde(rename = "MessageId")]
    pub message_id: String,

    #[serde(default, rename = "Token")]
    pub token: Option<String>,

    #[serde(rename = "TopicArn")]
    pub topic_arn: String,

    #[serde(rename = "Message")]
    pub message: String,

    #[serde(default, rename = "SubscribeURL")]
    pub subscribe_url: Option<String>,

    #[serde(rename = "SignatureVersion")]
    pub signature_version: String,

    #[serde(rename = "Signature")]
    pub signature: String,

    #[serde(rename = "SigningCertURL")]
    pub signing_cert_url: String,

    #[serde(rename = "Timestamp")]
    pub timestamp: String,

    #[serde(default, rename = "UnsubscribeURL")]
    pub unsubscribe_url: Option<String>,

    #[serde(rename = "MessageAttributes")]
    pub message_attributes: Option<HashMap<String, NotificationAttribute>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnsNotificationMessage {
    #[serde(rename = "AuthenticateOnUnsubscribe")]
    authenticate_on_unsubscribe: Option<bool>,

    #[serde(rename = "Token")]
    token: String,

    #[serde(rename = "TopicArn")]
    topic_arn: String,
}

/// Constructs the string to sign for a SubscriptionConfirmation message according to AWS SNS guidelines.
/// For SubscriptionConfirmation (and UnsubscribeConfirmation) messages, the string to sign is:
///
/// ```text
/// Message
/// <Message value>
/// MessageId
/// <MessageId value>
/// SubscribeURL
/// <SubscribeURL value>
/// Timestamp
/// <Timestamp value>
/// Token
/// <Token value>
/// TopicArn
/// <TopicArn value>
/// Type
/// <Type value>
/// ```
///
/// Note that each label and value is separated by a newline character.
fn build_string_to_sign(subscription: &SnsMessage) -> String {
    format!(
        "Message\n{}\nMessageId\n{}\nSubscribeURL\n{}\nTimestamp\n{}\nToken\n{}\nTopicArn\n{}\nType\n{}",
        subscription.message,
        subscription.message_id,
        subscription.subscribe_url.clone().unwrap_or_default(),
        subscription.timestamp,
        subscription.token.clone().unwrap_or_default(),
        subscription.topic_arn,
        subscription.message_type,
    )
}

/// Validates the SNS subscription message by verifying its signature.
///
/// This function performs the following steps:
/// 1. Checks that the SigningCertURL looks valid (must use HTTPS and come from AWS SNS).
/// 2. Downloads the certificate from the SigningCertURL.
/// 3. Parses the certificate using OpenSSL.
/// 4. Builds the string to sign from the message.
/// 5. Decodes the signature from Base64.
/// 6. Verifies the signature using the public key from the certificate.
async fn validate_subscription_message(subscription: &SnsMessage) -> Result<(), Box<dyn Error>> {
    // Validate the SigningCertURL. According to AWS guidelines, it should:
    // - Use HTTPS
    // - Belong to an AWS SNS domain (e.g., "sns.<region>.amazonaws.com")
    // - End with "SimpleNotificationService.pem"
    if !subscription.signing_cert_url.starts_with("https://sns.") {
        return Err("Invalid SigningCertURL".into());
    }

    // Download the signing certificate.
    let cert_response = reqwest::get(&subscription.signing_cert_url).await?;
    let cert_pem = cert_response.text().await?;

    // Parse the certificate from PEM format.
    let cert = X509::from_pem(cert_pem.as_bytes())?;

    // Build the string to sign.
    let string_to_sign = build_string_to_sign(subscription);

    // Decode the signature from Base64.
    let signature_bytes = general_purpose::STANDARD.decode(&subscription.signature);
    if signature_bytes.is_err() {
        return Err("Could not decode signature".into());
    };
    let signature = signature_bytes.unwrap();

    // Verify the signature using the public key from the certificate.
    let public_key = cert.public_key();
    if public_key.is_err() {
        return Err("Could not decode public key".into());
    };
    let public_key = public_key.unwrap();

    let mut verifier = Verifier::new(MessageDigest::sha1(), &public_key)?;
    verifier.update(string_to_sign.as_bytes())?;
    let is_valid = verifier.verify(&signature);
    if is_valid.is_err() {
        return Err("Signature verification failed".into());
    }

    Ok(())
}

/// Processes an AWS SNS subscription confirmation message by first authenticating it
/// (via signature verification) and then calling the ConfirmSubscription API.
///
/// # Arguments
///
/// * `message_json` - A JSON string representing the SNS message.
///
/// # Returns
///
/// An `Ok(())` if the message is valid, and the subscription is confirmed, or an error
/// if signature verification or the AWS API call fails.
pub async fn confirm_subscription(subscription: &SnsMessage) -> Result<(), Box<dyn Error>> {
    println!("Confirming subscription: {:?}", subscription);

    if subscription.message_type != "SubscriptionConfirmation" {
        return Err(format!(
            "Received a message of type '{}'. Ignoring since it is not a subscription confirmation.",
            subscription.message_type
        ).into());
    }

    // Authenticate and validate the subscription message.
    validate_subscription_message(subscription).await?;

    // Load AWS configuration from the environment.
    // Create a credential provider that reads from your profile.
    let credentials_provider = ProfileFileCredentialsProvider::builder()
        .profile_name("email") // Replace with your desired profile.
        .build();

    // Create a region provider that uses the same profile.
    let region_provider = ProfileFileRegionProvider::builder()
        .profile_name("email") // Replace with your desired profile.
        .build();

    // Build a custom config loader with your providers.
    let config = ConfigLoader::default()
        .profile_name("email")
        .region(region_provider)
        .credentials_provider(credentials_provider)
        .behavior_version(BehaviorVersion::v2024_03_28())
        .load()
        .await;

    let client = Client::new(&config);

    // Call the ConfirmSubscription API.
    if subscription.token.is_none() {
        return Err("No token was provided".into());
    }

    let response = client
        .confirm_subscription()
        .topic_arn(&subscription.topic_arn)
        .token(subscription.token.clone().unwrap())
        .send()
        .await?;

    println!("Subscription confirmed: {:?}", response);
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_this() {}
}
