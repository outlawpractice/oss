use aws_config::profile::{ProfileFileCredentialsProvider, ProfileFileRegionProvider};
use aws_config::{BehaviorVersion, ConfigLoader};
use aws_sdk_sesv2::error::SdkError;
use aws_sdk_sesv2::primitives::Blob;
use aws_sdk_sesv2::types::{Body, Content, Destination, EmailContent, Message, RawMessage};
use aws_sdk_sesv2::Client;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::fmt::{Debug, Display};
use textnonce::TextNonce;
use validator::{Validate, ValidateEmail, ValidateLength, ValidationError};

pub const SUCCESS_EMAIL: &str = "success@simulator.amazon.com";
pub const BOUNCE_EMAIL: &str = "bounce@simulator.amazon.com";
pub const OUT_OF_THE_OFFICE_EMAIL: &str = "ooto@simulator.amazon.com";
pub const COMPLAINT_EMAIL: &str = "complaint@simulator.amazon.com";
pub const SUPPRESSION_LIST_EMAIL: &str = "suppressionlist@simulator.amazon.com";

const NEWLINE: &str = "\n";

/// When we call SES to send email, it is not always apparent if the email was processed
/// or not.  For example, if we get an error back indicating that the return message
/// was garbled or lost connection before finishing, we do not know if the emails were processed.
///
/// This only tells you if the emails were successfully **processed** by SES, not if the email
/// was successfully **sent**.  You need to use AWS SNS to determine if each of the recipients
/// actually received the email, as there are any number of reasons an email might fail, either
/// initially (mailbox full) or permanently (no such email address).
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub enum WasEmailProcessed {
    No,
    Yes,
    Maybe,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub enum ContentEncoding {
    /// Content is currently base64-encoded
    #[serde(rename = "base64")]
    Base64,

    /// Content is currently hex-encoded binary
    #[serde(rename = "hex")]
    Hex,

    /// Content is currently binary-encoded
    #[serde(rename = "binary")]
    Binary,

    /// Content is currently UTF8-encoded
    #[serde(rename = "utf8")]
    Utf8,

    /// Content is currently UTF16LE-encoded
    #[serde(rename = "utf16le")]
    Utf16Le,

    /// Content is currently ucs2-encoded
    #[serde(rename = "ucs2")]
    Ucs2,

    /// Content is currently ascii-encoded (7-bit)
    #[serde(rename = "ascii")]
    Ascii,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub enum ContentDisposition {
    /// Include this content as a separate attachment to the email (not in the body)
    #[serde(rename = "attachment")]
    Attachment,

    /// Include this content inline in the email body
    #[serde(rename = "inline")]
    Inline,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub struct SendEmailResponse {
    /// Was the message processed by SES?
    #[serde(rename = "wasEmailProcessed")]
    pub was_email_processed: WasEmailProcessed,

    /// If the message was successfully processed, this is the message_id
    #[serde(rename = "messageId")]
    pub message_id: Option<String>,

    /// If the message was not successfully processed, this is the error message
    #[serde(rename = "errorMessage")]
    pub error_message: Option<String>,
}

impl Display for SendEmailResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Clone, Serialize, Deserialize, Validate, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
#[serde_as]
pub struct EmailAttachment {
    #[validate(length(min = 1))]
    file_name: String,

    #[validate(length(min = 1))]
    content_type: String, // e.g. application/pdf

    #[serde(default = "default_disposition")] // default disposition is "attachment"
    disposition: ContentDisposition,

    #[serde(default = "default_content_encoding")]
    content_encoding: ContentEncoding,

    #[validate(length(min = 1))]
    #[serde_as(as = "BorrowCow")]
    content: String,
}

#[derive(Clone, Serialize, Deserialize, Validate, PartialEq, Debug)]
pub struct EmailOptions {
    #[validate(length(min = 1), email)]
    pub from: String,

    #[validate(custom(function = "validate_emails"))]
    pub to: Option<Vec<String>>,

    #[validate(custom(function = "validate_emails"))]
    pub cc: Option<Vec<String>>,

    #[validate(custom(function = "validate_emails"))]
    pub bcc: Option<Vec<String>>,

    #[validate(length(min = 1))]
    pub subject: String,

    #[validate(length(min = 1))]
    pub text: Option<String>,

    #[validate(length(min = 1))]
    pub html: Option<String>,

    #[serde(rename = "ReplyTo")]
    #[validate(custom(function = "validate_emails"))]
    pub reply_to: Option<Vec<String>>,

    #[validate(custom(function = "validate_attachments"))]
    pub attachments: Option<Vec<EmailAttachment>>,
}

#[derive(Clone, Debug, PartialEq, Validate, Serialize, Deserialize)]
struct AwsEmailDestination {
    #[validate(custom(function = "validate_emails"))]
    #[serde(rename = "ToAddresses")]
    to_addresses: Vec<String>,

    #[validate(custom(function = "validate_emails"))]
    #[serde(rename = "CcAddresses")]
    cc_addresses: Option<Vec<String>>,

    #[validate(custom(function = "validate_emails"))]
    #[serde(rename = "BccAddresses")]
    bcc_addresses: Option<Vec<String>>,
}

#[derive(Clone, Debug, PartialEq, Validate, Serialize, Deserialize)]
struct AwsEmailData {
    #[validate(length(min = 1))]
    #[serde(rename = "Data")]
    data: String,
}

#[derive(Clone, Debug, PartialEq, Validate, Serialize, Deserialize)]
struct AwsEmailBody {
    #[validate(nested)]
    #[serde(rename = "Text")]
    text: AwsEmailData,

    #[validate(nested)]
    #[serde(rename = "Html")]
    html: AwsEmailData,
}
#[derive(Clone, Debug, PartialEq, Validate, Serialize, Deserialize)]
struct AwsEmailMessage {
    #[validate(nested)]
    #[serde(rename = "Body")]
    body: AwsEmailBody,

    #[validate(nested)]
    #[serde(rename = "Subject")]
    subject: AwsEmailData,
}

#[derive(Clone, Debug, PartialEq, Validate, Serialize, Deserialize)]
struct AwsEmail {
    #[validate(nested)]
    #[serde(rename = "Destination")]
    destination: AwsEmailDestination,

    #[validate(nested)]
    #[serde(rename = "Message")]
    message: AwsEmailMessage,

    #[validate(email)]
    #[serde(rename = "Source")]
    source: String,
}

impl EmailAttachment {
    pub fn new(
        file_name: &str,
        content_type: &str,
        content: &str,
        content_encoding: ContentEncoding,
        disposition: ContentDisposition,
    ) -> Self {
        EmailAttachment {
            file_name: file_name.to_string(),
            content_type: content_type.to_string(),
            content: content.to_string(),
            content_encoding,
            disposition,
        }
    }
}

/// Set default value of disposition to "attachment"
fn default_disposition() -> ContentDisposition {
    ContentDisposition::Attachment
}

/// By default, we assume attachments are not base64 encoded
fn default_content_encoding() -> ContentEncoding {
    ContentEncoding::Utf8
}

fn validate_emails(emails: &Vec<String>) -> Result<(), ValidationError> {
    for email in emails {
        if !ValidateEmail::validate_email(&email) {
            let mut error = ValidationError::new("invalid_email");
            error.add_param("value".into(), &email);
            return Err(error);
        }
    }
    Ok(())
}

fn validate_attachments(attachments: &Vec<EmailAttachment>) -> Result<(), ValidationError> {
    for attachment in attachments {
        // Check content_type for two strings separated by a "/"
        let parts: Vec<&str> = attachment.content_type.split("/").collect();
        if parts.len() != 2 {
            let mut error = ValidationError::new("malformed content_type");
            error.add_param("value".into(), &attachment.content_type);
            return Err(error);
        }

        // Check
        let mut len = attachment.file_name.length();
        if len.is_none() || len.unwrap() <= 1 {
            return Err(ValidationError::new("no filename"));
        }

        len = attachment.content.length();
        if len.is_none() || len.unwrap() <= 1 {
            return Err(ValidationError::new("no content"));
        }
    }
    Ok(())
}

fn generate_boundary() -> String {
    TextNonce::sized_urlsafe(64).unwrap().into_string()
}

pub async fn send_email(options: &EmailOptions) -> SendEmailResponse {
    // Create a credentials provider that reads from your profile.
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

    // Build the destination addresses from to, cc and bcc
    let dest = Destination::builder()
        .set_to_addresses(options.to.clone())
        .set_cc_addresses(options.cc.clone())
        .set_bcc_addresses(options.bcc.clone())
        .build();

    let subject_content = Content::builder()
        .data(&options.subject)
        .charset("UTF-8")
        .build();

    if subject_content.is_err() {
        return SendEmailResponse {
            was_email_processed: WasEmailProcessed::No,
            message_id: None,
            error_message: Some("Subject text not provided".to_string()),
        };
    }

    let from = &options.from;

    let text_content = Content::builder()
        .data(&options.text.clone().unwrap_or_default())
        .charset("UTF-8")
        .build();

    if text_content.is_err() {
        return SendEmailResponse {
            was_email_processed: WasEmailProcessed::No,
            message_id: None,
            error_message: Some("Invalid text content provided".to_string()),
        };
    };

    let html_content = Content::builder()
        .data(&options.html.clone().unwrap_or_default())
        .charset("UTF-8")
        .build();

    if html_content.is_err() {
        return SendEmailResponse {
            was_email_processed: WasEmailProcessed::No,
            message_id: None,
            error_message: Some(format!(
                "Invalid html content provided: {}",
                html_content.unwrap_err()
            )),
        };
    };

    let body = Body::builder()
        .text(text_content.unwrap())
        .html(html_content.unwrap())
        .build();

    let message = Message::builder()
        .body(body)
        .subject(subject_content.unwrap())
        .build();

    let to_send = if options.attachments.is_none() {
        let email_content = EmailContent::builder().simple(message).build();

        client
            .send_email()
            .from_email_address(from)
            .destination(dest)
            .content(email_content)
            .set_reply_to_addresses(options.reply_to.clone())
    } else {
        let msg = Blob::from(construct_raw_email(options).as_bytes().to_vec());

        let raw_message = RawMessage::builder().data(msg).build().unwrap();

        let email_content = EmailContent::builder().raw(raw_message).build();

        client
            .send_email()
            .from_email_address(from)
            .destination(dest)
            .content(email_content)
            .set_reply_to_addresses(options.reply_to.clone())
    };

    match to_send.send().await {
        Ok(output) => {
            println!(
                "Email sent successfully! Message ID: {:?}",
                output.message_id
            );
            SendEmailResponse {
                was_email_processed: WasEmailProcessed::Yes,
                message_id: Some(output.message_id.unwrap_or_default()),
                error_message: None,
            }
        }
        Err(err) => {
            eprintln!("Error sending email: {:?}", err);

            match err {
                SdkError::ConstructionFailure(err) => {
                    eprintln!("Error constructing email: {:?}", err);
                    SendEmailResponse {
                        was_email_processed: WasEmailProcessed::No,
                        message_id: None,
                        error_message: Some(
                            "Could not construct the email. Email was not sent to any recipients."
                                .to_string(),
                        ),
                    }
                }
                SdkError::ResponseError(err) => {
                    // Was there a body returned?
                    eprintln!("Error sending email: {:?}", err);
                    SendEmailResponse {
                        was_email_processed: WasEmailProcessed::Maybe,
                        message_id: None,
                        error_message: Some(format!(
                            "The server returned a corrupted response. Email may not have been sent. Status: {}",
                            err.raw().status()
                        )),
                    }
                }
                SdkError::ServiceError(err) => {
                    // Was there a body returned?
                    eprintln!("Error sending email: {:?}", err);
                    SendEmailResponse {
                        was_email_processed: WasEmailProcessed::Maybe,
                        message_id: None,
                        error_message: Some(format!(
                            "There was an error sending the message. Status: {}",
                            err.raw().status()
                        )),
                    }
                }
                SdkError::TimeoutError(err) => {
                    // Was there a body returned?
                    eprintln!("Error sending email: {:?}", err);
                    SendEmailResponse {
                        was_email_processed: WasEmailProcessed::Maybe,
                        message_id: None,
                        error_message: Some(
                            "The server timed out while sending the email.".to_string(),
                        ),
                    }
                }
                SdkError::DispatchFailure(err) => SendEmailResponse {
                    was_email_processed: WasEmailProcessed::Maybe,
                    message_id: None,
                    error_message: Some(format!(
                        "There was an error dispatching the email: {:?}",
                        err
                    )),
                },
                _err => SendEmailResponse {
                    was_email_processed: WasEmailProcessed::Maybe,
                    message_id: None,
                    error_message: Some(_err.to_string()),
                },
            }
        }
    }
}

/// Encode an attachment of type text/* into MIME 1.0 format with a given boundary
pub fn encode_text_attachment<'a>(
    boundary: &'a str,
    att: &EmailAttachment,
    is_last: bool,
) -> String {
    let encoding = if att.content_encoding == ContentEncoding::Base64 {
        "base64"
    } else {
        "7bit"
    };

    let disposition = match att.disposition {
        ContentDisposition::Attachment => {
            format!(
                "Content-Disposition: attachment; filename=\"{}\"",
                att.file_name
            )
        }
        ContentDisposition::Inline => "Content-Disposition: inline;".to_string(),
    };

    [
        String::from(""),
        format!("--{}", boundary),
        format!("Content-Type: {}", att.content_type),
        disposition,
        format!("Content-Transfer-Encoding: {}", encoding),
        String::from(""),
        att.content.to_string(),
        String::from(""),
        format!("--{}{}", boundary, if is_last { "--" } else { "" }),
    ]
    .join(NEWLINE)
}

pub fn encode_base64_attachment(boundary: &str, att: &EmailAttachment, is_last: bool) -> String {
    // If the content is not base64-encoded, we need to encode it
    let content = if att.content_encoding != ContentEncoding::Base64 {
        STANDARD.encode(att.content.as_str())
    } else {
        att.content.to_string()
    };

    let disposition = match att.disposition {
        ContentDisposition::Attachment => {
            format!(
                "Content-Disposition: attachment; filename=\"{}\"",
                att.file_name
            )
        }
        ContentDisposition::Inline => "Content-Disposition: inline;".to_string(),
    };

    [
        String::from(""),
        format!("--{}", boundary),
        format!("Content-Type: {}", att.content_type),
        String::from("Content-Transfer-Encoding: base64"),
        disposition,
        String::from(""),
        content,
        String::from(""),
        format!("--{}{}", boundary, if is_last { "--" } else { "" }),
    ]
    .join(NEWLINE)
}

pub fn construct_raw_email(options: &EmailOptions) -> String {
    let mut header = Vec::from([format!("From: {}", options.from)]);
    let outer_boundary = generate_boundary();
    let inner_boundary = generate_boundary();

    if let Some(to_field) = &options.to {
        header.push(format!("To: {}", to_field.join(", ")));
    }

    if let Some(cc_field) = &options.cc {
        header.push(format!("To: {}", cc_field.join(", ")));
    }

    if let Some(bcc_field) = &options.bcc {
        header.push(format!("To: {}", bcc_field.join(", ")));
    }

    header.push(format!("Subject: {}", &options.subject));
    header.push(String::from("MIME-Version: 1.0"));
    header.push(format!(
        "Content-Type: multipart/mixed; boundary=\"{}\"{}",
        outer_boundary, NEWLINE
    ));

    // Start outer boundary
    header.push(format!("--{}", outer_boundary));

    let has_body = options.text.is_some() || options.html.is_some();

    if has_body {
        header.push(format!(
            "Content-Type: multipart/alternative;boundary=\"{}\"{}",
            inner_boundary, NEWLINE
        ));

        // Handle plain text
        if options.text.is_some() {
            header.push(format!("--{}", inner_boundary));
            header.push(String::from("Content-Type: text/plain; charset=\"UTF-8\""));
            header.push(String::from("Content-Transfer-Encoding: 7bit"));
            header.push(String::from(NEWLINE));
            header.push(String::from(&options.text.clone().unwrap()));
            header.push(String::from(""));
        };

        // Handle HTML
        if options.html.is_some() {
            header.push(format!("--{}", inner_boundary));
            header.push(String::from("Content-Type: text/html; charset=\"UTF-8\""));
            header.push(String::from("Content-Transfer-Encoding: 7bit"));
            header.push(String::from(NEWLINE));
            header.push(String::from(&options.html.clone().unwrap()));
            header.push(String::from(""));
        };

        header.push(format!("--{}--{}", inner_boundary, NEWLINE));
    }

    if let Some(attachments) = &options.attachments {
        let attachment_count = attachments.len();
        let mut attachment_number = 0;

        for attachment in attachments {
            attachment_number += 1;

            if attachment.content_type.starts_with("text/") {
                header.push(encode_text_attachment(
                    &outer_boundary,
                    attachment,
                    attachment_number == attachment_count,
                ));
            } else {
                header.push(encode_base64_attachment(
                    &outer_boundary,
                    attachment,
                    attachment_number == attachment_count,
                ));
            }
        }
    }

    header.join(NEWLINE)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PDF_AS_BASE64: &str = "JVBERi0xLjMKJf////8KNyAwIG9iago8PAovVHlwZSAvUGFnZQovUGFyZW50IDEgMCBSCi9NZWRpYUJveCBbMCAwIDYxMiA3OTJdCi9Db250ZW50cyA1IDAgUgovUmVzb3VyY2VzIDYgMCBSCj4+CmVuZG9iago2IDAgb2JqCjw8Ci9Qcm9jU2V0IFsvUERGIC9UZXh0IC9JbWFnZUIgL0ltYWdlQyAvSW1hZ2VJXQovRm9udCA8PAovRjEgOCAwIFIKPj4KL0NvbG9yU3BhY2UgPDwKPj4KPj4KZW5kb2JqCjUgMCBvYmoKPDwKL0xlbmd0aCA5MwovRmlsdGVyIC9GbGF0ZURlY29kZQo+PgpzdHJlYW0KeJxlyCEKgEAQBdA+p/gXUOfPrjsKYhA02IRpYhJsBu9fLDbLC49QKCpC4b3hvOUR/m6KLwk3OFmnLiNuaRaChrhkH9pcutJ7Mv2kqefSevI8Qg/EKnPIJi8dwRcECmVuZHN0cmVhbQplbmRvYmoKMTAgMCBvYmoKKFBERktpdCkKZW5kb2JqCjExIDAgb2JqCihQREZLaXQpCmVuZG9iagoxMiAwIG9iagooRDoyMDI1MDIwNjAwNTk0NVopCmVuZG9iago5IDAgb2JqCjw8Ci9Qcm9kdWNlciAxMCAwIFIKL0NyZWF0b3IgMTEgMCBSCi9DcmVhdGlvbkRhdGUgMTIgMCBSCj4+CmVuZG9iago4IDAgb2JqCjw8Ci9UeXBlIC9Gb250Ci9CYXNlRm9udCAvSGVsdmV0aWNhCi9TdWJ0eXBlIC9UeXBlMQovRW5jb2RpbmcgL1dpbkFuc2lFbmNvZGluZwo+PgplbmRvYmoKNCAwIG9iago8PAo+PgplbmRvYmoKMyAwIG9iago8PAovVHlwZSAvQ2F0YWxvZwovUGFnZXMgMSAwIFIKL05hbWVzIDIgMCBSCj4+CmVuZG9iagoxIDAgb2JqCjw8Ci9UeXBlIC9QYWdlcwovQ291bnQgMQovS2lkcyBbNyAwIFJdCj4+CmVuZG9iagoyIDAgb2JqCjw8Ci9EZXN0cyA8PAogIC9OYW1lcyBbCl0KPj4KPj4KZW5kb2JqCnhyZWYKMCAxMwowMDAwMDAwMDAwIDY1NTM1IGYgCjAwMDAwMDA3MzEgMDAwMDAgbiAKMDAwMDAwMDc4OCAwMDAwMCBuIAowMDAwMDAwNjY5IDAwMDAwIG4gCjAwMDAwMDA2NDggMDAwMDAgbiAKMDAwMDAwMDIyNiAwMDAwMCBuIAowMDAwMDAwMTE5IDAwMDAwIG4gCjAwMDAwMDAwMTUgMDAwMDAgbiAKMDAwMDAwMDU1MSAwMDAwMCBuIAowMDAwMDAwNDc2IDAwMDAwIG4gCjAwMDAwMDAzOTAgMDAwMDAgbiAKMDAwMDAwMDQxNSAwMDAwMCBuIAowMDAwMDAwNDQwIDAwMDAwIG4gCnRyYWlsZXIKPDwKL1NpemUgMTMKL1Jvb3QgMyAwIFIKL0luZm8gOSAwIFIKL0lEIFs8MTA0MTQ0MTNlMTMyYzA5YTE3ZDAyODBhOGI0NTE2MWI+IDwxMDQxNDQxM2UxMzJjMDlhMTdkMDI4MGE4YjQ1MTYxYj5dCj4+CnN0YXJ0eHJlZgo4MzUKJSVFT0YK";

    const TEXT: &str = r#"A Transaction Has Been Approved.
On 01/01/2021, a trust transaction for $100.00 was approved."#;

    const HTML: &str = r#"<html lang="en-US">
    <header>
        <style>body {margin: 1em;font-family: Arial, sans-serif;font-size: 11px;}h1 {font-size: 14px;font-weight: bold;}</style>
    </header>
    <body>
        <h1>A Transaction Has Been Approved</h1>
        <p>On 01/01/2021, a trust transaction for $100.00 was approved.</p>
    </body>
</html>"#;

    fn create_options(to: &str) -> EmailOptions {
        EmailOptions {
            from: "payments@outlawpayments.com".to_string(),
            to: Some(vec![to.to_string()]),
            cc: None,
            bcc: None,
            subject: "Your payment has been accepted".to_string(),
            text: Some("Thank you for your payment of $25.00.".to_string()),
            html: Some("<h1>Thank you for your payment</h1>".to_string()),
            reply_to: None,
            attachments: None,
        }
    }

    // #[tokio::test]
    // async fn success_email() {
    //     let email_options = create_options(SUCCESS_EMAIL);
    //
    //     let response = send_email(&email_options).await;
    //     assert_eq!(response.sent, WasEmailSent::Yes);
    //     assert!(response.message_id.is_some());
    //     assert_eq!(response.error_message, None);
    // }

    // #[tokio::test]
    // async fn send_email_with_attachments() {
    //     let mut email_options = create_options("john@margaglione.com");
    //
    //     let attachments = vec![
    //         EmailAttachment::new("test.pdf", "application/pdf", PDF_AS_BASE64, true),
    //         EmailAttachment::new("test.txt", "text/plain", TEXT, false),
    //         EmailAttachment::new("test.html", "text/html", HTML, false),
    //     ];
    //
    //     email_options.attachments = Some(attachments);
    //
    //     let response = send_email(&email_options).await;
    //     assert_eq!(response.was_email_processed, WasEmailProcessed::Yes);
    //     assert!(response.message_id.is_some());
    //     assert_eq!(response.error_message, None);
    // }
    #[tokio::test]
    async fn send_email_with_utf8() {
        let mut email_options = create_options("john@margaglione.com");
        email_options.text =
            Some("This is text with UTF-8 characters: ♠ 平仮名, ひらがな".to_string());

        email_options.html =
            Some("<p>This is HTML with UTF-8 characters: ♠ 平仮名, ひらがな</p>".to_string());

        email_options.attachments = Some(vec![EmailAttachment::new(
            "test_utf8.txt",
            "text/plain",
            "This is inline content: ♠ 平仮名, ひらがな",
            ContentEncoding::Utf8,
            ContentDisposition::Attachment,
        )]);

        let response = send_email(&email_options).await;
        assert_eq!(response.was_email_processed, WasEmailProcessed::Yes);
        assert!(response.message_id.is_some());
        assert_eq!(response.error_message, None);
    }
}
