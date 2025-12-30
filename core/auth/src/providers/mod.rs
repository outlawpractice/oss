//! Built-in OAuth provider implementations
//!
//! This module provides ready-to-use implementations of `OAuthProvider`
//! for common cloud storage and calendar providers.

mod google;
mod microsoft;
mod dropbox;
mod box_cloud;

pub use google::{Google, GoogleWithScopes};
pub use microsoft::{Microsoft, OneDrive, SharePoint};
pub use dropbox::Dropbox;
pub use box_cloud::Box;
