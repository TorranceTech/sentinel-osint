//! Hardened HTTP client for collectors.
//!
//! All outbound HTTP in Sentinel goes through [`HttpClient`]. It enforces:
//!
//! - the [`NetworkPolicy`]: HTTPS only, public addresses only, checked before
//!   the request, on every redirect, and at DNS resolution;
//! - at most [`MAX_REDIRECTS`] redirects, and **same-origin only** for
//!   requests that carry secret headers;
//! - connect and total timeouts;
//! - a response size cap, enforced while streaming, so a lying or missing
//!   `Content-Length` does not help an attacker;
//! - a limit on concurrent in-flight requests;
//! - no proxies, no cookies, no automatic decompression, no retries, no
//!   `Referer` header.
//!
//! See `docs/THREAT-MODEL.md` (T3, T4, T6).

mod client;
mod message;
mod policy;
mod resolver;
#[cfg(test)]
mod tests;

use std::time::Duration;

pub use client::HttpClient;
pub use message::{HttpRequest, HttpResponse};
pub use policy::{MAX_REDIRECTS, NetworkPolicy, PolicyViolation, check_ip};

/// The `User-Agent` sent with every request:
/// `sentinel-osint/<version> (+<repository URL>)`. It identifies the tool,
/// never the user. The URL comes from the workspace `repository` field.
#[must_use]
pub fn user_agent() -> String {
    concat!(
        "sentinel-osint/",
        env!("CARGO_PKG_VERSION"),
        " (+",
        env!("CARGO_PKG_REPOSITORY"),
        ")"
    )
    .to_owned()
}

/// Configuration of the HTTP client.
#[derive(Debug, Clone)]
pub struct HttpConfig {
    /// Maximum time to establish a connection (TCP + TLS).
    pub connect_timeout: Duration,
    /// Maximum time for a whole request, including reading the body.
    pub request_timeout: Duration,
    /// Default response size cap, in bytes. Individual requests may lower or
    /// raise it up to [`HttpConfig::MAX_BODY_BYTES_CEILING`].
    pub max_body_bytes: usize,
    /// Maximum number of requests in flight at once, across all collectors.
    pub max_concurrent_requests: usize,
}

impl HttpConfig {
    /// Absolute upper bound for any response body.
    pub const MAX_BODY_BYTES_CEILING: usize = 64 * 1024 * 1024;
    /// Absolute upper bound for a per-request timeout override.
    pub const MAX_REQUEST_TIMEOUT: Duration = Duration::from_mins(1);
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(20),
            max_body_bytes: 5 * 1024 * 1024,
            max_concurrent_requests: 8,
        }
    }
}

/// An HTTP request failed.
///
/// Messages are fixed texts or already-validated values. They never contain
/// URLs, header values, response bodies or other server-provided content,
/// so they are safe to log and show, and they cannot leak secrets.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HttpError {
    /// The destination violates the network policy.
    #[error("request blocked by network policy: {0}")]
    Blocked(#[from] PolicyViolation),
    /// The request did not complete within the timeout.
    #[error("request timed out")]
    Timeout,
    /// No connection could be established.
    #[error("could not connect to the source")]
    Connect,
    /// The response body exceeded the size cap.
    #[error("response exceeded the size limit of {limit} bytes")]
    ResponseTooLarge {
        /// The cap that was exceeded.
        limit: usize,
    },
    /// The request could not be built (e.g. an invalid header value).
    #[error("invalid request: {0}")]
    InvalidRequest(&'static str),
    /// The HTTP client could not be initialized.
    #[error("HTTP client initialization failed")]
    ClientInit,
    /// Any other transport-level failure (protocol error, reset, …).
    #[error("HTTP transport error")]
    Transport,
}
