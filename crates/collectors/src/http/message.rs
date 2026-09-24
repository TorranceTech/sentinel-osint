//! Request and response types.

use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};
use secrecy::{ExposeSecret, SecretString};
use sentinel_core::{HttpMethod, Provenance, Sha256Digest};
use url::Url;

use super::HttpError;

/// An outbound request.
///
/// `Debug` never shows secret header values: they are stored as *sensitive*
/// [`HeaderValue`]s, which render as `Sensitive`.
#[derive(Debug)]
pub struct HttpRequest {
    pub(super) method: HttpMethod,
    pub(super) url: Url,
    pub(super) headers: HeaderMap,
    pub(super) body: Option<Vec<u8>>,
    pub(super) max_body_bytes: Option<usize>,
    pub(super) timeout: Option<std::time::Duration>,
    pub(super) has_secret: bool,
}

impl HttpRequest {
    /// A `GET` request.
    #[must_use]
    pub fn get(url: Url) -> Self {
        Self {
            method: HttpMethod::Get,
            url,
            headers: HeaderMap::new(),
            body: None,
            max_body_bytes: None,
            timeout: None,
            has_secret: false,
        }
    }

    /// A `POST` request with an `application/x-www-form-urlencoded` body.
    #[must_use]
    pub fn post_form<'a>(url: Url, fields: impl IntoIterator<Item = (&'a str, &'a str)>) -> Self {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(fields)
            .finish();
        let mut request = Self::get(url);
        request.method = HttpMethod::Post;
        request.headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        request.body = Some(body.into_bytes());
        request
    }

    /// Adds a non-secret header.
    #[must_use]
    pub fn header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.headers.insert(name, value);
        self
    }

    /// Adds a header carrying a secret (API key).
    ///
    /// The value is marked sensitive, so it is hidden from `Debug` output
    /// and from HTTP/2 header compression tables. Requests with a secret
    /// header only follow **same-origin** redirects, so the key is never
    /// forwarded to another host.
    ///
    /// # Errors
    /// [`HttpError::InvalidRequest`] if the secret contains characters that
    /// are not valid in a header. The secret itself is never included in the
    /// error.
    pub fn secret_header(
        mut self,
        name: HeaderName,
        secret: &SecretString,
    ) -> Result<Self, HttpError> {
        let mut value = HeaderValue::from_str(secret.expose_secret()).map_err(|_| {
            HttpError::InvalidRequest(
                "API key contains characters that are not allowed in an HTTP header",
            )
        })?;
        value.set_sensitive(true);
        self.headers.insert(name, value);
        self.has_secret = true;
        Ok(self)
    }

    /// Overrides the response size cap for this request (clamped to
    /// [`HttpConfig::MAX_BODY_BYTES_CEILING`](super::HttpConfig::MAX_BODY_BYTES_CEILING)).
    #[must_use]
    pub const fn max_body_bytes(mut self, limit: usize) -> Self {
        self.max_body_bytes = Some(limit);
        self
    }

    /// Overrides the client's total request timeout for this request
    /// (clamped to [`HttpConfig::MAX_REQUEST_TIMEOUT`](super::HttpConfig::MAX_REQUEST_TIMEOUT)),
    /// for sources that are known to be slow. The engine's source timeout
    /// and global deadline still apply.
    #[must_use]
    pub const fn timeout(mut self, timeout: std::time::Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// The request URL.
    #[must_use]
    pub const fn url(&self) -> &Url {
        &self.url
    }
}

/// A completed response whose body was read within the size cap.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    method: HttpMethod,
    final_url: Url,
    status: u16,
    body: Vec<u8>,
    digest: Sha256Digest,
}

impl HttpResponse {
    pub(super) fn new(method: HttpMethod, final_url: Url, status: u16, body: Vec<u8>) -> Self {
        let digest = Sha256Digest::of(&body);
        Self {
            method,
            final_url,
            status,
            body,
            digest,
        }
    }

    /// HTTP status code.
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    /// Whether the status is 2xx.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        self.status >= 200 && self.status < 300
    }

    /// The raw body. Untrusted: parse it, never interpret it.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// The URL that produced the response (after redirects).
    #[must_use]
    pub const fn final_url(&self) -> &Url {
        &self.final_url
    }

    /// SHA-256 of the raw body, for the observation's integrity hash.
    #[must_use]
    pub const fn raw_response_hash(&self) -> Sha256Digest {
        self.digest
    }

    /// Provenance for observations derived from this response (final URL,
    /// sanitized).
    #[must_use]
    pub fn provenance(&self) -> Provenance {
        Provenance::https(self.method, &self.final_url, self.status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_hides_secret_headers() {
        let secret = SecretString::from("sk-live-DO-NOT-LEAK");
        let request = HttpRequest::get(Url::parse("https://api.example.com/").unwrap())
            .secret_header(HeaderName::from_static("x-apikey"), &secret)
            .unwrap();
        let debug = format!("{request:?}");
        assert!(!debug.contains("DO-NOT-LEAK"), "{debug}");
        assert!(debug.contains("Sensitive"));
        assert!(request.has_secret);
    }

    #[test]
    fn invalid_secret_error_does_not_echo_the_secret() {
        let secret = SecretString::from("bad\nkey-DO-NOT-LEAK");
        let err = HttpRequest::get(Url::parse("https://api.example.com/").unwrap())
            .secret_header(HeaderName::from_static("x-apikey"), &secret)
            .unwrap_err();
        assert!(!err.to_string().contains("DO-NOT-LEAK"));
        assert!(!format!("{err:?}").contains("DO-NOT-LEAK"));
    }

    #[test]
    fn form_bodies_are_url_encoded() {
        let request = HttpRequest::post_form(
            Url::parse("https://api.example.com/").unwrap(),
            [("query", "get_info"), ("hash", "a b&c")],
        );
        assert_eq!(request.method, HttpMethod::Post);
        assert_eq!(
            request.body.as_deref(),
            Some(&b"query=get_info&hash=a+b%26c"[..])
        );
    }

    #[test]
    fn response_hash_and_provenance() {
        let response = HttpResponse::new(
            HttpMethod::Get,
            Url::parse("https://api.example.com/v1?key=SECRET&q=1").unwrap(),
            200,
            b"{}".to_vec(),
        );
        assert_eq!(response.raw_response_hash(), Sha256Digest::of(b"{}"));
        let Provenance::Https(p) = response.provenance() else {
            panic!("expected https provenance");
        };
        assert_eq!(p.endpoint(), "https://api.example.com/v1?key=REDACTED&q=1");
    }
}
