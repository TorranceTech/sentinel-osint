//! The hardened HTTP client.

use std::error::Error as StdError;
use std::sync::Arc;
use std::time::{Duration, Instant};

use reqwest::redirect;
use sentinel_core::HttpMethod;
use sentinel_core::evidence::sanitize_url;
use tokio::sync::Semaphore;

use super::policy::{MAX_REDIRECTS, NetworkPolicy, PolicyViolation, same_origin};
use super::resolver::PublicOnlyResolver;
use super::{HttpConfig, HttpError, HttpRequest, HttpResponse, user_agent};

/// Shared, cheaply cloneable HTTP client. Create one per process and pass
/// clones around, so the connection pool and the concurrency limit are shared.
#[derive(Debug, Clone)]
pub struct HttpClient {
    /// Follows validated redirects (up to [`MAX_REDIRECTS`]) across origins.
    public: reqwest::Client,
    /// Used for requests with secret headers. Follows **same-origin**
    /// redirects only: reqwest strips `Authorization` on cross-host
    /// redirects, but not custom API-key headers such as `x-apikey`.
    authenticated: reqwest::Client,
    policy: NetworkPolicy,
    config: HttpConfig,
    permits: Arc<Semaphore>,
}

impl HttpClient {
    /// Creates a client with the production network policy (HTTPS only,
    /// public addresses only).
    ///
    /// # Errors
    /// [`HttpError::ClientInit`] if the TLS backend cannot be initialized.
    pub fn new(config: HttpConfig) -> Result<Self, HttpError> {
        Self::with_policy(config, NetworkPolicy::public_https_only())
    }

    /// Creates a client that may also talk plain HTTP to the given loopback
    /// mock servers. Only exists in tests.
    #[cfg(test)]
    pub(crate) fn for_tests(
        config: HttpConfig,
        servers: Vec<std::net::SocketAddr>,
    ) -> Result<Self, HttpError> {
        Self::with_policy(config, NetworkPolicy::with_test_servers(servers))
    }

    fn with_policy(config: HttpConfig, policy: NetworkPolicy) -> Result<Self, HttpError> {
        Ok(Self {
            public: build_client(&config, &policy, RedirectScope::AnyOrigin)?,
            authenticated: build_client(&config, &policy, RedirectScope::SameOrigin)?,
            permits: Arc::new(Semaphore::new(config.max_concurrent_requests.max(1))),
            policy,
            config,
        })
    }

    /// The client configuration.
    #[must_use]
    pub const fn config(&self) -> &HttpConfig {
        &self.config
    }

    /// Sends a request and reads the response body within the size cap.
    ///
    /// Any HTTP status is returned as `Ok`: interpreting it (for example,
    /// a 404 meaning "not found in this source") is up to the collector.
    ///
    /// # Errors
    /// [`HttpError`] for policy violations, timeouts, connection failures,
    /// oversized responses and transport errors.
    pub async fn send(&self, request: HttpRequest) -> Result<HttpResponse, HttpError> {
        self.policy.check_url(&request.url)?;

        let limit = request
            .max_body_bytes
            .unwrap_or(self.config.max_body_bytes)
            .min(HttpConfig::MAX_BODY_BYTES_CEILING);
        let client = if request.has_secret {
            &self.authenticated
        } else {
            &self.public
        };
        let method = request.method;
        // Sanitized and percent-encoded: safe to log.
        let endpoint = sanitize_url(&request.url);

        // The semaphore is never closed, so this cannot fail in practice.
        let _permit = self
            .permits
            .acquire()
            .await
            .map_err(|_| HttpError::Transport)?;

        tracing::debug!(method = ?method, endpoint = %endpoint, "sending request");
        let started = Instant::now();

        let mut builder = match method {
            HttpMethod::Get => client.get(request.url),
            HttpMethod::Post => client.post(request.url),
        }
        .headers(request.headers);
        if let Some(timeout) = request.timeout {
            builder = builder.timeout(timeout.min(HttpConfig::MAX_REQUEST_TIMEOUT));
        }
        if let Some(body) = request.body {
            builder = builder.body(body);
        }

        let mut response = builder.send().await.map_err(|e| map_error(&e))?;
        let status = response.status().as_u16();
        let final_url = response.url().clone();

        let limit_u64 = u64::try_from(limit).unwrap_or(u64::MAX);
        if response.content_length().is_some_and(|len| len > limit_u64) {
            tracing::warn!(endpoint = %endpoint, limit, "response exceeds size limit (Content-Length)");
            return Err(HttpError::ResponseTooLarge { limit });
        }

        // Enforced while streaming: Content-Length may be absent or wrong.
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|e| map_error(&e))? {
            if body.len().saturating_add(chunk.len()) > limit {
                tracing::warn!(endpoint = %endpoint, limit, "response exceeds size limit (streamed)");
                return Err(HttpError::ResponseTooLarge { limit });
            }
            body.extend_from_slice(&chunk);
        }

        tracing::debug!(
            endpoint = %endpoint,
            status,
            bytes = body.len(),
            elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            "response received"
        );
        Ok(HttpResponse::new(method, final_url, status, body))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RedirectScope {
    AnyOrigin,
    SameOrigin,
}

fn build_client(
    config: &HttpConfig,
    policy: &NetworkPolicy,
    scope: RedirectScope,
) -> Result<reqwest::Client, HttpError> {
    reqwest::Client::builder()
        .user_agent(user_agent())
        .connect_timeout(config.connect_timeout)
        .timeout(config.request_timeout)
        .redirect(redirect_policy(policy.clone(), scope))
        .dns_resolver(PublicOnlyResolver)
        // A proxy would resolve names itself, bypassing the resolver check.
        .no_proxy()
        .retry(reqwest::retry::never())
        // Don't leak the previous URL (and its query) to redirect targets.
        .referer(false)
        .pool_max_idle_per_host(2)
        .pool_idle_timeout(Duration::from_secs(30))
        .https_only(policy.https_only())
        .tls_version_min(reqwest::tls::Version::TLS_1_2)
        .build()
        .map_err(|_| HttpError::ClientInit)
}

/// Validates every redirect hop against the network policy.
fn redirect_policy(policy: NetworkPolicy, scope: RedirectScope) -> redirect::Policy {
    redirect::Policy::custom(move |attempt| {
        // `previous()` holds every URL requested so far, starting with the
        // original one. Its length is the number of hops once this one is
        // followed.
        if attempt.previous().len() > MAX_REDIRECTS {
            return attempt.error(PolicyViolation::TooManyRedirects { max: MAX_REDIRECTS });
        }
        if scope == RedirectScope::SameOrigin
            && attempt
                .previous()
                .first()
                .is_some_and(|original| !same_origin(original, attempt.url()))
        {
            return attempt.error(PolicyViolation::CrossOriginRedirect);
        }
        match policy.check_url(attempt.url()) {
            Ok(()) => attempt.follow(),
            Err(violation) => attempt.error(violation),
        }
    })
}

/// Maps a reqwest error to an [`HttpError`] without carrying over any URL
/// or server-provided text.
fn map_error(err: &reqwest::Error) -> HttpError {
    if let Some(violation) = find_policy_violation(err) {
        tracing::warn!(violation = %violation, "request blocked by network policy");
        return HttpError::Blocked(violation);
    }
    let mapped = if err.is_timeout() {
        HttpError::Timeout
    } else if err.is_connect() {
        HttpError::Connect
    } else if err.is_builder() {
        HttpError::InvalidRequest("request could not be built")
    } else {
        HttpError::Transport
    };
    tracing::debug!(error = %mapped, "request failed");
    mapped
}

/// Finds a [`PolicyViolation`] raised by the redirect policy or the
/// resolver anywhere in the error's source chain.
fn find_policy_violation(err: &(dyn StdError + 'static)) -> Option<PolicyViolation> {
    let mut current = Some(err);
    while let Some(e) = current {
        if let Some(violation) = e.downcast_ref::<PolicyViolation>() {
            return Some(violation.clone());
        }
        current = e.source();
    }
    None
}
