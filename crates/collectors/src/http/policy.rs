//! Network policy: which destinations Sentinel may connect to.
//!
//! This is the single place where SSRF rules live. It is enforced at three
//! points, so no request can bypass it:
//!
//! 1. **Before sending** ([`NetworkPolicy::check_url`]): scheme, credentials,
//!    and IP-literal hosts.
//! 2. **On every redirect hop** (see `redirect_policy` in `client.rs`): the
//!    same URL check, plus a hop limit.
//! 3. **At DNS resolution** (see `resolver.rs`): names are resolved once, and
//!    only globally routable addresses are handed to the connector. The
//!    connection is made to the address that was checked, so a DNS-rebinding
//!    answer between check and connect is not possible.

use std::fmt;
use std::net::{IpAddr, SocketAddr};

use sentinel_core::AddressScope;
use sentinel_core::net;
use url::{Host, Url};

/// Maximum number of redirects followed for a single request.
pub const MAX_REDIRECTS: usize = 3;

/// Why a destination was refused.
///
/// Messages contain only values Sentinel has already parsed and validated
/// (IP addresses and scopes), never raw server-provided text.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PolicyViolation {
    /// The URL does not use HTTPS.
    #[error("only HTTPS destinations are allowed")]
    InsecureScheme,
    /// The URL contains `user:password@`.
    #[error("URLs with embedded credentials are not allowed")]
    CredentialsInUrl,
    /// The URL has no host.
    #[error("URL has no host")]
    MissingHost,
    /// The destination is a non-public IP address.
    #[error("destination {ip} is a {scope} address")]
    NonPublicAddress {
        /// The refused address.
        ip: IpAddr,
        /// Its scope.
        scope: AddressScope,
    },
    /// A host name resolved only to non-public addresses.
    #[error("host name did not resolve to any public address")]
    NoPublicAddress,
    /// The redirect chain is too long.
    #[error("more than {max} redirects")]
    TooManyRedirects {
        /// The limit.
        max: usize,
    },
    /// An authenticated request was redirected to a different origin, which
    /// would forward the API key to that origin.
    #[error("authenticated request redirected to a different origin")]
    CrossOriginRedirect,
}

/// The network policy applied to all outbound HTTP.
///
/// In production there is exactly one policy: HTTPS only, public addresses
/// only. Tests can allow specific loopback socket addresses (mock servers);
/// that constructor only exists under `cfg(test)`.
#[derive(Clone, Default)]
pub struct NetworkPolicy {
    /// Mock servers reachable over plain HTTP on loopback. Always empty
    /// outside tests.
    #[cfg(test)]
    test_servers: Vec<SocketAddr>,
}

impl fmt::Debug for NetworkPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NetworkPolicy(public HTTPS only)")
    }
}

impl NetworkPolicy {
    /// The production policy: HTTPS only, globally routable addresses only.
    #[must_use]
    pub fn public_https_only() -> Self {
        Self::default()
    }

    /// Test policy that additionally allows plain HTTP to the given
    /// loopback mock servers. Everything else is still refused.
    #[cfg(test)]
    pub(crate) fn with_test_servers(servers: Vec<SocketAddr>) -> Self {
        Self {
            test_servers: servers,
        }
    }

    /// Whether this policy enforces HTTPS for every request. False only in
    /// tests that talk to plain-HTTP mock servers.
    #[cfg_attr(not(test), allow(clippy::unused_self))]
    pub(crate) fn https_only(&self) -> bool {
        #[cfg(test)]
        {
            self.test_servers.is_empty()
        }
        #[cfg(not(test))]
        {
            true
        }
    }

    /// Checks a URL before a request or redirect hop.
    ///
    /// # Errors
    /// Returns the [`PolicyViolation`] that forbids the destination.
    pub fn check_url(&self, url: &Url) -> Result<(), PolicyViolation> {
        if !url.username().is_empty() || url.password().is_some() {
            return Err(PolicyViolation::CredentialsInUrl);
        }
        if self.is_test_server(url) {
            return Ok(());
        }
        let ip = match url.host() {
            None => return Err(PolicyViolation::MissingHost),
            // Names are checked at resolution time (see resolver.rs).
            Some(Host::Domain(_)) => None,
            Some(Host::Ipv4(v4)) => Some(IpAddr::V4(v4)),
            Some(Host::Ipv6(v6)) => Some(IpAddr::V6(v6)),
        };
        if let Some(ip) = ip {
            check_ip(ip)?;
        }
        if url.scheme() != "https" {
            return Err(PolicyViolation::InsecureScheme);
        }
        Ok(())
    }

    #[cfg(test)]
    fn is_test_server(&self, url: &Url) -> bool {
        let addr = match (url.host(), url.port_or_known_default()) {
            (Some(Host::Ipv4(ip)), Some(port)) => SocketAddr::new(IpAddr::V4(ip), port),
            (Some(Host::Ipv6(ip)), Some(port)) => SocketAddr::new(IpAddr::V6(ip), port),
            _ => return false,
        };
        self.test_servers.contains(&addr)
    }

    #[cfg(not(test))]
    #[allow(clippy::unused_self)] // Signature shared with the cfg(test) version.
    const fn is_test_server(&self, _url: &Url) -> bool {
        false
    }
}

/// Checks that an IP address is globally routable.
///
/// # Errors
/// [`PolicyViolation::NonPublicAddress`] otherwise.
pub fn check_ip(ip: IpAddr) -> Result<(), PolicyViolation> {
    let scope = net::classify(ip);
    if scope.is_global() {
        Ok(())
    } else {
        Err(PolicyViolation::NonPublicAddress { ip, scope })
    }
}

/// Keeps only globally routable addresses.
pub(crate) fn retain_public(addrs: impl IntoIterator<Item = SocketAddr>) -> Vec<SocketAddr> {
    addrs
        .into_iter()
        .filter(|addr| net::is_global(addr.ip()))
        .collect()
}

/// Whether two URLs share an origin (scheme, host, port).
pub(crate) fn same_origin(a: &Url, b: &Url) -> bool {
    a.scheme() == b.scheme()
        && a.host() == b.host()
        && a.port_or_known_default() == b.port_or_known_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(url: &str) -> Result<(), PolicyViolation> {
        NetworkPolicy::public_https_only().check_url(&Url::parse(url).unwrap())
    }

    #[test]
    fn production_policy_accepts_public_https() {
        assert_eq!(check("https://api.example.com/v1?q=1"), Ok(()));
        assert_eq!(check("https://8.8.8.8/"), Ok(()));
        assert_eq!(check("https://[2001:4860:4860::8888]/"), Ok(()));
    }

    #[test]
    fn production_policy_rejects_plain_http_and_other_schemes() {
        assert_eq!(
            check("http://example.com/"),
            Err(PolicyViolation::InsecureScheme)
        );
        assert_eq!(
            check("ftp://example.com/"),
            Err(PolicyViolation::InsecureScheme)
        );
        assert_eq!(
            check("file:///etc/passwd"),
            Err(PolicyViolation::MissingHost)
        );
    }

    #[test]
    fn production_policy_rejects_credentials() {
        assert_eq!(
            check("https://user:pw@example.com/"),
            Err(PolicyViolation::CredentialsInUrl)
        );
    }

    #[test]
    fn production_policy_rejects_non_public_ip_literals() {
        for url in [
            "https://127.0.0.1/",
            "https://10.0.0.1/",
            "https://192.168.1.1:8443/",
            "https://169.254.169.254/latest/meta-data/",
            "https://[::1]/",
            "https://[fd00::1]/",
            "https://[::ffff:127.0.0.1]/",
            "https://0.0.0.0/",
            "https://0x7f.1/",     // WHATWG parsing: 127.0.0.1
            "https://2130706433/", // decimal notation: 127.0.0.1
            "https://224.0.0.1/",
        ] {
            assert!(
                matches!(check(url), Err(PolicyViolation::NonPublicAddress { .. })),
                "{url} should be refused"
            );
        }
    }

    #[test]
    fn test_servers_are_only_the_exact_socket_addresses() {
        let server: SocketAddr = "127.0.0.1:4000".parse().unwrap();
        let policy = NetworkPolicy::with_test_servers(vec![server]);
        assert!(!policy.https_only());
        assert_eq!(
            policy.check_url(&Url::parse("http://127.0.0.1:4000/x").unwrap()),
            Ok(())
        );
        // Same IP, other port: still loopback, still refused.
        assert!(matches!(
            policy.check_url(&Url::parse("http://127.0.0.1:4001/").unwrap()),
            Err(PolicyViolation::NonPublicAddress { .. })
        ));
        // Plain HTTP to anything else is refused.
        assert_eq!(
            policy.check_url(&Url::parse("http://example.com/").unwrap()),
            Err(PolicyViolation::InsecureScheme)
        );
        assert!(NetworkPolicy::public_https_only().https_only());
    }

    #[test]
    fn retain_public_filters_resolved_addresses() {
        let addrs: Vec<SocketAddr> = ["127.0.0.1:443", "8.8.8.8:443", "10.1.1.1:443", "[::1]:443"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        assert_eq!(retain_public(addrs), vec!["8.8.8.8:443".parse().unwrap()]);
    }

    #[test]
    fn same_origin_compares_scheme_host_and_port() {
        let u = |s: &str| Url::parse(s).unwrap();
        assert!(same_origin(
            &u("https://a.example/x"),
            &u("https://a.example:443/y")
        ));
        assert!(!same_origin(
            &u("https://a.example/"),
            &u("https://b.example/")
        ));
        assert!(!same_origin(
            &u("https://a.example/"),
            &u("https://a.example:8443/")
        ));
        assert!(!same_origin(
            &u("https://a.example/"),
            &u("http://a.example/")
        ));
    }
}
