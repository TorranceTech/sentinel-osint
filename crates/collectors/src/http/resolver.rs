//! DNS resolver for the HTTP client that only yields public addresses.
//!
//! reqwest calls this resolver for every host name it connects to, including
//! hosts reached through redirects. It resolves the name once, drops every
//! non-public address, and returns the rest. The connector then connects to
//! exactly those addresses, so the address that was checked is the address
//! that is used. That closes the DNS-rebinding window between "check" and
//! "connect".
//!
//! IP-literal hosts never reach a resolver. They are checked by
//! `NetworkPolicy::check_url` before the request and on every redirect.

use std::net::SocketAddr;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};

use super::policy::{PolicyViolation, retain_public};

/// Resolver that filters out non-public addresses.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct PublicOnlyResolver;

impl Resolve for PublicOnlyResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_owned();
        Box::pin(async move {
            // Port 0: the connector sets the real port.
            let resolved: Vec<SocketAddr> =
                tokio::net::lookup_host((host.as_str(), 0)).await?.collect();
            let total = resolved.len();
            let public = retain_public(resolved);
            if public.len() < total {
                tracing::debug!(
                    host = ?host,
                    dropped = total - public.len(),
                    "dropped non-public addresses from DNS answer"
                );
            }
            if public.is_empty() {
                return Err(Box::new(PolicyViolation::NoPublicAddress) as _);
            }
            Ok(Box::new(public.into_iter()) as Addrs)
        })
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[tokio::test]
    async fn refuses_names_that_resolve_to_loopback() {
        // `localhost` resolves to loopback on every supported platform.
        let err = PublicOnlyResolver
            .resolve(Name::from_str("localhost").unwrap())
            .await
            .err()
            .expect("localhost must be refused");
        assert_eq!(
            err.downcast_ref::<PolicyViolation>(),
            Some(&PolicyViolation::NoPublicAddress)
        );
    }

    #[tokio::test]
    async fn refuses_ip_literals_in_private_ranges_passed_as_names() {
        // Should a literal ever reach the resolver, the result is filtered too.
        for name in ["127.0.0.1", "10.0.0.1", "169.254.169.254"] {
            let result = PublicOnlyResolver
                .resolve(Name::from_str(name).unwrap())
                .await;
            assert!(result.is_err(), "{name} must be refused");
        }
    }
}
