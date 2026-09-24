//! DNS resolution for collectors.
//!
//! The [`DnsResolver`] trait abstracts the resolver so the DNS collector can
//! be tested without a network. [`HickoryResolver`] is the real
//! implementation.
//!
//! Resolvers only perform **plain lookups of explicitly requested names and
//! types**. There is no zone transfer (AXFR/IXFR), no ANY query, no name
//! enumeration and no brute forcing.

mod hickory;

use std::future::Future;
use std::pin::Pin;

use sentinel_core::DnsRecord;
use sentinel_core::DnsRecordType;

pub use hickory::{DnsSetupError, HickoryResolver};

/// The future returned by [`DnsResolver::lookup`].
pub type DnsLookupFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Vec<DnsRecord>, DnsQueryError>> + Send + 'a>>;

/// A DNS resolver.
pub trait DnsResolver: Send + Sync {
    /// Describes the resolver for provenance, e.g. `system`.
    fn description(&self) -> &str;

    /// Looks up records of `record_type` for the absolute name `name`
    /// (without trailing dot). Returns only records of the requested type.
    /// An empty answer is reported as [`DnsQueryError::NoRecords`].
    fn lookup<'a>(&'a self, name: &'a str, record_type: DnsRecordType) -> DnsLookupFuture<'a>;
}

/// Why a DNS query produced no records.
///
/// `NxDomain` and `NoRecords` are *answers* (evidence of absence). The other
/// variants are failures, after which nothing can be concluded about the
/// queried type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DnsQueryError {
    /// The name does not exist.
    #[error("name does not exist (NXDOMAIN)")]
    NxDomain,
    /// The name exists but has no records of the requested type.
    #[error("no records of the requested type")]
    NoRecords,
    /// No answer in time.
    #[error("DNS query timed out")]
    Timeout,
    /// The name could not be encoded as a DNS query.
    #[error("invalid query name")]
    InvalidName,
    /// Any other failure (SERVFAIL, REFUSED, network error, malformed response).
    #[error("DNS query failed")]
    Failure,
}

impl DnsQueryError {
    /// Whether this is a definitive negative answer rather than a failure.
    #[must_use]
    pub const fn is_negative_answer(self) -> bool {
        matches!(self, Self::NxDomain | Self::NoRecords)
    }
}
