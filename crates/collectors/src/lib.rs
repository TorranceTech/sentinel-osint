//! # sentinel-collectors
//!
//! Everything in Sentinel OSINT that touches the network:
//!
//! - [`http`]: the hardened HTTP client (SSRF policy, redirect validation,
//!   size caps, timeouts, secret handling);
//! - [`collector`]: the [`Collector`] trait that data sources implement;
//! - [`engine`]: the [`Engine`] that runs collectors concurrently under a
//!   global deadline, per-source timeouts, a concurrency limit, a request
//!   budget and pivot limits;
//! - [`clock`]: the only source of wall-clock time.
//!
//! External content is data, not instructions. Collectors parse responses
//! into typed observations; they never execute or follow anything a source
//! returns, except validated HTTP redirects.

mod analysis;
pub mod clock;
pub mod collector;
pub mod dns;
pub mod engine;
pub mod http;
pub mod sources;
#[cfg(test)]
mod testing;

pub use clock::{Clock, SystemClock};
pub use collector::{
    Availability, CollectContext, CollectFuture, Collection, Collector, CollectorError,
    CollectorScope,
};
pub use dns::{DnsQueryError, DnsResolver, HickoryResolver};
pub use engine::{
    Engine, EngineConfig, EngineError, EngineRun, MAX_PIVOT_CANDIDATES, PivotLimits, RunStats,
};
pub use http::{HttpClient, HttpConfig, HttpError, HttpRequest, HttpResponse};
pub use sources::abuseipdb::AbuseIpDbCollector;
pub use sources::ct::CtCollector;
pub use sources::cymru::CymruCollector;
pub use sources::dns::DnsCollector;
pub use sources::malwarebazaar::MalwareBazaarCollector;
pub use sources::rdap::RdapCollector;
pub use sources::urlhaus::UrlhausCollector;
pub use sources::virustotal::VirusTotalCollector;
