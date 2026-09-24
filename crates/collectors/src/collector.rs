//! The collector abstraction.
//!
//! A collector queries one data source for one indicator and returns a
//! [`Collection`]: observations (facts, with provenance), relationships and
//! findings derived from them, and pivot candidates. It never touches the
//! [`Investigation`](sentinel_core::Investigation) directly. The engine
//! merges collections, which keeps integrity checks and limits in one place.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use sentinel_core::{
    Finding, Indicator, Observation, ObservationId, Relationship, SourceId, Timestamp,
};

use crate::clock::Clock;
use crate::http::{HttpClient, HttpError, HttpRequest, HttpResponse};

/// The future returned by [`Collector::collect`].
pub type CollectFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Collection, CollectorError>> + Send + 'a>>;

/// A data source.
pub trait Collector: Send + Sync {
    /// Stable identifier of the source (used in evidence and `--sources`).
    fn id(&self) -> SourceId;

    /// Whether this collector can handle the indicator type.
    fn supports(&self, indicator: &Indicator) -> bool;

    /// Whether the collector may run on pivoted indicators or only on the
    /// investigation target. Defaults to target only, the conservative
    /// choice for keyed third-party APIs.
    fn scope(&self) -> CollectorScope {
        CollectorScope::TargetOnly
    }

    /// Whether the collector is ready to run (for example, whether its API
    /// key is configured).
    fn availability(&self) -> Availability {
        Availability::Ready
    }

    /// Collects intelligence about `indicator`.
    ///
    /// The indicator has already passed
    /// [`Indicator::ensure_investigable`]. All network access must go
    /// through `ctx`, which enforces the request budget and network policy.
    /// The future may be cancelled at any await point (timeouts).
    fn collect<'a>(
        &'a self,
        indicator: &'a Indicator,
        ctx: &'a CollectContext,
    ) -> CollectFuture<'a>;
}

/// Which indicators a collector may run on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollectorScope {
    /// Only the investigation target.
    TargetOnly,
    /// The target and pivoted indicators (within the engine's pivot limits).
    TargetAndPivots,
}

/// Whether a collector can run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Availability {
    /// Ready.
    Ready,
    /// Not runnable; recorded as a skipped source.
    Unavailable {
        /// Fixed explanation, e.g. `"no API key configured"`.
        reason: &'static str,
    },
}

/// Why a collector failed. Recorded in the source status and logged.
///
/// DNS failures use [`CollectorError::Dns`].
///
/// Messages are fixed texts chosen by Sentinel (`&'static str`), never text
/// taken from a response. Parse errors from serde, for instance, can quote
/// the offending input, so they must be mapped to a fixed message.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CollectorError {
    /// HTTP-level failure.
    #[error(transparent)]
    Http(#[from] HttpError),
    /// The source answered with a status the collector cannot use.
    #[error("unexpected HTTP status {0}")]
    UnexpectedStatus(u16),
    /// The provider answered with a documented error status. `meaning` is
    /// Sentinel's fixed description of that status, never the provider's
    /// error message.
    #[error("{meaning} (HTTP {status})")]
    ProviderStatus {
        /// The HTTP status.
        status: u16,
        /// Fixed description, e.g. `"API key rejected by the provider"`.
        meaning: &'static str,
    },
    /// The response could not be understood.
    #[error("invalid response from source: {0}")]
    InvalidResponse(&'static str),
    /// The collector refused the indicator because it is not investigable
    /// (defense in depth: the engine already filters targets and pivots).
    #[error("refused: the indicator is not a public, investigable value")]
    RefusedTarget,
    /// The collector is not configured (e.g. no API key). The engine does
    /// not run unavailable collectors, so this is defense in depth.
    #[error("source is not configured")]
    NotConfigured,
    /// Every DNS query of the collector failed.
    #[error(transparent)]
    Dns(#[from] crate::dns::DnsQueryError),
    /// The investigation's request budget is used up.
    #[error("request budget of {limit} requests exhausted")]
    RequestBudgetExhausted {
        /// The budget.
        limit: u32,
    },
}

/// What a collector found.
#[derive(Debug, Default)]
pub struct Collection {
    pub(crate) observations: Vec<Observation>,
    pub(crate) relationships: Vec<Relationship>,
    pub(crate) findings: Vec<Finding>,
    pub(crate) pivots: Vec<Indicator>,
    pub(crate) failures: Vec<String>,
}

impl Collection {
    /// An empty collection.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an observation and returns its ID (to cite as evidence).
    pub fn observe(&mut self, observation: Observation) -> ObservationId {
        let id = observation.id();
        self.observations.push(observation);
        id
    }

    /// Adds a relationship. Its evidence must be observations of this
    /// collection; the engine rejects anything else.
    pub fn relate(&mut self, relationship: Relationship) {
        self.relationships.push(relationship);
    }

    /// Adds a finding.
    pub fn find(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    /// Suggests an indicator for further enrichment. The engine decides
    /// whether to follow it (depth, entity limit, investigation policy).
    pub fn pivot(&mut self, indicator: Indicator) {
        self.pivots.push(indicator);
    }

    /// Records that part of the collection failed (for example one of
    /// several DNS queries). The source is then reported as `partial`.
    /// The message must be built from fixed text and validated values only,
    /// never from response content. It is sanitized again when recorded.
    pub fn note_failure(&mut self, message: impl Into<String>) {
        self.failures.push(message.into());
    }

    /// Observations collected so far.
    #[must_use]
    pub fn observations(&self) -> &[Observation] {
        &self.observations
    }
}

/// Everything a collector may use while collecting.
#[derive(Clone)]
pub struct CollectContext {
    http: HttpClient,
    budget: Arc<RequestBudget>,
    clock: Arc<dyn Clock>,
}

impl CollectContext {
    pub(crate) fn new(http: HttpClient, budget: Arc<RequestBudget>, clock: Arc<dyn Clock>) -> Self {
        Self {
            http,
            budget,
            clock,
        }
    }

    /// The current time, for `collected_at` timestamps.
    #[must_use]
    pub fn now(&self) -> Timestamp {
        self.clock.now()
    }

    /// Takes one unit of the investigation's request budget. Every network
    /// request (HTTP or DNS) must be accounted for this way.
    ///
    /// # Errors
    /// [`CollectorError::RequestBudgetExhausted`] once the budget is used up.
    pub fn acquire_request(&self) -> Result<(), CollectorError> {
        if self.budget.try_acquire() {
            Ok(())
        } else {
            Err(CollectorError::RequestBudgetExhausted {
                limit: self.budget.limit(),
            })
        }
    }

    /// Sends an HTTP request through the hardened client, after taking one
    /// unit of the request budget.
    ///
    /// # Errors
    /// [`CollectorError::RequestBudgetExhausted`] or [`CollectorError::Http`].
    pub async fn send(&self, request: HttpRequest) -> Result<HttpResponse, CollectorError> {
        self.acquire_request()?;
        Ok(self.http.send(request).await?)
    }
}

/// Upper bound on the number of network requests in one investigation.
#[derive(Debug)]
pub(crate) struct RequestBudget {
    limit: u32,
    used: AtomicU32,
}

impl RequestBudget {
    pub(crate) const fn new(limit: u32) -> Self {
        Self {
            limit,
            used: AtomicU32::new(0),
        }
    }

    /// Takes one request from the budget; `false` if exhausted.
    pub(crate) fn try_acquire(&self) -> bool {
        self.used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                (used < self.limit).then_some(used + 1)
            })
            .is_ok()
    }

    pub(crate) const fn limit(&self) -> u32 {
        self.limit
    }

    pub(crate) fn used(&self) -> u32 {
        self.used.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_is_exact() {
        let budget = RequestBudget::new(3);
        assert!(budget.try_acquire());
        assert!(budget.try_acquire());
        assert!(budget.try_acquire());
        assert!(!budget.try_acquire());
        assert_eq!(budget.used(), 3);
    }

    #[test]
    fn budget_is_exact_under_contention() {
        let budget = Arc::new(RequestBudget::new(100));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let budget = Arc::clone(&budget);
                std::thread::spawn(move || (0..50).filter(|_| budget.try_acquire()).count())
            })
            .collect();
        let granted: usize = threads.into_iter().map(|t| t.join().unwrap()).sum();
        assert_eq!(granted, 100);
        assert_eq!(budget.used(), 100);
    }
}
