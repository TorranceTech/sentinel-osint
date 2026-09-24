//! The investigation engine: runs collectors concurrently under explicit
//! limits and merges their results into an [`Investigation`].
//!
//! Limits (see [`EngineConfig`]):
//!
//! | Limit | Enforced by |
//! |---|---|
//! | total time | global deadline; unfinished sources are cancelled |
//! | time per source run | `tokio::time::timeout` around each `collect` |
//! | concurrent source runs | semaphore (a permit is held while collecting) |
//! | concurrent HTTP requests | semaphore inside the HTTP client |
//! | network requests | request budget shared by all collectors |
//! | pivot depth / pivot entities | checked before a pivot is scheduled |
//!
//! A failing, panicking or slow collector only affects its own source
//! status. It never aborts the investigation.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use sentinel_core::{
    Indicator, IndicatorError, Investigation, SourceId, SourceOutcome, SourceStatus, TimeLimit,
    Timestamp,
};
use tokio::sync::Semaphore;
use tokio::task::{Id as TaskId, JoinError, JoinSet};
use tracing::Instrument;

use crate::clock::Clock;
use crate::collector::{
    Availability, CollectContext, Collection, Collector, CollectorError, CollectorScope,
    RequestBudget,
};
use crate::http::HttpClient;

#[cfg(test)]
mod tests;

/// Maximum pivot candidates examined per collection. Bounds the engine's
/// bookkeeping even if a source returns an enormous list.
pub const MAX_PIVOT_CANDIDATES: usize = 1000;

/// Limits on pivoting from the target to related indicators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PivotLimits {
    /// Maximum pivot depth. The target is depth 0, so `1` allows
    /// `domain → IP` but not `domain → IP → domain`. `0` disables pivoting.
    pub max_depth: u8,
    /// Maximum number of distinct pivoted indicators per investigation.
    pub max_entities: usize,
}

/// Engine limits.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// Global deadline for the whole investigation.
    pub investigation_timeout: Duration,
    /// Timeout for one collector run on one indicator.
    pub source_timeout: Duration,
    /// Maximum number of collector runs executing at once.
    pub max_concurrent_sources: usize,
    /// Maximum number of network requests (HTTP and DNS) per investigation.
    pub max_requests: u32,
    /// Pivot limits.
    pub pivots: PivotLimits,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            investigation_timeout: Duration::from_mins(1),
            source_timeout: Duration::from_secs(45),
            max_concurrent_sources: 4,
            max_requests: 100,
            pivots: PivotLimits {
                max_depth: 1,
                max_entities: 10,
            },
        }
    }
}

/// Engine setup errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EngineError {
    /// Two collectors share an ID.
    #[error("a collector with id `{0}` is already registered")]
    DuplicateSource(SourceId),
}

/// Counters describing how an investigation ran.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunStats {
    /// Collector runs that were started (target and pivots).
    pub source_runs: usize,
    /// Distinct pivoted indicators that were enriched.
    pub pivots_followed: usize,
    /// Distinct pivot candidates that were not followed (depth, entity
    /// limit, or not investigable).
    pub pivots_dropped: usize,
    /// Network requests used from the budget.
    pub requests_used: u32,
    /// Whether the global deadline cut the investigation short.
    pub deadline_exceeded: bool,
}

/// The result of [`Engine::investigate`].
#[derive(Debug)]
pub struct EngineRun {
    /// The finished investigation.
    pub investigation: Investigation,
    /// How it ran.
    pub stats: RunStats,
}

/// Runs collectors against a target.
pub struct Engine {
    collectors: Vec<Arc<dyn Collector>>,
    http: HttpClient,
    clock: Arc<dyn Clock>,
    config: EngineConfig,
}

impl Engine {
    /// Creates an engine without collectors.
    #[must_use]
    pub fn new(http: HttpClient, clock: Arc<dyn Clock>, config: EngineConfig) -> Self {
        Self {
            collectors: Vec::new(),
            http,
            clock,
            config,
        }
    }

    /// Registers a collector.
    ///
    /// # Errors
    /// [`EngineError::DuplicateSource`] if a collector with the same ID exists.
    pub fn register(&mut self, collector: Arc<dyn Collector>) -> Result<(), EngineError> {
        let id = collector.id();
        if self.collectors.iter().any(|c| c.id() == id) {
            return Err(EngineError::DuplicateSource(id));
        }
        self.collectors.push(collector);
        Ok(())
    }

    /// IDs of the registered collectors.
    #[must_use]
    pub fn sources(&self) -> Vec<SourceId> {
        self.collectors.iter().map(|c| c.id()).collect()
    }

    /// Investigates `target`.
    ///
    /// # Errors
    /// [`IndicatorError`] if the target may not be investigated (see
    /// [`Indicator::ensure_investigable`]). Source failures are **not**
    /// errors; they are recorded in the investigation's source statuses.
    pub async fn investigate(&self, target: Indicator) -> Result<EngineRun, IndicatorError> {
        let investigation = Investigation::new(target.clone(), self.clock.now())?;
        let span = tracing::info_span!(
            "investigation",
            id = %investigation.id(),
            target = %target,
        );
        Ok(Run::new(self, investigation)
            .execute(target)
            .instrument(span)
            .await)
    }
}

/// What a collector task reports back.
struct TaskOutput {
    outcome: TaskOutcome,
    started_at: Timestamp,
    finished_at: Timestamp,
}

enum TaskOutcome {
    Finished(Result<Collection, CollectorError>),
    SourceTimeout,
}

/// Bookkeeping for a spawned task.
struct PendingTask {
    source: SourceId,
    indicator: Indicator,
    depth: u8,
    queued_at: Timestamp,
}

/// State of one investigation while it runs.
struct Run<'e> {
    engine: &'e Engine,
    investigation: Investigation,
    tasks: JoinSet<TaskOutput>,
    pending: HashMap<TaskId, PendingTask>,
    visited: HashSet<Indicator>,
    /// Sources that ran or were found unavailable at least once.
    considered: HashSet<SourceId>,
    dropped: HashSet<Indicator>,
    /// Pivot candidates beyond [`MAX_PIVOT_CANDIDATES`] per collection,
    /// counted but not stored.
    overflow: usize,
    semaphore: Arc<Semaphore>,
    budget: Arc<RequestBudget>,
    ctx: CollectContext,
    stats: RunStats,
}

impl<'e> Run<'e> {
    fn new(engine: &'e Engine, investigation: Investigation) -> Self {
        let budget = Arc::new(RequestBudget::new(engine.config.max_requests));
        let ctx = CollectContext::new(
            engine.http.clone(),
            Arc::clone(&budget),
            Arc::clone(&engine.clock),
        );
        Self {
            engine,
            investigation,
            tasks: JoinSet::new(),
            pending: HashMap::new(),
            visited: HashSet::new(),
            considered: HashSet::new(),
            dropped: HashSet::new(),
            overflow: 0,
            semaphore: Arc::new(Semaphore::new(engine.config.max_concurrent_sources.max(1))),
            budget,
            ctx,
            stats: RunStats::default(),
        }
    }

    async fn execute(mut self, target: Indicator) -> EngineRun {
        let deadline = tokio::time::Instant::now() + self.engine.config.investigation_timeout;
        tracing::info!("investigation started");

        self.visited.insert(target.clone());
        self.schedule(&target, 0);

        loop {
            match tokio::time::timeout_at(deadline, self.tasks.join_next_with_id()).await {
                Ok(None) => break,
                Ok(Some(Ok((id, output)))) => self.complete(id, output),
                Ok(Some(Err(join_error))) => self.crashed(&join_error),
                Err(_elapsed) => {
                    self.cancel_remaining().await;
                    break;
                }
            }
        }

        self.record_unsupported();
        self.stats.requests_used = self.budget.used();
        self.stats.pivots_dropped = self.dropped.len() + self.overflow;
        let finished_at = self.engine.clock.now().max(self.investigation.started_at());
        if let Err(error) = self.investigation.finish(finished_at) {
            tracing::error!(error = %error, "could not finish investigation");
        }
        tracing::info!(
            observations = self.investigation.observations().len(),
            source_runs = self.stats.source_runs,
            pivots_followed = self.stats.pivots_followed,
            pivots_dropped = self.stats.pivots_dropped,
            requests_used = self.stats.requests_used,
            deadline_exceeded = self.stats.deadline_exceeded,
            "investigation finished"
        );
        EngineRun {
            investigation: self.investigation,
            stats: self.stats,
        }
    }

    /// Sources that never saw an indicator they support get one
    /// `unsupported` status, so every registered source is accounted for.
    fn record_unsupported(&mut self) {
        let now = self.engine.clock.now().max(self.investigation.started_at());
        for collector in &self.engine.collectors {
            if !self.considered.contains(&collector.id()) {
                self.investigation.record_source(SourceStatus::new(
                    collector.id(),
                    self.investigation.target().clone(),
                    SourceOutcome::Unsupported,
                    now,
                    now,
                ));
            }
        }
    }

    /// Starts every applicable collector for `indicator`.
    fn schedule(&mut self, indicator: &Indicator, depth: u8) {
        for collector in &self.engine.collectors {
            if !collector.supports(indicator) {
                continue;
            }
            if depth > 0 && collector.scope() == CollectorScope::TargetOnly {
                continue;
            }
            // One "unavailable" status per source, not one per indicator.
            if let Availability::Unavailable { reason } = collector.availability() {
                if self.considered.insert(collector.id()) {
                    let now = self.engine.clock.now();
                    self.investigation.record_source(SourceStatus::new(
                        collector.id(),
                        indicator.clone(),
                        SourceOutcome::Unavailable {
                            reason: reason.to_owned(),
                        },
                        now,
                        now,
                    ));
                }
                continue;
            }
            self.considered.insert(collector.id());
            self.spawn(Arc::clone(collector), indicator.clone(), depth);
        }
    }

    fn spawn(&mut self, collector: Arc<dyn Collector>, indicator: Indicator, depth: u8) {
        let source = collector.id();
        let span = tracing::info_span!("source", source = %source, indicator = %indicator, depth);
        let ctx = self.ctx.clone();
        let semaphore = Arc::clone(&self.semaphore);
        let clock = Arc::clone(&self.engine.clock);
        let timeout = self.engine.config.source_timeout;
        let task_indicator = indicator.clone();

        let handle = self.tasks.spawn(
            async move {
                // Held for the whole run: bounds concurrent collector runs.
                // The semaphore is never closed, so acquisition cannot fail.
                let _permit = semaphore.acquire_owned().await;
                let started_at = clock.now();
                tracing::debug!("source started");
                let outcome =
                    match tokio::time::timeout(timeout, collector.collect(&task_indicator, &ctx))
                        .await
                    {
                        Ok(result) => TaskOutcome::Finished(result),
                        Err(_elapsed) => TaskOutcome::SourceTimeout,
                    };
                TaskOutput {
                    outcome,
                    started_at,
                    finished_at: clock.now(),
                }
            }
            .instrument(span),
        );

        self.stats.source_runs += 1;
        self.pending.insert(
            handle.id(),
            PendingTask {
                source,
                indicator,
                depth,
                queued_at: self.engine.clock.now(),
            },
        );
    }

    fn complete(&mut self, id: TaskId, output: TaskOutput) {
        let Some(task) = self.pending.remove(&id) else {
            tracing::error!("completed task was not tracked");
            return;
        };
        let outcome = match output.outcome {
            TaskOutcome::Finished(Ok(mut collection)) => {
                let observations = collection.observations.len();
                let failures = std::mem::take(&mut collection.failures);
                let pivots = self.merge(collection);
                self.consider_pivots(pivots, task.depth);
                if failures.is_empty() {
                    tracing::debug!(source = %task.source, indicator = %task.indicator, observations, "source succeeded");
                    SourceOutcome::Succeeded { observations }
                } else {
                    tracing::warn!(source = %task.source, indicator = %task.indicator, observations, failures = failures.len(), "source partially failed");
                    SourceOutcome::Partial {
                        observations,
                        errors: failures,
                    }
                }
            }
            TaskOutcome::Finished(Err(CollectorError::RequestBudgetExhausted { limit })) => {
                tracing::warn!(source = %task.source, indicator = %task.indicator, limit, "source not run: request budget exhausted");
                SourceOutcome::BudgetExhausted { limit }
            }
            TaskOutcome::Finished(Err(error)) => {
                tracing::warn!(source = %task.source, indicator = %task.indicator, error = %error, "source failed");
                SourceOutcome::Failed {
                    error: error.to_string(),
                }
            }
            TaskOutcome::SourceTimeout => {
                tracing::warn!(source = %task.source, indicator = %task.indicator, "source timed out");
                SourceOutcome::TimedOut {
                    limit: TimeLimit::Source,
                }
            }
        };
        self.investigation.record_source(SourceStatus::new(
            task.source,
            task.indicator,
            outcome,
            output.started_at,
            output.finished_at,
        ));
    }

    /// A collector panicked. Its run is recorded as failed; the others continue.
    fn crashed(&mut self, error: &JoinError) {
        let Some(task) = self.pending.remove(&error.id()) else {
            tracing::error!("crashed task was not tracked");
            return;
        };
        tracing::error!(source = %task.source, indicator = %task.indicator, "source crashed");
        let now = self.engine.clock.now();
        self.investigation.record_source(SourceStatus::new(
            task.source,
            task.indicator,
            SourceOutcome::Failed {
                error: "collector crashed".to_owned(),
            },
            task.queued_at,
            now,
        ));
    }

    /// Global deadline reached: cancel every unfinished run and record it.
    async fn cancel_remaining(&mut self) {
        self.stats.deadline_exceeded = true;
        tracing::warn!(
            unfinished = self.pending.len(),
            "investigation deadline exceeded; cancelling remaining sources"
        );
        // Aborting drops the collector futures, which also drops in-flight
        // HTTP requests and their connections.
        self.tasks.abort_all();
        while self.tasks.join_next().await.is_some() {}

        let now = self.engine.clock.now();
        for (_, task) in self.pending.drain() {
            self.investigation.record_source(SourceStatus::new(
                task.source,
                task.indicator,
                SourceOutcome::TimedOut {
                    limit: TimeLimit::Investigation,
                },
                task.queued_at,
                now,
            ));
        }
    }

    /// Merges a collection into the investigation and returns its pivots.
    /// Relationships and findings with evidence the investigation does not
    /// contain are discarded (a collector bug, never a crash).
    fn merge(&mut self, collection: Collection) -> Vec<Indicator> {
        let Collection {
            observations,
            relationships,
            findings,
            pivots,
            failures: _,
        } = collection;
        for observation in observations {
            self.investigation.add_observation(observation);
        }
        for relationship in relationships {
            if let Err(error) = self.investigation.add_relationship(relationship) {
                tracing::warn!(error = %error, "discarding relationship with invalid evidence");
            }
        }
        for finding in findings {
            if let Err(error) = self.investigation.add_finding(finding) {
                tracing::warn!(error = %error, "discarding finding with invalid evidence");
            }
        }
        pivots
    }

    /// Schedules pivots that are within limits and investigable.
    fn consider_pivots(&mut self, pivots: Vec<Indicator>, parent_depth: u8) {
        let depth = parent_depth.saturating_add(1);
        let limits = self.engine.config.pivots;
        let excess = pivots.len().saturating_sub(MAX_PIVOT_CANDIDATES);
        if excess > 0 {
            tracing::warn!(
                excess,
                "too many pivot candidates from one source; ignoring the rest"
            );
            self.overflow += excess;
        }
        for pivot in pivots.into_iter().take(MAX_PIVOT_CANDIDATES) {
            if self.visited.contains(&pivot) || self.dropped.contains(&pivot) {
                continue; // Already enriched or rejected: no cycles, no repeats.
            }
            // `visited` includes the target, which is not a pivot.
            let pivots_so_far = self.visited.len() - 1;
            let rejection = if depth > limits.max_depth {
                Some("maximum pivot depth reached")
            } else if pivots_so_far >= limits.max_entities {
                Some("maximum number of pivot entities reached")
            } else if pivot.ensure_investigable().is_err() {
                Some("not investigable (non-public address or special-use name)")
            } else {
                None
            };
            if let Some(reason) = rejection {
                tracing::debug!(pivot = %pivot, depth, reason, "pivot not followed");
                self.dropped.insert(pivot);
                continue;
            }
            tracing::debug!(pivot = %pivot, depth, "following pivot");
            self.visited.insert(pivot.clone());
            self.stats.pivots_followed += 1;
            self.schedule(&pivot, depth);
        }
    }
}
