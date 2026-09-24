//! Engine tests with fake collectors. They run on tokio's paused clock, so
//! timeouts and deadlines are exercised deterministically and instantly.

use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use sentinel_core::{
    Confidence, DnsRecord, DnsRecordData, DnsRecordType, Indicator, IndicatorType, Observation,
    ObservationData, Provenance, RelationKind, Relationship, SourceOutcome, SourceStatus,
    TimeLimit,
};
use tokio::time::Instant;

use super::*;
use crate::clock::testing::FixedClock;
use crate::collector::CollectFuture;
use crate::http::HttpConfig;

/// What a fake collector does when run.
#[derive(Clone)]
enum Behavior {
    /// Returns one observation (plus the configured pivots) after `delay`.
    Succeed { delay: Duration },
    /// Fails after `delay`.
    Fail { delay: Duration },
    /// Panics.
    Panic,
    /// Takes `n` units of the request budget.
    UseRequests { n: u32 },
}

/// Computes the pivots a fake collector returns for an indicator.
type PivotFn = Box<dyn Fn(&Indicator) -> Vec<Indicator> + Send + Sync>;

struct FakeCollector {
    id: SourceId,
    types: Vec<IndicatorType>,
    scope: CollectorScope,
    availability: Availability,
    behavior: Behavior,
    /// Pivots returned for each indicator this collector runs on.
    pivots: PivotFn,
    runs: Mutex<Vec<Indicator>>,
    gauge: Option<Arc<Gauge>>,
}

/// Tracks how many collector runs execute at the same time.
#[derive(Default)]
struct Gauge {
    current: AtomicUsize,
    max: AtomicUsize,
}

impl FakeCollector {
    fn new(id: &'static str, behavior: Behavior) -> Self {
        Self {
            id: SourceId::from_static(id),
            types: vec![IndicatorType::Domain],
            scope: CollectorScope::TargetOnly,
            availability: Availability::Ready,
            behavior,
            pivots: Box::new(|_| Vec::new()),
            runs: Mutex::new(Vec::new()),
            gauge: None,
        }
    }

    fn succeeding(id: &'static str) -> Self {
        Self::new(
            id,
            Behavior::Succeed {
                delay: Duration::from_millis(10),
            },
        )
    }

    fn types(mut self, types: &[IndicatorType]) -> Self {
        self.types = types.to_vec();
        self
    }

    fn on_pivots(mut self) -> Self {
        self.scope = CollectorScope::TargetAndPivots;
        self
    }

    fn pivots(mut self, f: impl Fn(&Indicator) -> Vec<Indicator> + Send + Sync + 'static) -> Self {
        self.pivots = Box::new(f);
        self
    }

    fn gauge(mut self, gauge: &Arc<Gauge>) -> Self {
        self.gauge = Some(Arc::clone(gauge));
        self
    }

    fn runs(&self) -> Vec<Indicator> {
        self.runs.lock().unwrap().clone()
    }
}

impl Collector for FakeCollector {
    fn id(&self) -> SourceId {
        self.id.clone()
    }

    fn supports(&self, indicator: &Indicator) -> bool {
        self.types.contains(&indicator.indicator_type())
    }

    fn scope(&self) -> CollectorScope {
        self.scope
    }

    fn availability(&self) -> Availability {
        self.availability
    }

    fn collect<'a>(
        &'a self,
        indicator: &'a Indicator,
        ctx: &'a CollectContext,
    ) -> CollectFuture<'a> {
        Box::pin(async move {
            self.runs.lock().unwrap().push(indicator.clone());
            if let Some(gauge) = &self.gauge {
                let now = gauge.current.fetch_add(1, Ordering::SeqCst) + 1;
                gauge.max.fetch_max(now, Ordering::SeqCst);
            }
            let result = match &self.behavior {
                Behavior::Succeed { delay } => {
                    tokio::time::sleep(*delay).await;
                    let mut collection = Collection::new();
                    collection.observe(txt_observation(indicator, &self.id, ctx));
                    for pivot in (self.pivots)(indicator) {
                        collection.pivot(pivot);
                    }
                    Ok(collection)
                }
                Behavior::Fail { delay } => {
                    tokio::time::sleep(*delay).await;
                    Err(CollectorError::InvalidResponse("fake failure"))
                }
                Behavior::Panic => panic!("fake collector panicked"),
                Behavior::UseRequests { n } => {
                    for _ in 0..*n {
                        ctx.acquire_request()?;
                    }
                    Ok(Collection::new())
                }
            };
            if let Some(gauge) = &self.gauge {
                gauge.current.fetch_sub(1, Ordering::SeqCst);
            }
            result
        })
    }
}

fn txt_observation(indicator: &Indicator, source: &SourceId, ctx: &CollectContext) -> Observation {
    Observation::new(
        indicator.clone(),
        source.clone(),
        ctx.now(),
        ObservationData::DnsRecord(DnsRecord::new(
            "example.com",
            60,
            DnsRecordData::Txt {
                text: "fake".into(),
            },
        )),
        Confidence::CERTAIN,
        Provenance::dns("example.com", DnsRecordType::Txt, "fake"),
    )
}

fn domain(s: &str) -> Indicator {
    Indicator::parse_domain(s).unwrap()
}

fn ip(s: &str) -> Indicator {
    Indicator::parse_ip(s).unwrap()
}

fn engine(config: EngineConfig, collectors: Vec<Arc<dyn Collector>>) -> Engine {
    let http = HttpClient::new(HttpConfig::default()).unwrap();
    let mut engine = Engine::new(http, Arc::new(FixedClock::default()), config);
    for collector in collectors {
        engine.register(collector).unwrap();
    }
    engine
}

fn status<'a>(run: &'a EngineRun, source: &str) -> Vec<&'a SourceStatus> {
    run.investigation
        .sources()
        .iter()
        .filter(|s| s.source().as_str() == source)
        .collect()
}

fn outcome<'a>(run: &'a EngineRun, source: &str) -> &'a SourceOutcome {
    let statuses = status(run, source);
    assert_eq!(
        statuses.len(),
        1,
        "expected exactly one status for {source}"
    );
    statuses[0].outcome()
}

#[tokio::test(start_paused = true)]
async fn runs_collectors_and_merges_results() {
    let a = Arc::new(FakeCollector::succeeding("a"));
    let b = Arc::new(FakeCollector::succeeding("b"));
    let run = engine(EngineConfig::default(), vec![a.clone(), b.clone()])
        .investigate(domain("example.com"))
        .await
        .unwrap();

    assert_eq!(run.investigation.observations().len(), 2);
    assert_eq!(
        outcome(&run, "a"),
        &SourceOutcome::Succeeded { observations: 1 }
    );
    assert_eq!(
        outcome(&run, "b"),
        &SourceOutcome::Succeeded { observations: 1 }
    );
    assert!(run.investigation.finished_at().is_some());
    assert_eq!(run.stats.source_runs, 2);
    assert!(!run.stats.deadline_exceeded);
}

#[tokio::test(start_paused = true)]
async fn rejects_non_investigable_targets() {
    let collector = Arc::new(FakeCollector::succeeding("a").types(&[IndicatorType::Ipv4]));
    let result = engine(EngineConfig::default(), vec![collector.clone()])
        .investigate(ip("10.0.0.1"))
        .await;
    assert!(result.is_err());
    assert!(
        collector.runs().is_empty(),
        "no collector may run on a private target"
    );
}

#[tokio::test(start_paused = true)]
async fn unsupported_collectors_do_not_run_and_unavailable_ones_are_skipped() {
    let ip_only = Arc::new(FakeCollector::succeeding("ip_only").types(&[IndicatorType::Ipv4]));
    let mut keyless = FakeCollector::succeeding("keyed");
    keyless.availability = Availability::Unavailable {
        reason: "no API key configured",
    };
    let keyless = Arc::new(keyless);

    let run = engine(
        EngineConfig::default(),
        vec![ip_only.clone(), keyless.clone()],
    )
    .investigate(domain("example.com"))
    .await
    .unwrap();

    assert!(ip_only.runs().is_empty());
    // Never saw a supported indicator: accounted for as unsupported.
    assert_eq!(outcome(&run, "ip_only"), &SourceOutcome::Unsupported);
    assert!(keyless.runs().is_empty());
    assert_eq!(
        outcome(&run, "keyed"),
        &SourceOutcome::Unavailable {
            reason: "no API key configured".into()
        }
    );
}

#[tokio::test(start_paused = true)]
async fn a_failing_collector_does_not_affect_the_others() {
    let failing = Arc::new(FakeCollector::new(
        "failing",
        Behavior::Fail {
            delay: Duration::ZERO,
        },
    ));
    let ok = Arc::new(FakeCollector::succeeding("ok"));
    let run = engine(EngineConfig::default(), vec![failing, ok])
        .investigate(domain("example.com"))
        .await
        .unwrap();

    assert_eq!(
        outcome(&run, "failing"),
        &SourceOutcome::Failed {
            error: "invalid response from source: fake failure".into()
        }
    );
    assert_eq!(
        outcome(&run, "ok"),
        &SourceOutcome::Succeeded { observations: 1 }
    );
}

#[tokio::test(start_paused = true)]
async fn a_panicking_collector_is_isolated() {
    let panicking = Arc::new(FakeCollector::new("panicking", Behavior::Panic));
    let ok = Arc::new(FakeCollector::succeeding("ok"));
    let run = engine(EngineConfig::default(), vec![panicking, ok])
        .investigate(domain("example.com"))
        .await
        .unwrap();

    assert_eq!(
        outcome(&run, "panicking"),
        &SourceOutcome::Failed {
            error: "collector crashed".into()
        }
    );
    assert_eq!(
        outcome(&run, "ok"),
        &SourceOutcome::Succeeded { observations: 1 }
    );
}

#[tokio::test(start_paused = true)]
async fn slow_collector_hits_the_source_timeout() {
    let config = EngineConfig {
        source_timeout: Duration::from_secs(5),
        ..EngineConfig::default()
    };
    let slow = Arc::new(FakeCollector::new(
        "slow",
        Behavior::Succeed {
            delay: Duration::from_secs(30),
        },
    ));
    let fast = Arc::new(FakeCollector::succeeding("fast"));
    let started = Instant::now();
    let run = engine(config, vec![slow, fast])
        .investigate(domain("example.com"))
        .await
        .unwrap();

    assert_eq!(
        outcome(&run, "slow"),
        &SourceOutcome::TimedOut {
            limit: TimeLimit::Source
        }
    );
    assert_eq!(
        outcome(&run, "fast"),
        &SourceOutcome::Succeeded { observations: 1 }
    );
    assert!(started.elapsed() < Duration::from_secs(6));
    assert!(!run.stats.deadline_exceeded);
}

#[tokio::test(start_paused = true)]
async fn global_deadline_cancels_everything_still_running() {
    let config = EngineConfig {
        investigation_timeout: Duration::from_secs(10),
        source_timeout: Duration::from_mins(1),
        ..EngineConfig::default()
    };
    let slow = Arc::new(FakeCollector::new(
        "slow",
        Behavior::Succeed {
            delay: Duration::from_mins(2),
        },
    ));
    let fast = Arc::new(FakeCollector::succeeding("fast"));
    let started = Instant::now();
    let run = engine(config, vec![slow, fast])
        .investigate(domain("example.com"))
        .await
        .unwrap();

    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_secs(10) && elapsed < Duration::from_secs(11),
        "{elapsed:?}"
    );
    assert_eq!(
        outcome(&run, "slow"),
        &SourceOutcome::TimedOut {
            limit: TimeLimit::Investigation
        }
    );
    assert_eq!(
        outcome(&run, "fast"),
        &SourceOutcome::Succeeded { observations: 1 }
    );
    assert!(run.stats.deadline_exceeded);
    assert!(run.investigation.finished_at().is_some());
}

#[tokio::test(start_paused = true)]
async fn deadline_also_covers_runs_waiting_for_a_concurrency_permit() {
    let config = EngineConfig {
        investigation_timeout: Duration::from_secs(10),
        source_timeout: Duration::from_mins(1),
        max_concurrent_sources: 1,
        ..EngineConfig::default()
    };
    let slow = Arc::new(FakeCollector::new(
        "slow",
        Behavior::Succeed {
            delay: Duration::from_mins(2),
        },
    ));
    let queued = Arc::new(FakeCollector::succeeding("queued"));
    let run = engine(config, vec![slow, queued.clone()])
        .investigate(domain("example.com"))
        .await
        .unwrap();

    assert!(queued.runs().is_empty(), "queued run never got a permit");
    assert_eq!(
        outcome(&run, "queued"),
        &SourceOutcome::TimedOut {
            limit: TimeLimit::Investigation
        }
    );
}

#[tokio::test(start_paused = true)]
async fn collectors_run_in_parallel() {
    let collectors: Vec<Arc<dyn Collector>> = ["a", "b", "c"]
        .into_iter()
        .map(|id| {
            Arc::new(FakeCollector::new(
                id,
                Behavior::Succeed {
                    delay: Duration::from_secs(1),
                },
            )) as Arc<dyn Collector>
        })
        .collect();
    let config = EngineConfig {
        max_concurrent_sources: 3,
        ..EngineConfig::default()
    };
    let started = Instant::now();
    let run = engine(config, collectors)
        .investigate(domain("example.com"))
        .await
        .unwrap();

    // Three 1-second runs finish in ~1 second, not 3.
    assert!(
        started.elapsed() < Duration::from_millis(1500),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(run.investigation.observations().len(), 3);
}

#[tokio::test(start_paused = true)]
async fn concurrency_is_bounded() {
    let gauge = Arc::new(Gauge::default());
    let ids = ["c1", "c2", "c3", "c4", "c5", "c6", "c7", "c8"];
    let collectors: Vec<Arc<dyn Collector>> = ids
        .into_iter()
        .map(|id| {
            Arc::new(
                FakeCollector::new(
                    id,
                    Behavior::Succeed {
                        delay: Duration::from_secs(1),
                    },
                )
                .gauge(&gauge),
            ) as Arc<dyn Collector>
        })
        .collect();
    let config = EngineConfig {
        max_concurrent_sources: 2,
        ..EngineConfig::default()
    };
    let started = Instant::now();
    let run = engine(config, collectors)
        .investigate(domain("example.com"))
        .await
        .unwrap();

    assert_eq!(gauge.max.load(Ordering::SeqCst), 2);
    assert_eq!(run.investigation.observations().len(), 8);
    // 8 runs, 2 at a time, 1 s each: ~4 s.
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_secs(4) && elapsed < Duration::from_secs(5),
        "{elapsed:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn pivot_depth_and_entity_limits_stop_runaway_expansion() {
    // domain → 20 IPs → (each IP) → another domain → ...
    let dns = Arc::new(
        FakeCollector::succeeding("dns")
            .on_pivots()
            .pivots(|_| (1..=20).map(|i| ip(&format!("8.8.{i}.8"))).collect()),
    );
    let asn = Arc::new(
        FakeCollector::succeeding("asn")
            .types(&[IndicatorType::Ipv4])
            .on_pivots()
            .pivots(|_| vec![domain("pivot-back.example.net"), domain("example.com")]),
    );
    let config = EngineConfig {
        pivots: PivotLimits {
            max_depth: 1,
            max_entities: 5,
        },
        ..EngineConfig::default()
    };
    let run = engine(config, vec![dns.clone(), asn.clone()])
        .investigate(domain("example.com"))
        .await
        .unwrap();

    // Only the target was resolved; depth-2 domains were never enriched.
    assert_eq!(dns.runs(), vec![domain("example.com")]);
    // Only 5 of the 20 IPs were enriched.
    assert_eq!(asn.runs().len(), 5);
    assert_eq!(run.stats.pivots_followed, 5);
    // 15 IPs over the entity limit + 1 depth-2 domain (the target is not
    // counted again: it is already visited, which also prevents cycles).
    assert_eq!(run.stats.pivots_dropped, 16);
    assert_eq!(run.stats.source_runs, 6);
}

#[tokio::test(start_paused = true)]
async fn huge_pivot_lists_are_bounded() {
    let flood = Arc::new(FakeCollector::succeeding("flood").pivots(|_| {
        (0..5000u32)
            .map(|i| {
                ip(&format!(
                    "8.{}.{}.{}",
                    (i >> 16) & 0xff,
                    (i >> 8) & 0xff,
                    i & 0xff
                ))
            })
            .collect()
    }));
    let asn = Arc::new(
        FakeCollector::succeeding("asn")
            .types(&[IndicatorType::Ipv4])
            .on_pivots(),
    );
    let config = EngineConfig {
        pivots: PivotLimits {
            max_depth: 1,
            max_entities: 3,
        },
        ..EngineConfig::default()
    };
    let run = engine(config, vec![flood, asn.clone()])
        .investigate(domain("example.com"))
        .await
        .unwrap();
    assert_eq!(asn.runs().len(), 3);
    assert_eq!(run.stats.pivots_followed, 3);
    // 997 examined and rejected + 4000 never examined.
    assert_eq!(run.stats.pivots_dropped, 4997);
}

#[tokio::test(start_paused = true)]
async fn pivot_depth_zero_disables_pivoting() {
    let dns = Arc::new(
        FakeCollector::succeeding("dns")
            .on_pivots()
            .pivots(|_| vec![ip("8.8.8.8")]),
    );
    let asn = Arc::new(
        FakeCollector::succeeding("asn")
            .types(&[IndicatorType::Ipv4])
            .on_pivots(),
    );
    let config = EngineConfig {
        pivots: PivotLimits {
            max_depth: 0,
            max_entities: 10,
        },
        ..EngineConfig::default()
    };
    let run = engine(config, vec![dns, asn.clone()])
        .investigate(domain("example.com"))
        .await
        .unwrap();
    assert!(asn.runs().is_empty());
    assert_eq!(run.stats.pivots_dropped, 1);
}

#[tokio::test(start_paused = true)]
async fn non_public_pivots_are_never_enriched() {
    let dns = Arc::new(FakeCollector::succeeding("dns").pivots(|_| {
        vec![
            ip("10.0.0.5"),
            ip("127.0.0.1"),
            ip("169.254.169.254"),
            domain("db.corp.internal"),
            ip("8.8.8.8"),
        ]
    }));
    let asn = Arc::new(
        FakeCollector::succeeding("asn")
            .types(&[IndicatorType::Ipv4, IndicatorType::Domain])
            .on_pivots(),
    );
    let run = engine(EngineConfig::default(), vec![dns, asn.clone()])
        .investigate(domain("example.com"))
        .await
        .unwrap();

    let enriched_pivots: Vec<_> = asn
        .runs()
        .into_iter()
        .filter(|i| i != &domain("example.com"))
        .collect();
    assert_eq!(enriched_pivots, vec![ip("8.8.8.8")]);
    assert_eq!(run.stats.pivots_dropped, 4);
}

#[tokio::test(start_paused = true)]
async fn target_only_collectors_do_not_run_on_pivots() {
    let dns = Arc::new(FakeCollector::succeeding("dns").pivots(|_| vec![ip("8.8.8.8")]));
    let reputation =
        Arc::new(FakeCollector::succeeding("reputation").types(&[IndicatorType::Ipv4]));
    let run = engine(EngineConfig::default(), vec![dns, reputation.clone()])
        .investigate(domain("example.com"))
        .await
        .unwrap();
    assert!(reputation.runs().is_empty());
    assert_eq!(run.stats.pivots_followed, 1);
}

#[tokio::test(start_paused = true)]
async fn request_budget_is_shared_and_enforced() {
    let config = EngineConfig {
        max_requests: 5,
        ..EngineConfig::default()
    };
    let greedy = Arc::new(FakeCollector::new(
        "greedy",
        Behavior::UseRequests { n: 100 },
    ));
    let run = engine(config, vec![greedy])
        .investigate(domain("example.com"))
        .await
        .unwrap();
    assert_eq!(
        outcome(&run, "greedy"),
        &SourceOutcome::BudgetExhausted { limit: 5 }
    );
    assert_eq!(run.stats.requests_used, 5);
}

#[tokio::test(start_paused = true)]
async fn relationships_with_foreign_evidence_are_discarded() {
    struct Buggy;
    impl Collector for Buggy {
        fn id(&self) -> SourceId {
            SourceId::from_static("buggy")
        }
        fn supports(&self, _: &Indicator) -> bool {
            true
        }
        fn collect<'a>(
            &'a self,
            indicator: &'a Indicator,
            _: &'a CollectContext,
        ) -> CollectFuture<'a> {
            Box::pin(async move {
                let mut collection = Collection::new();
                let foreign = sentinel_core::ObservationId::new_random();
                collection.relate(
                    Relationship::new(
                        indicator.clone(),
                        RelationKind::ResolvesTo,
                        ip("8.8.8.8"),
                        [foreign],
                    )
                    .unwrap(),
                );
                Ok(collection)
            })
        }
    }
    let run = engine(EngineConfig::default(), vec![Arc::new(Buggy)])
        .investigate(domain("example.com"))
        .await
        .unwrap();
    assert!(run.investigation.relationships().is_empty());
    assert_eq!(
        outcome(&run, "buggy"),
        &SourceOutcome::Succeeded { observations: 0 }
    );
}

#[test]
fn duplicate_sources_are_rejected() {
    let mut engine = engine(EngineConfig::default(), vec![]);
    engine
        .register(Arc::new(FakeCollector::succeeding("dup")))
        .unwrap();
    assert_eq!(
        engine.register(Arc::new(FakeCollector::succeeding("dup"))),
        Err(EngineError::DuplicateSource(SourceId::from_static("dup")))
    );
    assert_eq!(engine.sources(), vec![SourceId::from_static("dup")]);
}
