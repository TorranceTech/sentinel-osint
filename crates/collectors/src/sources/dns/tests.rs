//! DNS collector tests with a fake resolver, run through the real engine.

use sentinel_core::{Investigation, ObservationData, SourceOutcome, SourceStatus, TimeLimit};

use super::*;
use crate::clock::testing::FixedClock;
use crate::engine::{Engine, EngineConfig, EngineRun};
use crate::http::{HttpClient, HttpConfig};
use crate::testing::{Answer, FakeResolver};

fn a(ip: &str) -> DnsRecordData {
    DnsRecordData::A {
        address: ip.parse().unwrap(),
    }
}

/// A realistic, well-configured domain.
fn example_com() -> FakeResolver {
    FakeResolver::default()
        .records("example.com", DnsRecordType::A, vec![a("93.184.215.14")])
        .records(
            "example.com",
            DnsRecordType::Aaaa,
            vec![DnsRecordData::Aaaa {
                address: "2606:2800:21f:cb07:6820:80da:af6b:8b2c".parse().unwrap(),
            }],
        )
        .records(
            "example.com",
            DnsRecordType::Mx,
            vec![
                DnsRecordData::Mx {
                    preference: 10,
                    exchange: "mail.example.com".into(),
                },
                DnsRecordData::Mx {
                    preference: 20,
                    exchange: "backup.example.net".into(),
                },
            ],
        )
        .records(
            "example.com",
            DnsRecordType::Ns,
            vec![
                DnsRecordData::Ns {
                    nameserver: "a.iana-servers.net".into(),
                },
                DnsRecordData::Ns {
                    nameserver: "b.iana-servers.net".into(),
                },
            ],
        )
        .records(
            "example.com",
            DnsRecordType::Soa,
            vec![DnsRecordData::Soa {
                mname: "ns.icann.org".into(),
                rname: "noc.dns.icann.org".into(),
                serial: 2_026_092_301,
                refresh: 7200,
                retry: 3600,
                expire: 1_209_600,
                minimum: 3600,
            }],
        )
        .txt(
            "example.com",
            &[
                "v=spf1 include:_spf.example.net -all",
                "google-site-verification=abc123",
            ],
        )
        .records(
            "example.com",
            DnsRecordType::Caa,
            vec![
                DnsRecordData::Caa {
                    critical: false,
                    tag: "issue".into(),
                    value: "letsencrypt.org".into(),
                },
                DnsRecordData::Caa {
                    critical: false,
                    tag: "iodef".into(),
                    value: "mailto:security@example.com".into(),
                },
            ],
        )
        .txt(
            "_dmarc.example.com",
            &["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"],
        )
}

fn engine(resolver: FakeResolver, config: EngineConfig) -> (Engine, Arc<FakeResolver>) {
    let resolver = Arc::new(resolver);
    let http = HttpClient::new(HttpConfig::default()).unwrap();
    let mut engine = Engine::new(http, Arc::new(FixedClock::default()), config);
    engine
        .register(Arc::new(DnsCollector::new(
            Arc::clone(&resolver) as Arc<dyn DnsResolver>
        )))
        .unwrap();
    (engine, resolver)
}

async fn investigate(resolver: FakeResolver) -> EngineRun {
    investigate_with(resolver, EngineConfig::default()).await
}

async fn investigate_with(resolver: FakeResolver, config: EngineConfig) -> EngineRun {
    let (engine, _) = engine(resolver, config);
    engine
        .investigate(Indicator::parse_domain("example.com").unwrap())
        .await
        .unwrap()
}

fn codes(investigation: &Investigation) -> Vec<&str> {
    investigation
        .findings()
        .iter()
        .map(|f| f.code().as_str())
        .collect()
}

fn dns_status(investigation: &Investigation) -> &SourceStatus {
    let statuses: Vec<_> = investigation
        .sources()
        .iter()
        .filter(|s| s.source() == &SOURCE)
        .collect();
    assert_eq!(statuses.len(), 1);
    statuses[0]
}

fn records_of(investigation: &Investigation, record_type: DnsRecordType) -> Vec<&DnsRecordData> {
    investigation
        .observations()
        .iter()
        .filter_map(|o| match o.data() {
            ObservationData::DnsRecord(r) if r.record_type() == record_type => Some(r.data()),
            _ => None,
        })
        .collect()
}

fn no_records_of(investigation: &Investigation) -> Vec<(String, DnsRecordType, NoRecordsReason)> {
    investigation
        .observations()
        .iter()
        .filter_map(|o| match o.data() {
            ObservationData::DnsNoRecords(n) => {
                Some((n.name().to_owned(), n.record_type(), n.reason()))
            }
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn collects_every_record_type_with_provenance() {
    let run = investigate(example_com()).await;
    let inv = &run.investigation;

    assert_eq!(records_of(inv, DnsRecordType::A), vec![&a("93.184.215.14")]);
    assert_eq!(records_of(inv, DnsRecordType::Aaaa).len(), 1);
    assert_eq!(records_of(inv, DnsRecordType::Mx).len(), 2);
    assert_eq!(records_of(inv, DnsRecordType::Ns).len(), 2);
    assert_eq!(records_of(inv, DnsRecordType::Soa).len(), 1);
    assert_eq!(records_of(inv, DnsRecordType::Txt).len(), 3); // 2 apex + 1 DMARC
    assert_eq!(records_of(inv, DnsRecordType::Caa).len(), 2);
    // No CNAME at the apex: recorded as evidence of absence.
    assert_eq!(
        no_records_of(inv),
        vec![(
            "example.com".to_owned(),
            DnsRecordType::Cname,
            NoRecordsReason::NoData
        )]
    );

    for observation in inv.observations() {
        assert_eq!(observation.source(), &SOURCE);
        assert_eq!(observation.confidence(), DNS_CONFIDENCE);
        let Provenance::Dns(provenance) = observation.provenance() else {
            panic!("expected DNS provenance");
        };
        assert_eq!(provenance.resolver(), "fake");
        match observation.data() {
            ObservationData::DnsRecord(_) => assert!(observation.raw_response_hash().is_some()),
            _ => assert!(observation.raw_response_hash().is_none()),
        }
    }
    assert_eq!(
        dns_status(inv).outcome(),
        &SourceOutcome::Succeeded { observations: 13 }
    );
}

#[tokio::test]
async fn records_of_one_answer_share_the_answer_digest() {
    let run = investigate(example_com()).await;
    let mx: Vec<_> = run
        .investigation
        .observations()
        .iter()
        .filter(|o| matches!(o.data(), ObservationData::DnsRecord(r) if r.record_type() == DnsRecordType::Mx))
        .collect();
    assert_eq!(mx.len(), 2);
    assert_eq!(mx[0].raw_response_hash(), mx[1].raw_response_hash());
    let expected = answer_digest(&[
        DnsRecord::new(
            "example.com",
            300,
            DnsRecordData::Mx {
                preference: 10,
                exchange: "mail.example.com".into(),
            },
        ),
        DnsRecord::new(
            "example.com",
            300,
            DnsRecordData::Mx {
                preference: 20,
                exchange: "backup.example.net".into(),
            },
        ),
    ]);
    assert_eq!(mx[0].raw_response_hash(), Some(expected));
}

#[tokio::test]
async fn builds_relationships_and_pivots() {
    let run = investigate(example_com()).await;
    let kinds: Vec<(RelationKind, String)> = run
        .investigation
        .relationships()
        .iter()
        .map(|r| (r.kind(), r.target().to_string()))
        .collect();
    for expected in [
        (RelationKind::ResolvesTo, "93.184.215.14"),
        (
            RelationKind::ResolvesTo,
            "2606:2800:21f:cb07:6820:80da:af6b:8b2c",
        ),
        (RelationKind::HasMailExchanger, "mail.example.com"),
        (RelationKind::HasMailExchanger, "backup.example.net"),
        (RelationKind::HasNameserver, "a.iana-servers.net"),
        (RelationKind::HasNameserver, "b.iana-servers.net"),
    ] {
        assert!(
            kinds.contains(&(expected.0, expected.1.to_owned())),
            "missing {expected:?}"
        );
    }
    assert_eq!(run.investigation.relationships().len(), 6);
    // Both addresses are offered as pivots (no IP collector exists yet).
    assert_eq!(run.stats.pivots_followed, 2);
}

#[tokio::test]
async fn derives_email_and_caa_findings() {
    let run = investigate(example_com()).await;
    assert_eq!(
        codes(&run.investigation),
        vec![
            "dns.spf.hardfail",
            "dns.spf.includes",
            "dns.dmarc.policy_reject",
            "dns.dmarc.aggregate_reporting",
            "dns.caa.issue",
            "dns.caa.iodef",
        ]
    );
    // Every finding cites evidence that exists in the investigation.
    for finding in run.investigation.findings() {
        assert!(!finding.evidence().is_empty());
        for id in finding.evidence() {
            assert!(run.investigation.observation(*id).is_some());
        }
    }
}

#[tokio::test]
async fn cname_creates_an_alias_relationship() {
    let resolver = FakeResolver::default()
        .records(
            "example.com",
            DnsRecordType::Cname,
            vec![DnsRecordData::Cname {
                target: "edge.cdn.example.net".into(),
            }],
        )
        .records(
            "example.com",
            DnsRecordType::A,
            vec![a("203.0.113.10"), a("198.51.100.20")],
        );
    let run = investigate(resolver).await;
    assert!(
        run.investigation
            .relationships()
            .iter()
            .any(|r| r.kind() == RelationKind::AliasOf
                && r.target().to_string() == "edge.cdn.example.net")
    );
    assert_eq!(records_of(&run.investigation, DnsRecordType::A).len(), 2);
}

#[tokio::test]
async fn domain_without_most_record_types() {
    let resolver =
        FakeResolver::default().records("example.com", DnsRecordType::A, vec![a("93.184.215.14")]);
    let run = investigate(resolver).await;
    let inv = &run.investigation;
    assert_eq!(
        codes(inv),
        vec!["dns.spf.missing", "dns.dmarc.missing", "dns.caa.missing"]
    );
    assert_eq!(no_records_of(inv).len(), 8);
    assert_eq!(
        dns_status(inv).outcome(),
        &SourceOutcome::Succeeded { observations: 9 }
    );
}

#[tokio::test]
async fn nxdomain_is_reported_once() {
    let mut resolver = FakeResolver::default();
    for record_type in APEX_TYPES {
        resolver = resolver.with(
            "example.com",
            record_type,
            Answer::Error(DnsQueryError::NxDomain),
        );
    }
    resolver = resolver.with(
        "_dmarc.example.com",
        DnsRecordType::Txt,
        Answer::Error(DnsQueryError::NxDomain),
    );
    let run = investigate(resolver).await;
    assert_eq!(codes(&run.investigation), vec!["dns.domain.nxdomain"]);
    assert!(
        no_records_of(&run.investigation)
            .iter()
            .all(|(_, _, r)| *r == NoRecordsReason::NxDomain)
    );
}

#[tokio::test]
async fn failed_queries_make_the_source_partial_and_draw_no_conclusions() {
    let resolver = example_com()
        .with(
            "example.com",
            DnsRecordType::Txt,
            Answer::Error(DnsQueryError::Failure),
        )
        .with(
            "example.com",
            DnsRecordType::Caa,
            Answer::Error(DnsQueryError::Failure),
        );
    let run = investigate(resolver).await;
    let inv = &run.investigation;
    let codes = codes(inv);
    assert!(
        !codes.iter().any(|c| c.starts_with("dns.spf.")),
        "no SPF conclusion without TXT: {codes:?}"
    );
    assert!(
        !codes.iter().any(|c| c.starts_with("dns.caa.")),
        "no CAA conclusion: {codes:?}"
    );
    assert!(codes.contains(&"dns.dmarc.policy_reject"));
    assert_eq!(
        dns_status(inv).outcome(),
        &SourceOutcome::Partial {
            observations: 9,
            errors: vec![
                "TXT lookup for example.com failed: DNS query failed".into(),
                "CAA lookup for example.com failed: DNS query failed".into(),
            ],
        }
    );
}

#[tokio::test(start_paused = true)]
async fn hanging_queries_time_out_individually() {
    let resolver = example_com().with("_dmarc.example.com", DnsRecordType::Txt, Answer::Hang);
    let run = investigate(resolver).await;
    let SourceOutcome::Partial { errors, .. } = dns_status(&run.investigation).outcome() else {
        panic!("expected partial outcome");
    };
    assert_eq!(
        errors,
        &vec!["TXT lookup for _dmarc.example.com failed: DNS query timed out".to_owned()]
    );
    assert!(
        !codes(&run.investigation)
            .iter()
            .any(|c| c.starts_with("dns.dmarc."))
    );
    assert!(codes(&run.investigation).contains(&"dns.spf.hardfail"));
}

#[tokio::test(start_paused = true)]
async fn a_resolver_slower_than_the_source_timeout_is_cut_off() {
    let mut resolver = FakeResolver::default();
    for record_type in APEX_TYPES {
        resolver = resolver.with("example.com", record_type, Answer::Hang);
    }
    let config = EngineConfig {
        source_timeout: Duration::from_secs(2),
        ..EngineConfig::default()
    };
    let run = investigate_with(resolver, config).await;
    assert_eq!(
        dns_status(&run.investigation).outcome(),
        &SourceOutcome::TimedOut {
            limit: TimeLimit::Source
        }
    );
}

#[tokio::test]
async fn total_dns_failure_fails_the_source() {
    let mut resolver = FakeResolver::default();
    for record_type in APEX_TYPES {
        resolver = resolver.with(
            "example.com",
            record_type,
            Answer::Error(DnsQueryError::Failure),
        );
    }
    resolver = resolver.with(
        "_dmarc.example.com",
        DnsRecordType::Txt,
        Answer::Error(DnsQueryError::Timeout),
    );
    let run = investigate(resolver).await;
    assert_eq!(
        dns_status(&run.investigation).outcome(),
        &SourceOutcome::Failed {
            error: "DNS query failed".into()
        }
    );
    assert!(run.investigation.findings().is_empty());
}

#[tokio::test]
async fn queries_are_charged_to_the_request_budget() {
    let config = EngineConfig {
        max_requests: 3,
        ..EngineConfig::default()
    };
    let (engine, resolver) = engine(example_com(), config);
    let run = engine
        .investigate(Indicator::parse_domain("example.com").unwrap())
        .await
        .unwrap();
    assert_eq!(resolver.queried.lock().unwrap().len(), 3);
    assert_eq!(run.stats.requests_used, 3);
    let SourceOutcome::Partial { errors, .. } = dns_status(&run.investigation).outcome() else {
        panic!("expected partial outcome");
    };
    assert_eq!(errors.len(), 6);
    assert!(
        errors
            .iter()
            .all(|e| e.ends_with("request budget of 3 requests exhausted"))
    );
}

#[tokio::test]
async fn only_the_fixed_query_plan_is_executed() {
    let (engine, resolver) = engine(example_com(), EngineConfig::default());
    engine
        .investigate(Indicator::parse_domain("example.com").unwrap())
        .await
        .unwrap();
    let mut queried = resolver.queried.lock().unwrap().clone();
    queried.sort_by_key(|(name, t)| (name.clone(), t.as_str()));
    let mut expected: Vec<(String, DnsRecordType)> = APEX_TYPES
        .iter()
        .map(|t| ("example.com".to_owned(), *t))
        .collect();
    expected.push(("_dmarc.example.com".to_owned(), DnsRecordType::Txt));
    expected.sort_by_key(|(name, t)| (name.clone(), t.as_str()));
    // No enumeration, no queries for discovered names (MX/NS/CNAME targets).
    assert_eq!(queried, expected);
}

#[tokio::test]
async fn oversized_answers_are_bounded() {
    let many: Vec<DnsRecordData> = (0..100u8).map(|i| a(&format!("93.184.{i}.1"))).collect();
    let huge_txt = format!("v=spf1 {}", "x".repeat(50_000));
    let huge_name = format!("{}.example.net", "n".repeat(5000));
    let resolver = example_com()
        .records("example.com", DnsRecordType::A, many)
        .txt("example.com", &[&huge_txt])
        .records(
            "example.com",
            DnsRecordType::Ns,
            vec![DnsRecordData::Ns {
                nameserver: huge_name,
            }],
        );
    let run = investigate(resolver).await;
    let inv = &run.investigation;

    assert_eq!(
        records_of(inv, DnsRecordType::A).len(),
        MAX_RECORDS_PER_QUERY
    );
    let apex_txt: Vec<_> = records_of(inv, DnsRecordType::Txt)
        .into_iter()
        .filter_map(DnsRecordData::txt)
        .filter(|t| t.starts_with("v=spf1"))
        .collect();
    assert_eq!(apex_txt[0].len(), MAX_TXT_BYTES);
    assert!(
        records_of(inv, DnsRecordType::Ns).is_empty(),
        "absurd record dropped"
    );
    let limit = inv
        .findings()
        .iter()
        .find(|f| f.code() == &LIMIT_EXCEEDED)
        .expect("limit finding");
    assert!(limit.detail().contains("A example.com"));
    assert!(limit.detail().contains("TXT example.com"));
    assert!(limit.detail().contains("NS example.com"));
    // Pivots stay bounded by the engine's entity limit.
    assert_eq!(
        run.stats.pivots_followed,
        EngineConfig::default().pivots.max_entities
    );
}

#[tokio::test]
async fn unicode_and_control_characters_are_kept_as_evidence_and_sanitized_in_findings() {
    let hostile = "v=spf1 include:\u{1b}[2J\u{1b}[31mfake.example ünïcödé\u{202e} ~all";
    let resolver = example_com().txt("example.com", &[hostile]);
    let run = investigate(resolver).await;
    let inv = &run.investigation;

    // The observation is faithful to what the resolver returned.
    assert!(
        records_of(inv, DnsRecordType::Txt)
            .iter()
            .any(|d| d.txt() == Some(hostile))
    );
    // Findings never carry raw control or bidi characters.
    for finding in inv.findings() {
        assert!(
            !finding.detail().chars().any(sentinel_core::text::is_unsafe),
            "{}",
            finding.detail()
        );
    }
    assert!(codes(inv).contains(&"dns.spf.softfail"));
    assert!(codes(inv).contains(&"dns.spf.malformed"));
}

#[tokio::test]
async fn private_addresses_are_reported_and_never_pivoted() {
    let resolver = example_com().records(
        "example.com",
        DnsRecordType::A,
        vec![a("10.0.0.5"), a("93.184.215.14")],
    );
    let run = investigate(resolver).await;
    assert!(codes(&run.investigation).contains(&"dns.address.non_public"));
    assert_eq!(run.stats.pivots_followed, 2); // the public IPv4 and the IPv6
    assert_eq!(run.stats.pivots_dropped, 1);
}

#[test]
fn query_plan_skips_dmarc_when_the_name_would_be_too_long() {
    let label = "a".repeat(63);
    let long = format!("{label}.{label}.{label}.{}.com", "b".repeat(57));
    let domain = DomainName::parse(&long).unwrap();
    assert!(plan(&domain).iter().all(|q| !q.is_dmarc));
    assert_eq!(plan(&DomainName::parse("example.com").unwrap()).len(), 9);
}

#[test]
fn truncation_respects_utf8_boundaries() {
    assert_eq!(truncate_at_char_boundary("ééé", 3), "é");
    assert_eq!(truncate_at_char_boundary("abc", 10), "abc");
}
