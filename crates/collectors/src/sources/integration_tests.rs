//! End-to-end: domain → DNS → public IP pivots → Cymru ASN + RDAP, through
//! the real engine, HTTP client and network policy (fake DNS, mock RDAP).

use std::sync::Arc;

use sentinel_core::{
    DnsRecordData, DnsRecordType, Indicator, Investigation, ObservationData, RelationKind,
    SourceOutcome,
};
use url::Url;
use wiremock::matchers::path;
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::abuseipdb::AbuseIpDbCollector;
use super::ct::CtCollector;
use super::cymru::CymruCollector;
use super::dns::DnsCollector;
use super::malwarebazaar::MalwareBazaarCollector;
use super::rdap::RdapCollector;
use super::urlhaus::UrlhausCollector;
use super::virustotal::VirusTotalCollector;
use crate::clock::testing::FixedClock;
use crate::dns::DnsResolver;
use crate::engine::{Engine, EngineConfig, EngineRun, PivotLimits};
use crate::http::{HttpClient, HttpConfig};
use crate::testing::FakeResolver;

const V4: &str = "93.184.215.14";
const V6: &str = "2606:2800:21f:cb07:6820:80da:af6b:8b2c";
const PRIVATE: &str = "10.0.0.5";

struct World {
    resolver: Arc<FakeResolver>,
    bootstrap: MockServer,
    rdap: MockServer,
    crtsh: MockServer,
    abuse: MockServer,
}

const ABUSE_KEY: &str = "integration-test-key";

/// A crt.sh answer with 300 subdomain names, look-alikes and hostile names.
fn ct_body() -> String {
    let names: Vec<String> = (0..300).map(|i| format!("host{i}.example.com")).collect();
    format!(
        r#"[{{"id": 42, "issuer_name": "CN=CA", "serial_number": "0a", "not_before": "2026-01-01T00:00:00",
             "not_after": "2027-01-01T00:00:00", "name_value": "{}\nexample.com.evil.test\n\u001b[2Jevil.example.com\n*.example.com"}}]"#,
        names.join("\\n")
    )
}

fn v6_origin_name() -> String {
    super::cymru::origin_query_name(V6.parse().unwrap())
}

async fn world() -> World {
    let a = |ip: &str| DnsRecordData::A {
        address: ip.parse().unwrap(),
    };
    let resolver = FakeResolver::default()
        // The same public IP twice (duplicate pivot) plus a private one.
        .records(
            "example.com",
            DnsRecordType::A,
            vec![a(V4), a(V4), a(PRIVATE)],
        )
        .records(
            "example.com",
            DnsRecordType::Aaaa,
            vec![DnsRecordData::Aaaa {
                address: V6.parse().unwrap(),
            }],
        )
        .txt("example.com", &["v=spf1 -all"])
        .txt(
            "14.215.184.93.origin.asn.cymru.com",
            &["15133 | 93.184.215.0/24 | US | ripencc | 2008-06-02"],
        )
        .txt(
            &v6_origin_name(),
            &["15133 | 2606:2800::/32 | US | arin | 2008-06-02"],
        )
        .txt(
            "AS15133.asn.cymru.com",
            &["15133 | US | arin | 2007-03-19 | EDGECAST, US"],
        );

    let bootstrap = MockServer::start().await;
    let rdap = MockServer::start().await;
    let service = format!("{}/", rdap.uri());
    for (file, prefix) in [("/ipv4.json", "93.0.0.0/8"), ("/ipv6.json", "2606::/16")] {
        Mock::given(path(file))
            .respond_with(ResponseTemplate::new(200).set_body_string(format!(
                r#"{{"services": [[["{prefix}"], ["{service}"]]]}}"#
            )))
            .mount(&bootstrap)
            .await;
    }
    for (ip, start, end, cidr, len) in [
        (V4, "93.184.215.0", "93.184.215.255", "93.184.215.0", 24),
        (
            V6,
            "2606:2800::",
            "2606:2800:ffff:ffff:ffff:ffff:ffff:ffff",
            "2606:2800::",
            32,
        ),
    ] {
        let key = if ip.contains(':') {
            "v6prefix"
        } else {
            "v4prefix"
        };
        Mock::given(path(format!("/ip/{ip}")))
            .respond_with(ResponseTemplate::new(200).set_body_string(format!(
                r#"{{"objectClassName": "ip network", "handle": "NET-{len}", "startAddress": "{start}", "endAddress": "{end}",
                    "cidr0_cidrs": [{{"{key}": "{cidr}", "length": {len}}}]}}"#
            )))
            .mount(&rdap)
            .await;
    }
    let crtsh = MockServer::start().await;
    Mock::given(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(ct_body()))
        .mount(&crtsh)
        .await;
    let abuse = MockServer::start().await;
    for ip in [V4, V6] {
        Mock::given(path("/api/v2/check"))
            .and(wiremock::matchers::query_param("ipAddress", ip))
            .and(wiremock::matchers::header("key", ABUSE_KEY))
            .respond_with(ResponseTemplate::new(200).set_body_string(format!(
                r#"{{"data": {{"ipAddress": "{ip}", "abuseConfidenceScore": 0, "totalReports": 0, "numDistinctUsers": 0, "lastReportedAt": null}}}}"#
            )))
            .mount(&abuse)
            .await;
    }
    World {
        resolver: Arc::new(resolver),
        bootstrap,
        rdap,
        crtsh,
        abuse,
    }
}

impl World {
    fn engine(&self, config: EngineConfig) -> Engine {
        self.engine_with(config, &[])
    }

    /// The standard engine, also allowed to reach `extra` mock servers.
    fn engine_with(&self, config: EngineConfig, extra: &[&MockServer]) -> Engine {
        let mut addresses = vec![
            *self.bootstrap.address(),
            *self.rdap.address(),
            *self.crtsh.address(),
            *self.abuse.address(),
        ];
        addresses.extend(extra.iter().map(|s| *s.address()));
        let http = HttpClient::for_tests(HttpConfig::default(), addresses).unwrap();
        let mut engine = Engine::new(http, Arc::new(FixedClock::default()), config);
        let resolver = Arc::clone(&self.resolver) as Arc<dyn DnsResolver>;
        engine
            .register(Arc::new(DnsCollector::new(Arc::clone(&resolver))))
            .unwrap();
        engine
            .register(Arc::new(CymruCollector::new(resolver)))
            .unwrap();
        engine
            .register(Arc::new(AbuseIpDbCollector::for_tests(
                Url::parse(&format!("{}/api/v2/check", self.abuse.uri())).unwrap(),
                Some(secrecy::SecretString::from(ABUSE_KEY)),
            )))
            .unwrap();
        engine
            .register(Arc::new(CtCollector::for_tests(
                Url::parse(&format!("{}/", self.crtsh.uri())).unwrap(),
            )))
            .unwrap();
        engine
            .register(Arc::new(RdapCollector::for_tests(
                Url::parse(&format!("{}/", self.bootstrap.uri())).unwrap(),
            )))
            .unwrap();
        engine
    }

    async fn run(&self, config: EngineConfig) -> EngineRun {
        self.engine(config)
            .investigate(Indicator::parse_domain("example.com").unwrap())
            .await
            .unwrap()
    }

    /// The `ipAddress` values AbuseIPDB received.
    async fn abuse_queries(&self) -> Vec<String> {
        self.abuse
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter_map(|r| {
                r.url
                    .query_pairs()
                    .find(|(k, _)| k == "ipAddress")
                    .map(|(_, v)| v.into_owned())
            })
            .collect()
    }

    async fn rdap_paths(&self) -> Vec<String> {
        self.rdap
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|r| r.url.path().to_owned())
            .collect()
    }
}

fn assert_integrity(investigation: &Investigation) {
    for relationship in investigation.relationships() {
        for id in relationship.evidence() {
            assert!(
                investigation.observation(*id).is_some(),
                "dangling relationship evidence"
            );
        }
    }
    for finding in investigation.findings() {
        for id in finding.evidence() {
            assert!(
                investigation.observation(*id).is_some(),
                "dangling finding evidence"
            );
        }
    }
}

fn sources(investigation: &Investigation, source: &str) -> Vec<(String, SourceOutcome)> {
    investigation
        .sources()
        .iter()
        .filter(|s| s.source().as_str() == source)
        .map(|s| (s.indicator().to_string(), s.outcome().clone()))
        .collect()
}

#[tokio::test]
async fn domain_to_asn_and_rdap() {
    let world = world().await;
    let run = world.run(EngineConfig::default()).await;
    let inv = &run.investigation;
    assert_integrity(inv);

    // DNS ran on the target; ASN and RDAP ran once per distinct public IP.
    assert_eq!(sources(inv, "dns").len(), 1);
    let mut cymru: Vec<String> = sources(inv, "cymru")
        .into_iter()
        .map(|(ip, _)| ip)
        .collect();
    cymru.sort();
    assert_eq!(cymru, vec![V6.to_owned(), V4.to_owned()]);
    for (ip, outcome) in sources(inv, "cymru")
        .into_iter()
        .chain(sources(inv, "rdap"))
    {
        assert!(
            matches!(outcome, SourceOutcome::Succeeded { .. }),
            "{ip}: {outcome:?}"
        );
    }
    assert_eq!(run.stats.pivots_followed, 2);
    assert_eq!(run.stats.pivots_dropped, 1, "the private address");

    let kinds = |kind: RelationKind| {
        inv.relationships()
            .iter()
            .filter(|r| r.kind() == kind)
            .count()
    };
    assert_eq!(
        kinds(RelationKind::ResolvesTo),
        3,
        "domain → V4, V6 and the private IP (data, not a target)"
    );
    assert_eq!(kinds(RelationKind::AnnouncedBy), 2);
    assert_eq!(kinds(RelationKind::RegisteredIn), 2);

    let codes: Vec<&str> = inv.findings().iter().map(|f| f.code().as_str()).collect();
    for expected in ["dns.address.non_public", "asn.origin", "rdap.network"] {
        assert!(codes.contains(&expected), "missing {expected}: {codes:?}");
    }
    assert!(
        inv.observations()
            .iter()
            .any(|o| matches!(o.data(), ObservationData::NetworkRegistration(_)))
    );

    // Requests: DNS 9 + CT 1 + Cymru 2×(origin + AS) + RDAP 2 bootstraps
    // + 2 queries + AbuseIPDB 2.
    assert_eq!(run.stats.requests_used, 9 + 1 + 4 + 4 + 2);
    let abuse = sources(inv, "abuseipdb");
    assert_eq!(abuse.len(), 2);
    assert!(
        abuse
            .iter()
            .all(|(_, o)| matches!(o, SourceOutcome::Succeeded { .. }))
    );
    assert_eq!(sources(inv, "ct").len(), 1);
}

#[tokio::test]
async fn private_addresses_never_reach_external_sources() {
    let world = world().await;
    world.run(EngineConfig::default()).await;
    let queried = world.resolver.queried_names();
    assert!(
        !queried.iter().any(|n| n.starts_with("5.0.0.10.")),
        "no Cymru query for {PRIVATE}: {queried:?}"
    );
    assert!(!world.rdap_paths().await.iter().any(|p| p.contains(PRIVATE)));
}

#[tokio::test]
async fn duplicate_pivots_are_enriched_once() {
    let world = world().await;
    world.run(EngineConfig::default()).await;
    let v4_queries = world
        .rdap_paths()
        .await
        .iter()
        .filter(|p| p.ends_with(V4))
        .count();
    assert_eq!(v4_queries, 1, "the duplicated A record is enriched once");
    let origin_queries = world
        .resolver
        .queried_names()
        .iter()
        .filter(|n| n.starts_with("14.215.184.93."))
        .count();
    assert_eq!(origin_queries, 1);
}

#[tokio::test]
async fn pivot_entity_limit_bounds_enrichment() {
    let world = world().await;
    let config = EngineConfig {
        pivots: PivotLimits {
            max_depth: 1,
            max_entities: 1,
        },
        ..EngineConfig::default()
    };
    let run = world.run(config).await;
    assert_eq!(run.stats.pivots_followed, 1);
    assert_eq!(sources(&run.investigation, "cymru").len(), 1);
    assert_eq!(sources(&run.investigation, "rdap").len(), 1);
    assert_integrity(&run.investigation);
}

#[tokio::test]
async fn pivot_depth_zero_means_dns_only() {
    let world = world().await;
    let config = EngineConfig {
        pivots: PivotLimits {
            max_depth: 0,
            max_entities: 10,
        },
        ..EngineConfig::default()
    };
    let run = world.run(config).await;
    assert_eq!(
        sources(&run.investigation, "cymru"),
        vec![("example.com".to_owned(), SourceOutcome::Unsupported)],
        "no pivot reached the IP collectors"
    );
    assert!(world.rdap_paths().await.is_empty());
    assert!(
        world
            .bootstrap
            .received_requests()
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn a_tight_request_budget_degrades_gracefully() {
    let world = world().await;
    let config = EngineConfig {
        max_requests: 11,
        ..EngineConfig::default()
    };
    let run = world.run(config).await;
    assert!(run.stats.requests_used <= 11);
    assert_integrity(&run.investigation);
    let failed = run
        .investigation
        .sources()
        .iter()
        .filter(|s| !matches!(s.outcome(), SourceOutcome::Succeeded { .. }))
        .count();
    assert!(failed > 0, "some sources must report the exhausted budget");
}

#[tokio::test]
async fn ct_names_never_cause_downstream_requests() {
    let world = world().await;
    let run = world.run(EngineConfig::default()).await;
    let inv = &run.investigation;
    assert_integrity(inv);

    // 300 CT names were reported; the per-certificate limit keeps 100 and
    // the truncation is reported, not hidden.
    let covered = inv
        .relationships()
        .iter()
        .filter(|r| r.kind() == RelationKind::CoversName)
        .count();
    assert_eq!(covered, super::ct::MAX_NAMES_PER_CERTIFICATE);
    assert!(
        inv.findings()
            .iter()
            .any(|f| f.code().as_str() == "ct.results_truncated")
    );
    // … but none of them was resolved, queried or enriched.
    let queried = world.resolver.queried_names();
    assert!(
        !queried
            .iter()
            .any(|n| n.contains("host") || n.contains("evil")),
        "CT names must not be queried: {queried:?}"
    );
    assert_eq!(
        world.crtsh.received_requests().await.unwrap().len(),
        1,
        "one CT query per investigation"
    );
    // Source runs: dns + ct on the target; cymru + rdap + abuseipdb on the
    // 2 DNS IPs only.
    assert_eq!(run.stats.source_runs, 2 + 3 * 2);
    assert_eq!(run.stats.pivots_followed, 2);
    // Hostile and look-alike names never become relationship targets.
    assert!(
        !inv.relationships()
            .iter()
            .any(|r| r.target().to_string().contains("evil"))
    );
}

#[tokio::test]
async fn a_slow_ct_source_is_cut_by_the_global_deadline() {
    let world = world().await;
    world.crtsh.reset().await;
    Mock::given(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("[]")
                .set_delay(std::time::Duration::from_secs(10)),
        )
        .mount(&world.crtsh)
        .await;
    let config = EngineConfig {
        investigation_timeout: std::time::Duration::from_millis(800),
        ..EngineConfig::default()
    };
    let run = world.run(config).await;
    let ct = sources(&run.investigation, "ct");
    assert_eq!(ct.len(), 1);
    assert!(
        matches!(ct[0].1, SourceOutcome::TimedOut { .. }),
        "{:?}",
        ct[0].1
    );
    assert!(run.stats.deadline_exceeded);
    // The fast sources still delivered their results.
    assert!(matches!(
        sources(&run.investigation, "dns")[0].1,
        SourceOutcome::Succeeded { .. }
    ));
    assert_integrity(&run.investigation);
}

#[tokio::test]
async fn only_public_dns_ips_reach_the_reputation_provider() {
    let world = world().await;
    world.run(EngineConfig::default()).await;
    let mut queried = world.abuse_queries().await;
    queried.sort();
    // Never the domain, a CT hostname, the private IP, or a duplicate.
    assert_eq!(queried, vec![V6.to_owned(), V4.to_owned()]);
}

#[tokio::test]
async fn ip_target_flow_asn_rdap_and_reputation() {
    let world = world().await;
    let run = world
        .engine(EngineConfig::default())
        .investigate(Indicator::parse_ip(V4).unwrap())
        .await
        .unwrap();
    let inv = &run.investigation;
    assert_integrity(inv);
    for source in ["cymru", "rdap", "abuseipdb"] {
        let statuses = sources(inv, source);
        assert_eq!(statuses.len(), 1, "{source}");
        assert!(
            matches!(statuses[0].1, SourceOutcome::Succeeded { .. }),
            "{source}: {:?}",
            statuses[0].1
        );
    }
    for source in ["dns", "ct"] {
        assert_eq!(
            sources(inv, source),
            vec![(V4.to_owned(), SourceOutcome::Unsupported)]
        );
    }
    assert!(
        inv.observations()
            .iter()
            .any(|o| matches!(o.data(), ObservationData::IpReputation(_)))
    );
    assert_eq!(world.abuse_queries().await, vec![V4.to_owned()]);
    assert_eq!(run.stats.requests_used, 2 + 2 + 1);
}

#[tokio::test]
async fn virustotal_enriches_the_target_only_and_its_content_never_becomes_a_pivot() {
    const VT_KEY: &str = "integration-vt-key";
    const VT_ONLY_IP: &str = "198.51.100.77";
    let world = world().await;
    let baseline = world.run(EngineConfig::default()).await.stats.requests_used;

    let vt = MockServer::start().await;
    Mock::given(path("/api/v3/domains/example.com"))
        .and(wiremock::matchers::header("x-apikey", VT_KEY))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            r#"{{"data": {{"type": "domain", "id": "example.com", "attributes": {{
                "last_analysis_stats": {{"harmless": 60, "malicious": 1, "suspicious": 0, "timeout": 0, "undetected": 20}},
                "reputation": 0, "total_votes": {{"harmless": 0, "malicious": 0}}, "last_analysis_date": 1758614400,
                "last_dns_records": [{{"type": "A", "value": "{VT_ONLY_IP}"}}, {{"type": "CNAME", "value": "cdn.example.net"}}],
                "last_https_certificate": {{"extensions": {{"subject_alternative_name": ["hidden.example.com"]}}}},
                "whois": "Registrant Email: owner@example.net"}}}}}}"#
        )))
        .mount(&vt)
        .await;
    let mut engine = world.engine_with(EngineConfig::default(), &[&vt]);
    engine
        .register(Arc::new(VirusTotalCollector::for_tests(
            Url::parse(&format!("{}/api/v3", vt.uri())).unwrap(),
            Some(secrecy::SecretString::from(VT_KEY)),
        )))
        .unwrap();
    let run = engine
        .investigate(Indicator::parse_domain("example.com").unwrap())
        .await
        .unwrap();
    let inv = &run.investigation;
    assert_integrity(inv);

    // Exactly one lookup, for the target; pivoted IPs are not sent (TargetOnly).
    assert_eq!(vt.received_requests().await.unwrap().len(), 1);
    let statuses = sources(inv, "virustotal");
    assert_eq!(
        statuses,
        vec![(
            "example.com".to_owned(),
            SourceOutcome::Succeeded { observations: 1 }
        )]
    );
    assert_eq!(run.stats.requests_used, baseline + 1);

    // Nothing from VirusTotal's content was pivoted to or looked up.
    let mut abuse = world.abuse_queries().await;
    abuse.sort();
    assert!(!abuse.iter().any(|q| q == VT_ONLY_IP), "{abuse:?}");
    let serialized = serde_json::to_string(inv).unwrap();
    for leaked in [
        VT_ONLY_IP,
        "cdn.example.net",
        "hidden.example.com",
        "owner@example.net",
    ] {
        assert!(
            !serialized.contains(leaked),
            "{leaked} must not enter the investigation"
        );
    }
    assert!(
        world
            .resolver
            .queried_names()
            .iter()
            .all(|name| !name.contains("77.100.51.198") && !name.contains("cdn.example.net")),
        "no DNS lookups of VirusTotal content"
    );
    assert!(
        inv.observations()
            .iter()
            .any(|o| matches!(o.data(), ObservationData::ProviderReputation(_)))
    );
}

#[tokio::test]
async fn urlhaus_enriches_the_target_only_and_listed_urls_are_never_followed() {
    const UH_KEY: &str = "integration-urlhaus-key";
    let world = world().await;
    let baseline = world.run(EngineConfig::default()).await.stats.requests_used;

    // A "malware host" the client is allowed to reach: only Sentinel's logic
    // keeps it untouched.
    let malware = MockServer::start().await;
    Mock::given(wiremock::matchers::any())
        .respond_with(ResponseTemplate::new(200).set_body_string("MZ"))
        .mount(&malware)
        .await;
    let urlhaus = MockServer::start().await;
    Mock::given(path("/v1/host/"))
        .and(wiremock::matchers::header("auth-key", UH_KEY))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            r#"{{"query_status": "ok", "host": "example.com", "firstseen": "2024-01-01 00:00:00 UTC", "url_count": "2",
                "urls": [
                  {{"id": "1", "url": "{m}/drop.exe", "url_status": "online", "date_added": "2024-01-01 00:00:00 UTC"}},
                  {{"id": "2", "url": "http://cdn.example.net/x.sh", "url_status": "offline"}},
                  {{"id": "3", "url": "http://198.51.100.99/bot", "url_status": "online"}}
                ]}}"#,
            m = malware.uri()
        )))
        .mount(&urlhaus)
        .await;
    let mut engine = world.engine_with(EngineConfig::default(), &[&urlhaus, &malware]);
    engine
        .register(Arc::new(UrlhausCollector::for_tests(
            Url::parse(&format!("{}/v1/", urlhaus.uri())).unwrap(),
            Some(secrecy::SecretString::from(UH_KEY)),
        )))
        .unwrap();
    let run = engine
        .investigate(Indicator::parse_domain("example.com").unwrap())
        .await
        .unwrap();
    let inv = &run.investigation;
    assert_integrity(inv);

    assert_eq!(
        urlhaus.received_requests().await.unwrap().len(),
        1,
        "target only"
    );
    assert!(
        malware.received_requests().await.unwrap().is_empty(),
        "listed URL accessed"
    );
    assert_eq!(
        sources(inv, "urlhaus"),
        vec![(
            "example.com".to_owned(),
            SourceOutcome::Succeeded { observations: 1 }
        )]
    );
    assert_eq!(run.stats.requests_used, baseline + 1);
    let mut abuse = world.abuse_queries().await;
    abuse.sort();
    assert!(!abuse.iter().any(|q| q == "198.51.100.99"), "{abuse:?}");
    assert!(
        world
            .resolver
            .queried_names()
            .iter()
            .all(|name| !name.contains("cdn.example.net") && !name.contains("99.100.51.198")),
        "no DNS lookups of URLhaus content"
    );
    let serialized = serde_json::to_string(inv).unwrap();
    for leaked in ["drop.exe", "cdn.example.net", "198.51.100.99"] {
        assert!(
            !serialized.contains(leaked),
            "{leaked} must not enter the investigation"
        );
    }
}

#[tokio::test]
async fn malwarebazaar_content_never_becomes_a_lookup() {
    const MB_KEY: &str = "integration-mb-key";
    const SHA256: &str = "e167b20f1acf48f7ce0ae33a218e2c1b300b41c012ededf03e7a3522a4ebe95e";
    let world = world().await;
    let mb = MockServer::start().await;
    Mock::given(path("/api/v1/"))
        .and(wiremock::matchers::header("auth-key", MB_KEY))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            r#"{{"query_status": "ok", "data": [{{"sha256_hash": "{SHA256}", "sha1_hash": "{sha1}",
                "first_seen": "2024-01-01 00:00:00", "file_size": 10, "file_type": "exe",
                "file_type_mime": "application/x-dosexec", "signature": "AgentTesla",
                "file_name": "invoice-for-cdn.example.net.exe",
                "comments": [{{"comment": "C2 {V4} and http://cdn.example.net/gate"}}],
                "file_information": [{{"context": "dropped_by_url", "value": "http://example.com/x.exe"}}]}}]}}"#,
            sha1 = "c".repeat(40)
        )))
        .mount(&mb)
        .await;
    let mut engine = world.engine_with(EngineConfig::default(), &[&mb]);
    engine
        .register(Arc::new(MalwareBazaarCollector::for_tests(
            Url::parse(&format!("{}/api/v1/", mb.uri())).unwrap(),
            Some(secrecy::SecretString::from(MB_KEY)),
        )))
        .unwrap();
    let run = engine
        .investigate(Indicator::parse_file_hash(SHA256).unwrap())
        .await
        .unwrap();
    let inv = &run.investigation;
    assert_integrity(inv);
    assert_eq!(mb.received_requests().await.unwrap().len(), 1);
    assert_eq!(
        sources(inv, "malwarebazaar"),
        vec![(
            SHA256.to_owned(),
            SourceOutcome::Succeeded { observations: 1 }
        )]
    );
    for source in ["dns", "cymru", "abuseipdb", "ct", "rdap"] {
        assert_eq!(
            sources(inv, source),
            vec![(SHA256.to_owned(), SourceOutcome::Unsupported)],
            "{source}"
        );
    }
    assert!(
        world.resolver.queried_names().is_empty(),
        "no DNS from MalwareBazaar content"
    );
    assert!(world.abuse_queries().await.is_empty());
    assert!(world.rdap_paths().await.is_empty());
    assert!(world.crtsh.received_requests().await.unwrap().is_empty());
    assert_eq!(run.stats.requests_used, 1);
    let serialized = serde_json::to_string(inv).unwrap();
    for leaked in ["cdn.example.net", V4, "x.exe", "invoice"] {
        assert!(!serialized.contains(leaked), "{leaked}");
    }
}
