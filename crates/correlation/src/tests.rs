//! Correlation tests over hand-built investigations (no collectors, no I/O).

use std::net::IpAddr;
use std::time::{Duration, Instant};

use chrono::{TimeZone, Utc};
use proptest::prelude::*;
use sentinel_core::text::is_unsafe;
use sentinel_core::{
    Asn, AsnOrigin, CertificateId, Confidence, CtCertificate, DnsRecord, DnsRecordData,
    DnsRecordType, DomainName, Entity, Indicator, Investigation, IpPrefix, IpReputation,
    NetworkRegistration, Observation, ObservationData, ObservationId, Provenance,
    ProviderAttribute, ProviderListing, ProviderMetric, ProviderNoRecord, ProviderReputation,
    RelationKind, Relationship, Severity, Sha256Digest, SourceId, SourceOutcome, SourceStatus,
    Timestamp, classify_certificate_name,
};

use super::*;

const TARGET: &str = "example.com";

fn t(seconds: u32) -> Timestamp {
    Utc.with_ymd_and_hms(2026, 9, 23, 17, 40, 0).unwrap()
        + chrono::TimeDelta::seconds(seconds.into())
}

fn dom(s: &str) -> Indicator {
    Indicator::parse_domain(s).unwrap()
}

fn ip(s: &str) -> Indicator {
    Indicator::parse_ip(s).unwrap()
}

fn metric(name: &str, value: u64, max: Option<u64>) -> ProviderMetric {
    ProviderMetric {
        name: name.into(),
        value,
        max,
    }
}

/// Builds investigations the way the collectors do.
struct Fx {
    inv: Investigation,
}

impl Fx {
    fn new(target: Indicator) -> Self {
        Self {
            inv: Investigation::new(target, t(0)).unwrap(),
        }
    }

    fn domain() -> Self {
        Self::new(dom(TARGET))
    }

    fn observe(
        &mut self,
        indicator: Indicator,
        source: &'static str,
        at: u32,
        data: ObservationData,
    ) -> ObservationId {
        let digest = Sha256Digest::of(format!("{source}{at}{indicator}").as_bytes());
        self.inv.add_observation(
            Observation::new(
                indicator,
                SourceId::from_static(source),
                t(at),
                data,
                Confidence::saturating(90),
                Provenance::dns(TARGET, DnsRecordType::Txt, source),
            )
            .with_raw_response_hash(digest),
        )
    }

    fn relate(
        &mut self,
        source: impl Into<Entity>,
        kind: RelationKind,
        target: impl Into<Entity>,
        id: ObservationId,
    ) {
        self.inv
            .add_relationship(Relationship::new(source, kind, target, [id]).unwrap())
            .unwrap();
    }

    fn a(&mut self, name: &str, address: &str, at: u32) -> ObservationId {
        let addr: IpAddr = address.parse().unwrap();
        let data = match addr {
            IpAddr::V4(v4) => DnsRecordData::A { address: v4 },
            IpAddr::V6(v6) => DnsRecordData::Aaaa { address: v6 },
        };
        let id = self.observe(
            dom(TARGET),
            "dns",
            at,
            ObservationData::DnsRecord(DnsRecord::new(name, 300, data)),
        );
        self.relate(dom(name), RelationKind::ResolvesTo, ip(address), id);
        id
    }

    fn mx(&mut self, exchange: &str, at: u32) -> ObservationId {
        let id = self.observe(
            dom(TARGET),
            "dns",
            at,
            ObservationData::DnsRecord(DnsRecord::new(
                TARGET,
                300,
                DnsRecordData::Mx {
                    preference: 10,
                    exchange: exchange.into(),
                },
            )),
        );
        self.relate(
            dom(TARGET),
            RelationKind::HasMailExchanger,
            dom(exchange),
            id,
        );
        id
    }

    fn asn(&mut self, address: &str, asns: &[u32], prefix: Option<&str>, at: u32) -> ObservationId {
        let asns: Vec<Asn> = asns.iter().map(|n| Asn::new(*n).unwrap()).collect();
        let id = self.observe(
            ip(address),
            "cymru",
            at,
            ObservationData::AsnOrigin(AsnOrigin {
                ip: address.parse().unwrap(),
                asns: asns.clone(),
                prefix: prefix.map(|p| IpPrefix::parse(p).unwrap()),
                country: None,
                registry: None,
                allocated: None,
                source_text: String::new(),
                issues: vec![],
            }),
        );
        for asn in asns {
            self.relate(ip(address), RelationKind::AnnouncedBy, asn, id);
        }
        id
    }

    fn rdap(
        &mut self,
        address: &str,
        cidrs: &[&str],
        range: (&str, &str),
        at: u32,
    ) -> ObservationId {
        let cidrs: Vec<IpPrefix> = cidrs.iter().map(|c| IpPrefix::parse(c).unwrap()).collect();
        let id = self.observe(
            ip(address),
            "rdap",
            at,
            ObservationData::NetworkRegistration(NetworkRegistration {
                queried_ip: address.parse().unwrap(),
                handle: None,
                name: None,
                network_type: None,
                ip_version: None,
                start_address: Some(range.0.parse().unwrap()),
                end_address: Some(range.1.parse().unwrap()),
                cidrs: cidrs.clone(),
                parent_handle: None,
                country: None,
                status: vec![],
                registered_at: None,
                last_changed_at: None,
                organization: None,
                abuse_email: None,
                issues: vec![],
            }),
        );
        for cidr in cidrs {
            self.relate(ip(address), RelationKind::RegisteredIn, cidr, id);
        }
        id
    }

    fn cert(&mut self, entry: u64, names: &[&str], at: u32) -> ObservationId {
        let target = DomainName::parse(TARGET).unwrap();
        let classified: Vec<_> = names
            .iter()
            .map(|n| classify_certificate_name(n, &target))
            .collect();
        let id = self.observe(
            dom(TARGET),
            "ct",
            at,
            ObservationData::CtCertificate(CtCertificate {
                source_entry_id: Some(entry),
                serial_number: None,
                issuer: None,
                common_name: None,
                not_before: None,
                not_after: None,
                names: classified.clone(),
                omitted_email_names: 0,
                source_entries: 1,
                issues: vec![],
            }),
        );
        let cert = CertificateId::new("crtsh", &entry.to_string()).unwrap();
        for name in classified.iter().filter(|n| n.relation.is_related()) {
            let kind = if name.wildcard {
                RelationKind::CoversWildcard
            } else {
                RelationKind::CoversName
            };
            let domain = Indicator::from(name.normalized.clone().unwrap());
            self.relate(cert.clone(), kind, domain, id);
        }
        id
    }

    fn abuse(&mut self, address: &str, total: Option<u64>, at: u32) -> ObservationId {
        let mut metrics = vec![metric("abuse_confidence_score", 95, Some(100))];
        if let Some(total) = total {
            metrics.push(metric("total_reports", total, None));
        }
        self.observe(
            ip(address),
            "abuseipdb",
            at,
            ObservationData::IpReputation(IpReputation {
                provider: "abuseipdb".into(),
                queried_ip: address.parse().unwrap(),
                window_days: Some(90),
                metrics,
                last_reported_at: None,
                is_allowlisted: None,
                is_tor: None,
                usage_type: None,
                isp: None,
                domain: None,
                country_code: None,
                hostnames: vec![],
                context_source: None,
                issues: vec![],
            }),
        )
    }

    fn vt(&mut self, indicator: Indicator, malicious: u64, at: u32) -> ObservationId {
        let s = |n: &str, v| metric(&format!("last_analysis_stats.{n}"), v, None);
        self.observe(
            indicator,
            "virustotal",
            at,
            ObservationData::ProviderReputation(ProviderReputation {
                provider: "virustotal".into(),
                metrics: vec![
                    s("malicious", malicious),
                    s("suspicious", 0),
                    s("undetected", 30),
                    s("harmless", 50),
                    s("timeout", 0),
                ],
                community_score: Some(-2),
                last_analysis_at: None,
                tags: vec![],
                issues: vec![],
            }),
        )
    }

    fn urlhaus(&mut self, indicator: Indicator, value: &str, at: u32) -> ObservationId {
        self.observe(
            indicator,
            "urlhaus",
            at,
            ObservationData::ProviderListing(ProviderListing {
                provider: "urlhaus".into(),
                entry_id: None,
                attributes: vec![ProviderAttribute {
                    name: "blacklists.surbl".into(),
                    value: value.into(),
                }],
                metrics: vec![metric("url_count", 3, None)],
                dates: vec![],
                tags: vec![],
                issues: vec![],
            }),
        )
    }

    fn no_record(&mut self, source: &'static str, indicator: Indicator, at: u32) -> ObservationId {
        self.observe(
            indicator,
            source,
            at,
            ObservationData::ProviderNoRecord(ProviderNoRecord {
                provider: source.into(),
            }),
        )
    }

    fn status(&mut self, source: &'static str, indicator: Indicator, outcome: SourceOutcome) {
        self.inv.record_source(SourceStatus::new(
            SourceId::from_static(source),
            indicator,
            outcome,
            t(0),
            t(1),
        ));
    }

    fn report(&self) -> CorrelationReport {
        correlate(&self.inv)
    }
}

fn only(report: &CorrelationReport, kind: CorrelationKind) -> &Correlation {
    let found: Vec<_> = report.of_kind(kind).collect();
    assert_eq!(found.len(), 1, "{kind:?}: {:#?}", report.correlations);
    found[0]
}

fn link_kinds(c: &Correlation) -> Vec<RelationKind> {
    c.links().iter().map(Relationship::kind).collect()
}

/// Invariants every report must satisfy.
fn assert_sound(inv: &Investigation, report: &CorrelationReport) {
    let index = EvidenceIndex::new(inv);
    assert_eq!(report.correlations.len(), report.findings.len());
    for (c, f) in report.correlations.iter().zip(&report.findings) {
        assert!(!c.evidence().is_empty());
        for id in c.evidence() {
            assert!(inv.observation(*id).is_some(), "dangling evidence");
        }
        for subject in c.subjects() {
            assert!(index.knows_entity(subject), "new entity {subject}");
        }
        let cited = c
            .links()
            .iter()
            .flat_map(|l| l.evidence().iter().copied())
            .chain(c.claims().iter().map(|x| x.observation))
            .chain(c.supporting().iter().copied())
            .chain(
                c.conflicts()
                    .iter()
                    .flat_map(|x| x.evidence.iter().copied()),
            );
        for id in cited {
            assert!(
                c.evidence().contains(&id),
                "cited but not listed as evidence"
            );
        }
        let mut sorted = c.evidence().to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted, c.evidence(), "evidence is a sorted set");
        for claim in c.claims() {
            let observation = inv.observation(claim.observation).unwrap();
            assert_eq!(claim.collected_at, observation.collected_at());
            assert_eq!(&claim.provider, observation.source());
        }
        let times: Vec<_> = c
            .evidence()
            .iter()
            .map(|id| inv.observation(*id).unwrap().collected_at())
            .collect();
        assert_eq!(c.observed().first, *times.iter().min().unwrap());
        assert_eq!(c.observed().last, *times.iter().max().unwrap());
        for link in c.links() {
            assert!(
                inv.relationships().iter().any(|r| r.is_same_edge(link)),
                "links must be existing relationships"
            );
        }
        assert_eq!(f.severity(), Severity::Info);
        assert_eq!(f.code(), &c.kind().finding_code());
        assert_eq!(f.evidence(), c.evidence());
        let min = c
            .evidence()
            .iter()
            .map(|id| inv.observation(*id).unwrap().confidence())
            .min()
            .unwrap();
        assert_eq!(f.confidence(), min, "finding confidence = weakest evidence");
        let lower = format!("{} {}", f.title(), f.detail()).to_lowercase();
        for banned in [
            "is malicious",
            "compromised",
            "attacker",
            "apt",
            "confirmed threat",
            "threat score",
            "risk score",
            "malicious actor",
        ] {
            assert!(!lower.contains(banned), "{banned}: {lower}");
        }
        assert!(!f.detail().chars().any(is_unsafe));
    }
}

// ------------------------------------------------------------------ C1

#[test]
fn domain_ip_asn_network_chain_with_auditable_provenance() {
    let mut fx = Fx::domain();
    let dns = fx.a(TARGET, "93.184.215.14", 1);
    let asn = fx.asn("93.184.215.14", &[15133], Some("93.184.215.0/24"), 2);
    let rdap = fx.rdap(
        "93.184.215.14",
        &["93.184.215.0/24"],
        ("93.184.215.0", "93.184.215.255"),
        3,
    );
    let report = fx.report();
    assert_sound(&fx.inv, &report);

    let c = only(&report, CorrelationKind::DomainIpInfrastructure);
    assert_eq!(
        link_kinds(c),
        [
            RelationKind::ResolvesTo,
            RelationKind::AnnouncedBy,
            RelationKind::RegisteredIn
        ]
    );
    let mut expected = vec![dns, asn, rdap];
    expected.sort_unstable();
    assert_eq!(c.evidence(), expected);
    assert!(c.conflicts().is_empty(), "{:?}", c.conflicts());
    assert!(c.gaps().is_empty());
    assert_eq!(c.observed().first, t(1));
    assert_eq!(c.observed().last, t(3));
    assert!(c.limitations().iter().any(|l| l == NOT_SIMULTANEOUS));
    assert!(
        c.limitations()
            .iter()
            .any(|l| l == ROUTING_IS_NOT_OWNERSHIP)
    );
    assert!(c.summary().starts_with(
        "example.com resolves to 93.184.215.14 (DNS); 93.184.215.14 is announced by AS15133 (BGP origin); 93.184.215.14 is registered in 93.184.215.0/24 (registry)."
    ), "{}", c.summary());

    // The chain is auditable: every step resolves to source, time, digest.
    let index = EvidenceIndex::new(&fx.inv);
    let steps = c.provenance(&index);
    assert_eq!(steps.len(), 3);
    for step in &steps {
        let observation = fx.inv.observation(step.observation).unwrap();
        assert_eq!(step.source, observation.source());
        assert_eq!(step.collected_at, observation.collected_at());
        assert_eq!(step.digest, observation.raw_response_hash());
        assert!(step.digest.is_some());
        assert_eq!(step.provenance, observation.provenance());
        assert_eq!(step.confidence, observation.confidence());
    }
    let sources: Vec<&str> = steps.iter().map(|s| s.source.as_str()).collect();
    for expected in ["dns", "cymru", "rdap"] {
        assert!(sources.contains(&expected), "{sources:?}");
    }
}

#[test]
fn missing_links_are_gaps_with_source_status() {
    let mut fx = Fx::domain();
    fx.a(TARGET, "93.184.215.14", 1);
    fx.asn("93.184.215.14", &[15133], Some("93.184.215.0/24"), 2);
    fx.status(
        "rdap",
        ip("93.184.215.14"),
        SourceOutcome::Failed { error: "x".into() },
    );
    let report = fx.report();
    let c = only(&report, CorrelationKind::DomainIpInfrastructure);
    assert_eq!(
        link_kinds(c),
        [RelationKind::ResolvesTo, RelationKind::AnnouncedBy]
    );
    assert_eq!(
        c.gaps(),
        [
            "No registered network (registered_in) is recorded for 93.184.215.14 (source status: rdap failed)."
        ]
    );
    // DNS alone is not a correlation.
    let mut fx = Fx::domain();
    fx.a(TARGET, "93.184.215.14", 1);
    assert!(fx.report().correlations.is_empty());
}

#[test]
fn asn_and_network_disagreements_are_conflicts_but_moas_and_multi_cidr_are_not() {
    let mut fx = Fx::domain();
    fx.a(TARGET, "93.184.215.14", 1);
    let first = fx.asn("93.184.215.14", &[15133], Some("93.184.215.0/24"), 2);
    let second = fx.asn("93.184.215.14", &[64496], Some("93.184.215.0/24"), 5);
    let r1 = fx.rdap(
        "93.184.215.14",
        &["93.184.215.0/24"],
        ("93.184.215.0", "93.184.215.255"),
        3,
    );
    let r2 = fx.rdap(
        "93.184.215.14",
        &["93.184.0.0/16"],
        ("93.184.0.0", "93.184.255.255"),
        4,
    );
    let report = fx.report();
    let c = only(&report, CorrelationKind::DomainIpInfrastructure);
    let descriptions: Vec<&str> = c
        .conflicts()
        .iter()
        .map(|x| x.description.as_str())
        .collect();
    assert!(descriptions.contains(&"Different observations report different origin ASes for 93.184.215.14: AS15133 vs. AS64496."), "{descriptions:?}");
    assert!(
        descriptions
            .iter()
            .any(|d| d.starts_with("Different observations report different registered networks"))
    );
    let asn_conflict = c
        .conflicts()
        .iter()
        .find(|x| x.description.contains("origin ASes"))
        .unwrap();
    let mut both = vec![first, second];
    both.sort_unstable();
    assert_eq!(asn_conflict.evidence, both, "both sides are cited");
    let net_conflict = c
        .conflicts()
        .iter()
        .find(|x| x.description.contains("registered networks"))
        .unwrap();
    assert!(net_conflict.evidence.contains(&r1) && net_conflict.evidence.contains(&r2));

    // One answer with two origins (MOAS) and one registration with two CIDRs.
    let mut fx = Fx::domain();
    fx.a(TARGET, "1.0.1.5", 1);
    fx.asn("1.0.1.5", &[13335, 15169], Some("1.0.0.0/22"), 2);
    fx.rdap(
        "1.0.1.5",
        &["1.0.0.0/23", "1.0.2.0/24"],
        ("1.0.0.0", "1.0.2.255"),
        3,
    );
    let report = fx.report();
    let c = only(&report, CorrelationKind::DomainIpInfrastructure);
    assert!(c.conflicts().is_empty(), "{:?}", c.conflicts());
    assert!(c.limitations().iter().any(|l| l == MOAS));
}

#[test]
fn containment_and_overlap_problems_are_conflicts() {
    let mut fx = Fx::domain();
    fx.a(TARGET, "93.184.215.14", 1);
    let asn = fx.asn("93.184.215.14", &[15133], Some("10.0.0.0/8"), 2);
    let rdap = fx.rdap(
        "93.184.215.14",
        &["198.51.100.0/24"],
        ("198.51.100.0", "198.51.100.255"),
        3,
    );
    let report = fx.report();
    let c = only(&report, CorrelationKind::DomainIpInfrastructure);
    let descriptions: Vec<&str> = c
        .conflicts()
        .iter()
        .map(|x| x.description.as_str())
        .collect();
    assert!(descriptions.contains(
        &"The BGP prefix 10.0.0.0/8 reported for 93.184.215.14 does not contain the address."
    ));
    assert!(descriptions.contains(
        &"The registered range reported for 93.184.215.14 does not contain the address."
    ));
    assert!(
        c.conflicts().iter().any(|x| x.evidence == [asn])
            && c.conflicts().iter().any(|x| x.evidence == [rdap])
    );

    // Both contain the IP but do not overlap each other.
    let mut fx = Fx::domain();
    fx.a(TARGET, "93.184.215.14", 1);
    fx.asn("93.184.215.14", &[15133], Some("93.184.215.0/24"), 2);
    fx.rdap(
        "93.184.215.14",
        &["93.184.215.8/29"],
        ("93.184.215.8", "93.184.215.15"),
        3,
    );
    let overlapping = fx.report();
    assert!(
        only(&overlapping, CorrelationKind::DomainIpInfrastructure)
            .conflicts()
            .is_empty(),
        "nested prefixes overlap"
    );
}

#[test]
fn same_time_evidence_has_no_simultaneity_caveat() {
    let mut fx = Fx::domain();
    fx.a(TARGET, "93.184.215.14", 1);
    fx.asn("93.184.215.14", &[15133], Some("93.184.215.0/24"), 1);
    let report = fx.report();
    let c = only(&report, CorrelationKind::DomainIpInfrastructure);
    assert!(!c.limitations().iter().any(|l| l == NOT_SIMULTANEOUS));
}

// ------------------------------------------------------------- C2 / C5

#[test]
fn domain_certificate_cites_certificates_and_dns_context() {
    let mut fx = Fx::domain();
    let dns = fx.a(TARGET, "93.184.215.14", 1);
    let c1 = fx.cert(1, &["example.com", "www.example.com"], 2);
    let c2 = fx.cert(2, &["*.example.com"], 2);
    fx.cert(3, &["other.test"], 2);
    let report = fx.report();
    assert_sound(&fx.inv, &report);
    let c = only(&report, CorrelationKind::DomainCertificate);
    assert_eq!(c.supporting(), [dns]);
    assert_eq!(c.links().len(), 2);
    assert!(c.evidence().contains(&c1) && c.evidence().contains(&c2));
    assert_eq!(
        c.summary(),
        "2 certificate(s) reported by Certificate Transparency list example.com (1 as the wildcard *.example.com). The domain also has DNS address records in this investigation."
    );
    assert!(
        c.limitations()
            .iter()
            .any(|l| l == CERTIFICATE_IS_NOT_PROOF)
    );
}

#[test]
fn ct_names_are_correlated_only_with_existing_dns_data() {
    let mut fx = Fx::domain();
    let mx = fx.mx("mail.example.com", 1);
    fx.cert(
        1,
        &["mail.example.com", "api.example.com", "dev.example.com"],
        2,
    );
    let report = fx.report();
    assert_sound(&fx.inv, &report);
    let c = only(&report, CorrelationKind::CtDnsNames);
    let names: Vec<String> = c.subjects().iter().map(ToString::to_string).collect();
    assert_eq!(names, ["mail.example.com"]);
    assert!(c.evidence().contains(&mx));
    assert_eq!(
        c.gaps(),
        [
            "2 related name(s) seen in Certificate Transparency have no DNS data in this investigation; they were not resolved (by design)."
        ]
    );
    // Without DNS data, no CT name is correlated (and none is looked up).
    let mut fx = Fx::domain();
    fx.cert(1, &["api.example.com"], 2);
    assert_eq!(fx.report().of_kind(CorrelationKind::CtDnsNames).count(), 0);
}

// ------------------------------------------------------------- C3 / C4

#[test]
fn multiple_providers_are_listed_not_combined() {
    let mut fx = Fx::new(ip("45.33.32.156"));
    let a = fx.abuse("45.33.32.156", Some(41), 1);
    let v = fx.vt(ip("45.33.32.156"), 4, 2);
    let u = fx.urlhaus(ip("45.33.32.156"), "listed", 3);
    let report = fx.report();
    assert_sound(&fx.inv, &report);
    let c = only(&report, CorrelationKind::MultipleSources);
    assert_eq!(c.claims().len(), 3);
    let by_provider = |p: &str| {
        c.claims()
            .iter()
            .find(|x| x.provider.as_str() == p)
            .unwrap()
    };
    assert_eq!(by_provider("abuseipdb").observation, a);
    assert_eq!(
        by_provider("abuseipdb").summary,
        "abuse_confidence_score=95/100, total_reports=41"
    );
    assert_eq!(by_provider("virustotal").observation, v);
    assert!(
        by_provider("virustotal")
            .summary
            .starts_with("last_analysis_stats.malicious=4")
    );
    assert_eq!(
        by_provider("urlhaus").summary,
        "listed, blacklists.surbl=listed, url_count=3"
    );
    assert_eq!(by_provider("urlhaus").observation, u);
    for claim in c.claims() {
        assert_eq!(claim.stance, ProviderStance::Flags);
        assert_eq!(
            claim.collected_at,
            fx.inv
                .observation(claim.observation)
                .unwrap()
                .collected_at()
        );
    }
    assert!(c.limitations().iter().any(|l| l == OWN_CLASSIFICATIONS));
    assert_eq!(
        report.of_kind(CorrelationKind::SourceDisagreement).count(),
        0,
        "all flag: no disagreement"
    );
    // Agreement does not raise severity or confidence.
    let finding = &report.findings[0];
    assert_eq!(finding.severity(), Severity::Info);
    assert_eq!(finding.confidence(), Confidence::saturating(90));
}

#[test]
fn detection_versus_no_record_is_kept_as_a_disagreement() {
    let mut fx = Fx::new(ip("45.33.32.156"));
    let v = fx.vt(ip("45.33.32.156"), 4, 1);
    let n = fx.no_record("urlhaus", ip("45.33.32.156"), 9);
    let a = fx.abuse("45.33.32.156", Some(0), 5);
    let report = fx.report();
    assert_sound(&fx.inv, &report);
    let c = only(&report, CorrelationKind::SourceDisagreement);
    assert_eq!(c.conflicts().len(), 1);
    let conflict = &c.conflicts()[0];
    assert_eq!(
        conflict.description,
        "For 45.33.32.156, virustotal report(s) something while abuseipdb, urlhaus do(es) not (abuseipdb: does_not_flag, urlhaus: no_record)."
    );
    let mut all = vec![v, n, a];
    all.sort_unstable();
    assert_eq!(conflict.evidence, all, "both sides are cited");
    assert!(c.limitations().iter().any(|l| l == NOT_RESOLVED));
    assert!(
        c.limitations().iter().any(|l| l == NOT_SIMULTANEOUS),
        "different times"
    );
    assert_eq!(
        report
            .findings
            .iter()
            .filter(|f| f.severity() != Severity::Info)
            .count(),
        0
    );
}

#[test]
fn a_provider_contradicting_itself_is_a_conflict_and_unclear_is_ignored() {
    let mut fx = Fx::new(ip("45.33.32.156"));
    fx.vt(ip("45.33.32.156"), 3, 1);
    fx.vt(ip("45.33.32.156"), 0, 2);
    fx.abuse("45.33.32.156", None, 3); // unclear: no count
    let report = fx.report();
    let c = only(&report, CorrelationKind::SourceDisagreement);
    assert!(c.conflicts().iter().any(|x| x.description == "virustotal answered differently for 45.33.32.156 in different observations (flags, does_not_flag)."));
}

#[test]
fn providers_are_counted_once_even_with_duplicate_observations() {
    let mut fx = Fx::new(ip("45.33.32.156"));
    fx.abuse("45.33.32.156", Some(2), 1);
    fx.abuse("45.33.32.156", Some(2), 2); // repeated collector execution
    let single = fx.report();
    assert_eq!(
        single.of_kind(CorrelationKind::MultipleSources).count(),
        0,
        "one provider is not several"
    );
    assert_eq!(
        single.of_kind(CorrelationKind::SourceDisagreement).count(),
        0
    );
    fx.vt(ip("45.33.32.156"), 1, 3);
    let report = fx.report();
    let c = only(&report, CorrelationKind::MultipleSources);
    assert!(
        c.summary().starts_with(
            "2 providers report on 45.33.32.156: abuseipdb (flags), virustotal (flags)."
        ),
        "{}",
        c.summary()
    );
    assert_eq!(c.claims().len(), 3, "every observation is cited once");
}

// ------------------------------------------------------------------ C6

#[test]
fn shared_asn_network_and_certificate() {
    let mut fx = Fx::domain();
    fx.a(TARGET, "93.184.215.14", 1);
    fx.a(TARGET, "2606:2800:21f:cb07:6820:80da:af6b:8b2c", 1);
    fx.asn("93.184.215.14", &[15133], Some("93.184.215.0/24"), 2);
    fx.asn(
        "2606:2800:21f:cb07:6820:80da:af6b:8b2c",
        &[15133],
        Some("2606:2800::/32"),
        2,
    );
    fx.cert(7, &["example.com", "www.example.com", "api.example.com"], 3);
    let report = fx.report();
    assert_sound(&fx.inv, &report);
    let shared: Vec<&Correlation> = report
        .of_kind(CorrelationKind::SharedInfrastructure)
        .collect();
    let summaries: Vec<&str> = shared.iter().map(|c| c.summary()).collect();
    assert!(summaries.contains(&"2 addresses are announced by the same origin AS AS15133: 93.184.215.14, 2606:2800:21f:cb07:6820:80da:af6b:8b2c."), "{summaries:?}");
    assert!(
        summaries
            .iter()
            .any(|s| s.starts_with("Certificate crtsh:7 lists 3 names")),
        "{summaries:?}"
    );
    for c in shared {
        assert!(
            c.limitations()
                .iter()
                .any(|l| l == SHARING_IS_NOT_ATTRIBUTION)
        );
    }
}

// ------------------------------------------------------------ evidence

#[test]
fn a_correlation_without_valid_evidence_cannot_be_built() {
    let mut fx = Fx::domain();
    let dns = fx.a(TARGET, "93.184.215.14", 1);
    let index = EvidenceIndex::new(&fx.inv);
    assert_eq!(
        Draft::default().build(CorrelationKind::MultipleSources, &index),
        Err(CorrelationError::MissingEvidence)
    );
    let foreign = ObservationId::new_random();
    let draft = Draft {
        supporting: vec![foreign],
        ..Draft::default()
    };
    assert_eq!(
        draft.build(CorrelationKind::MultipleSources, &index),
        Err(CorrelationError::UnknownObservation(foreign))
    );
    let draft = Draft {
        supporting: vec![dns],
        conflicts: vec![Conflict {
            description: "x".into(),
            evidence: vec![],
        }],
        ..Draft::default()
    };
    assert_eq!(
        draft.build(CorrelationKind::SourceDisagreement, &index),
        Err(CorrelationError::MissingEvidence)
    );
    let draft = Draft {
        supporting: vec![dns],
        subjects: vec![Entity::Indicator(dom("never-seen.example"))],
        ..Draft::default()
    };
    assert_eq!(
        draft.build(CorrelationKind::MultipleSources, &index),
        Err(CorrelationError::UnknownEntity)
    );
    let ok = Draft {
        supporting: vec![dns, dns],
        ..Draft::default()
    };
    assert_eq!(
        ok.build(CorrelationKind::MultipleSources, &index)
            .unwrap()
            .evidence(),
        [dns]
    );
}

// ---------------------------------------------------- hostile input

#[test]
fn hostile_provider_text_never_reaches_output_unsanitized() {
    let mut fx = Fx::new(ip("45.33.32.156"));
    fx.urlhaus(
        ip("45.33.32.156"),
        "\u{1b}]0;pwned\u{7}\u{1b}[2J\r\nFORGED\u{202e}",
        1,
    );
    fx.vt(ip("45.33.32.156"), 0, 2);
    let report = fx.report();
    assert_sound(&fx.inv, &report);
    let json = serde_json::to_string(&report).unwrap();
    for c in &report.correlations {
        for claim in c.claims() {
            assert!(!claim.summary.chars().any(is_unsafe), "{:?}", claim.summary);
        }
        for conflict in c.conflicts() {
            assert!(!conflict.description.chars().any(is_unsafe));
        }
    }
    assert!(
        !json.contains("\\u001b"),
        "escapes are replaced before serialization"
    );
}

#[test]
fn duplicate_ids_cycles_and_duplicate_relationships_are_handled() {
    let mut fx = Fx::domain();
    let dns = fx.a(TARGET, "93.184.215.14", 1);
    fx.a(TARGET, "93.184.215.14", 2); // same edge again: merged
    fx.asn("93.184.215.14", &[15133], Some("93.184.215.0/24"), 2);
    let clone = fx.inv.observation(dns).unwrap().clone();
    fx.inv.add_observation(clone); // same ID twice
    let alias = fx.observe(
        dom(TARGET),
        "dns",
        3,
        ObservationData::DnsRecord(DnsRecord::new(
            TARGET,
            1,
            DnsRecordData::Cname {
                target: "a.example.com".into(),
            },
        )),
    );
    fx.relate(
        dom("a.example.com"),
        RelationKind::AliasOf,
        dom("b.example.com"),
        alias,
    );
    fx.relate(
        dom("b.example.com"),
        RelationKind::AliasOf,
        dom("a.example.com"),
        alias,
    );
    let report = fx.report();
    assert_sound(&fx.inv, &report);
    assert!(
        report
            .limitations
            .iter()
            .any(|l| l.contains("reused an ID"))
    );
    let c = only(&report, CorrelationKind::DomainIpInfrastructure);
    assert_eq!(
        c.links()
            .iter()
            .filter(|l| l.kind() == RelationKind::ResolvesTo)
            .count(),
        1
    );
    assert_eq!(
        c.links()[0].evidence().len(),
        2,
        "merged evidence, not duplicated links"
    );
}

#[test]
fn huge_inputs_are_bounded_and_fast() {
    let mut fx = Fx::domain();
    fx.a(TARGET, "93.184.215.14", 1);
    for i in 0..5_000u64 {
        let names = [TARGET.to_owned(), format!("h{}.example.com", i % 300)];
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        fx.cert(i + 1, &refs, 2);
    }
    for i in 0..2_000u32 {
        let address = format!("198.51.{}.{}", i / 250, i % 250 + 1);
        fx.a(TARGET, &address, 3);
        fx.asn(&address, &[64500], None, 4);
    }
    let started = Instant::now();
    let report = fx.report();
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "{:?}",
        started.elapsed()
    );
    assert_sound(&fx.inv, &report);
    let c = only(&report, CorrelationKind::DomainCertificate);
    assert_eq!(c.links().len(), MAX_LINKS);
    assert!(
        c.limitations()
            .iter()
            .any(|l| l.starts_with("100 of 5000 certificate links are listed"))
    );
    let cert_groups = report
        .of_kind(CorrelationKind::SharedInfrastructure)
        .filter(|c| c.summary().starts_with("Certificate "))
        .count();
    assert_eq!(cert_groups, MAX_CERTIFICATE_GROUPS);
    assert!(
        report
            .limitations
            .iter()
            .any(|l| l.starts_with("20 of 5000 certificates"))
    );
}

// --------------------------------------------------------- determinism

fn full_fixture() -> Fx {
    let mut fx = Fx::domain();
    fx.a(TARGET, "93.184.215.14", 1);
    fx.a(TARGET, "2606:2800:21f:cb07:6820:80da:af6b:8b2c", 1);
    fx.asn("93.184.215.14", &[15133], Some("93.184.215.0/24"), 2);
    fx.asn(
        "2606:2800:21f:cb07:6820:80da:af6b:8b2c",
        &[15133],
        Some("2606:2800::/32"),
        2,
    );
    fx.rdap(
        "93.184.215.14",
        &["93.184.215.0/24"],
        ("93.184.215.0", "93.184.215.255"),
        3,
    );
    fx.mx("mail.example.com", 1);
    fx.cert(1, &["example.com", "mail.example.com", "*.example.com"], 4);
    fx.abuse("93.184.215.14", Some(0), 5);
    fx.vt(dom(TARGET), 2, 6);
    fx.no_record("urlhaus", dom(TARGET), 7);
    fx
}

#[test]
fn identical_input_gives_byte_identical_output() {
    let fx = full_fixture();
    let first = serde_json::to_string(&fx.report()).unwrap();
    let second = serde_json::to_string(&fx.report()).unwrap();
    assert_eq!(first, second);
    let report = fx.report();
    assert_sound(&fx.inv, &report);
    for kind in [
        CorrelationKind::DomainIpInfrastructure,
        CorrelationKind::DomainCertificate,
        CorrelationKind::CtDnsNames,
        CorrelationKind::MultipleSources,
        CorrelationKind::SourceDisagreement,
        CorrelationKind::SharedInfrastructure,
    ] {
        assert!(
            report.of_kind(kind).count() > 0,
            "{kind:?} expected in the full fixture"
        );
    }
    let ids: Vec<String> = report
        .correlations
        .iter()
        .map(|c| c.id().to_string())
        .collect();
    assert!(
        ids.iter()
            .all(|id| id.len() == 37 && id.starts_with("corr-"))
    );
}

#[test]
fn insertion_order_does_not_change_the_result() {
    let fx = full_fixture();
    // Same observations and relationships, inserted in reverse order.
    let mut reversed = Investigation::new(dom(TARGET), t(0)).unwrap();
    for observation in fx.inv.observations().iter().rev() {
        reversed.add_observation(observation.clone());
    }
    for relationship in fx.inv.relationships().iter().rev() {
        reversed.add_relationship(relationship.clone()).unwrap();
    }
    let a = fx.report();
    let b = correlate(&reversed);
    assert_eq!(
        serde_json::to_string(&a.correlations).unwrap(),
        serde_json::to_string(&b.correlations).unwrap()
    );
    assert_eq!(
        serde_json::to_string(&a.findings).unwrap(),
        serde_json::to_string(&b.findings).unwrap()
    );
}

#[test]
fn json_shape_uses_references() {
    let fx = full_fixture();
    let report = fx.report();
    let json: serde_json::Value = serde_json::to_value(&report).unwrap();
    let first = &json["correlations"][0];
    for key in [
        "id",
        "kind",
        "finding_code",
        "summary",
        "subjects",
        "links",
        "claims",
        "supporting",
        "conflicts",
        "gaps",
        "observed",
        "evidence",
        "evidence_confidence",
        "limitations",
    ] {
        assert!(first.get(key).is_some(), "{key}");
    }
    assert!(
        first["evidence"][0].is_string(),
        "evidence is referenced by ID"
    );
    assert!(
        first.get("data").is_none() && first.get("observations").is_none(),
        "no copied observations"
    );
    for banned in ["score", "malicious_score", "risk", "verdict"] {
        assert!(first.get(banned).is_none());
    }
}

// ------------------------------------------------------ property tests

fn arbitrary_investigation() -> impl Strategy<Value = Investigation> {
    let ips = prop::collection::vec(0u8..6, 0..8);
    let ops = prop::collection::vec((0u8..8, 0u8..6, 0u32..40, 0u64..4), 0..40);
    (ips, ops).prop_map(|(resolved, ops)| {
        let mut fx = Fx::domain();
        let address = |n: u8| format!("198.51.100.{}", n + 1);
        for n in resolved {
            fx.a(TARGET, &address(n), 1);
        }
        for (op, n, at, v) in ops {
            let a = address(n);
            match op {
                0 => {
                    fx.asn(&a, &[64496 + u32::from(n % 2)], Some("198.51.100.0/24"), at);
                }
                1 => {
                    fx.rdap(
                        &a,
                        &["198.51.100.0/24"],
                        ("198.51.100.0", "198.51.100.255"),
                        at,
                    );
                }
                2 => {
                    fx.abuse(&a, Some(v), at);
                }
                3 => {
                    fx.vt(ip(&a), v, at);
                }
                4 => {
                    fx.no_record("urlhaus", ip(&a), at);
                }
                5 => {
                    fx.cert(v + 1, &[TARGET, "www.example.com"], at);
                }
                6 => {
                    fx.mx("www.example.com", at);
                }
                _ => {
                    fx.urlhaus(ip(&a), "listed", at);
                }
            }
        }
        fx.inv
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn correlation_is_sound_serializable_and_deterministic(inv in arbitrary_investigation()) {
        let first = correlate(&inv);
        let second = correlate(&inv);
        assert_sound(&inv, &first);
        let a = serde_json::to_string(&first).unwrap();
        let b = serde_json::to_string(&second).unwrap();
        prop_assert_eq!(a, b);
        prop_assert!(first.limitations.iter().all(|l| !l.contains("rejected")), "{:?}", first.limitations);
    }
}

#[test]
fn malwarebazaar_listings_are_consumed_by_the_existing_provider_rules() {
    const SHA: &str = "e167b20f1acf48f7ce0ae33a218e2c1b300b41c012ededf03e7a3522a4ebe95e";
    let target = Indicator::parse_file_hash(SHA).unwrap();
    let mut fx = Fx::new(target.clone());
    let mb = fx.observe(
        target.clone(),
        "malwarebazaar",
        1,
        ObservationData::ProviderListing(ProviderListing {
            provider: "malwarebazaar".into(),
            entry_id: None,
            attributes: vec![ProviderAttribute {
                name: "signature".into(),
                value: "Adwind".into(),
            }],
            metrics: vec![],
            dates: vec![],
            tags: vec![],
            issues: vec![],
        }),
    );
    let vt = fx.vt(target, 0, 2);
    let report = fx.report();
    assert_sound(&fx.inv, &report);
    let c = only(&report, CorrelationKind::SourceDisagreement);
    let mut both = vec![mb, vt];
    both.sort_unstable();
    assert_eq!(c.conflicts()[0].evidence, both);
    assert!(
        c.claims()
            .iter()
            .any(|x| x.provider.as_str() == "malwarebazaar"
                && x.summary == "listed, signature=Adwind")
    );
    assert_eq!(report.of_kind(CorrelationKind::MultipleSources).count(), 1);
}
