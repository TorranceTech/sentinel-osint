//! Shared fixtures: investigations shaped like real DNS collector output.

#![allow(dead_code, unreachable_pub, clippy::unwrap_used)]

use chrono::{TimeZone, Utc};
use sentinel_core::{
    Confidence, DnsNoRecords, DnsRecord, DnsRecordData, DnsRecordType, Finding, FindingCode,
    Indicator, Investigation, NoRecordsReason, Observation, ObservationData, ObservationId,
    Provenance, RelationKind, Relationship, Severity, Sha256Digest, SourceId, SourceOutcome,
    SourceStatus, Timestamp,
};

pub const DNS: SourceId = SourceId::from_static("dns");

pub fn at(millis: i64) -> Timestamp {
    Utc.with_ymd_and_hms(2026, 9, 23, 17, 40, 12).unwrap() + chrono::TimeDelta::milliseconds(millis)
}

pub struct Builder {
    pub inv: Investigation,
    pub target: Indicator,
}

impl Builder {
    pub fn new(domain: &str) -> Self {
        let target = Indicator::parse_domain(domain).unwrap();
        Self {
            inv: Investigation::new(target.clone(), at(0)).unwrap(),
            target,
        }
    }

    pub fn record(&mut self, name: &str, data: DnsRecordData) -> ObservationId {
        let record_type = data.record_type();
        let record = DnsRecord::new(name, 300, data);
        self.inv.add_observation(
            Observation::new(
                self.target.clone(),
                DNS,
                at(150),
                ObservationData::DnsRecord(record),
                Confidence::saturating(90),
                Provenance::dns(name, record_type, "system"),
            )
            .with_raw_response_hash(Sha256Digest::of(name.as_bytes())),
        )
    }

    pub fn none(
        &mut self,
        name: &str,
        record_type: DnsRecordType,
        reason: NoRecordsReason,
    ) -> ObservationId {
        self.inv.add_observation(Observation::new(
            self.target.clone(),
            DNS,
            at(150),
            ObservationData::DnsNoRecords(DnsNoRecords::new(name, record_type, reason)),
            Confidence::saturating(90),
            Provenance::dns(name, record_type, "system"),
        ))
    }

    pub fn finding(
        &mut self,
        code: &'static str,
        severity: Severity,
        title: &str,
        detail: &str,
        evidence: ObservationId,
    ) {
        self.inv
            .add_finding(
                Finding::new(
                    FindingCode::from_static(code),
                    severity,
                    title,
                    detail,
                    Confidence::saturating(90),
                )
                .with_evidence([evidence]),
            )
            .unwrap();
    }

    pub fn status(&mut self, outcome: SourceOutcome) {
        self.inv.record_source(SourceStatus::new(
            DNS,
            self.target.clone(),
            outcome,
            at(0),
            at(180),
        ));
    }

    pub fn finish(mut self) -> Investigation {
        self.inv.finish(at(215)).unwrap();
        self.inv
    }
}

/// example.com as the DNS collector reports it.
pub fn example_com() -> Investigation {
    let mut b = Builder::new("example.com");
    let a = b.record(
        "example.com",
        DnsRecordData::A {
            address: "93.184.215.14".parse().unwrap(),
        },
    );
    b.record(
        "example.com",
        DnsRecordData::Aaaa {
            address: "2606:2800:21f:cb07:6820:80da:af6b:8b2c".parse().unwrap(),
        },
    );
    b.none("example.com", DnsRecordType::Cname, NoRecordsReason::NoData);
    b.record(
        "example.com",
        DnsRecordData::Mx {
            preference: 10,
            exchange: "mail.example.com".into(),
        },
    );
    b.record(
        "example.com",
        DnsRecordData::Ns {
            nameserver: "a.iana-servers.net".into(),
        },
    );
    b.record(
        "example.com",
        DnsRecordData::Ns {
            nameserver: "b.iana-servers.net".into(),
        },
    );
    b.record(
        "example.com",
        DnsRecordData::Soa {
            mname: "ns.icann.org".into(),
            rname: "noc.dns.icann.org".into(),
            serial: 2_026_092_301,
            refresh: 7200,
            retry: 3600,
            expire: 1_209_600,
            minimum: 3600,
        },
    );
    let spf = b.record(
        "example.com",
        DnsRecordData::Txt {
            text: "v=spf1 -all".into(),
        },
    );
    b.record(
        "example.com",
        DnsRecordData::Txt {
            text: "google-site-verification=abc123".into(),
        },
    );
    let caa = b.none("example.com", DnsRecordType::Caa, NoRecordsReason::NoData);
    let dmarc = b.record(
        "_dmarc.example.com",
        DnsRecordData::Txt {
            text: "v=DMARC1; p=reject; rua=mailto:dmarc@example.com".into(),
        },
    );

    let ip = Indicator::parse_ip("93.184.215.14").unwrap();
    b.inv
        .add_relationship(
            Relationship::new(b.target.clone(), RelationKind::ResolvesTo, ip, [a]).unwrap(),
        )
        .unwrap();

    b.finding(
        "dns.spf.hardfail",
        Severity::Info,
        "SPF policy: -all (fail)",
        "Mail from hosts not listed in the SPF record fails SPF.",
        spf,
    );
    b.finding(
        "dns.dmarc.policy_reject",
        Severity::Info,
        "DMARC policy: reject",
        "Receivers are asked to reject messages that fail DMARC.",
        dmarc,
    );
    b.finding(
        "dns.dmarc.aggregate_reporting",
        Severity::Info,
        "DMARC aggregate reports requested",
        "rua: mailto:dmarc@example.com",
        dmarc,
    );
    b.finding(
        "dns.caa.missing",
        Severity::Info,
        "No CAA records",
        "No CAA records at example.com. Parent domains were not checked; if none of them publish CAA either, any certificate authority may issue certificates for this name.",
        caa,
    );
    b.status(SourceOutcome::Succeeded { observations: 11 });
    b.finish()
}

/// Adds an infrastructure observation about `ip` (ASN/RDAP), like the
/// Cymru and RDAP collectors do.
pub fn infra(
    inv: &mut Investigation,
    ip: &str,
    source: &'static str,
    data: ObservationData,
) -> ObservationId {
    let indicator = Indicator::parse_ip(ip).unwrap();
    let provenance = if source == "rdap" {
        Provenance::https(
            sentinel_core::HttpMethod::Get,
            &url::Url::parse(&format!("https://rdap.example.net/ip/{ip}")).unwrap(),
            200,
        )
    } else {
        Provenance::dns("origin.asn.cymru.com", DnsRecordType::Txt, "system")
    };
    inv.add_observation(
        Observation::new(
            indicator,
            SourceId::from_static(source),
            at(160),
            data,
            Confidence::saturating(90),
            provenance,
        )
        .with_raw_response_hash(Sha256Digest::of(ip.as_bytes())),
    )
}

/// 8.8.8.8 with ASN and RDAP data, as the collectors report it.
pub fn ip_8_8_8_8() -> Investigation {
    use sentinel_core::{Asn, AsnDescription, AsnOrigin, IpPrefix, IpVersion, NetworkRegistration};
    let target = Indicator::parse_ip("8.8.8.8").unwrap();
    let mut inv = Investigation::new(target.clone(), at(0)).unwrap();
    let asn = Asn::new(15169).unwrap();
    let origin = infra(
        &mut inv,
        "8.8.8.8",
        "cymru",
        ObservationData::AsnOrigin(AsnOrigin {
            ip: "8.8.8.8".parse().unwrap(),
            asns: vec![asn],
            prefix: Some(IpPrefix::parse("8.8.8.0/24").unwrap()),
            country: Some("US".into()),
            registry: Some("arin".into()),
            allocated: chrono::NaiveDate::from_ymd_opt(2023, 12, 28),
            source_text: "15169 | 8.8.8.0/24 | US | arin | 2023-12-28".into(),
            issues: vec![],
        }),
    );
    infra(
        &mut inv,
        "8.8.8.8",
        "cymru",
        ObservationData::AsnDescription(AsnDescription {
            asn,
            name: Some("GOOGLE, US".into()),
            country: Some("US".into()),
            registry: Some("arin".into()),
            allocated: chrono::NaiveDate::from_ymd_opt(2000, 3, 30),
            source_text: "15169 | US | arin | 2000-03-30 | GOOGLE, US".into(),
            issues: vec![],
        }),
    );
    let network = infra(
        &mut inv,
        "8.8.8.8",
        "rdap",
        ObservationData::NetworkRegistration(NetworkRegistration {
            queried_ip: "8.8.8.8".parse().unwrap(),
            handle: Some("NET-8-8-8-0-2".into()),
            name: Some("GOGL".into()),
            network_type: Some("DIRECT ALLOCATION".into()),
            ip_version: Some(IpVersion::V4),
            start_address: Some("8.8.8.0".parse().unwrap()),
            end_address: Some("8.8.8.255".parse().unwrap()),
            cidrs: vec![IpPrefix::parse("8.8.8.0/24").unwrap()],
            parent_handle: Some("NET-8-0-0-0-0".into()),
            country: Some("US".into()),
            status: vec!["active".into()],
            registered_at: Some(at(0) - chrono::TimeDelta::days(4576)),
            last_changed_at: Some(at(0) - chrono::TimeDelta::days(4576)),
            organization: Some("Google LLC".into()),
            abuse_email: Some("network-abuse@google.com".into()),
            issues: vec![],
        }),
    );
    inv.add_relationship(
        Relationship::new(target.clone(), RelationKind::AnnouncedBy, asn, [origin]).unwrap(),
    )
    .unwrap();
    inv.add_relationship(
        Relationship::new(
            target.clone(),
            RelationKind::RegisteredIn,
            IpPrefix::parse("8.8.8.0/24").unwrap(),
            [network],
        )
        .unwrap(),
    )
    .unwrap();
    inv.add_finding(
        Finding::new(
            FindingCode::from_static("asn.origin"),
            Severity::Info,
            "BGP origin reported",
            "8.8.8.8 is announced by AS15169 (GOOGLE, US) in prefix 8.8.8.0/24, according to the source. A BGP origin identifies the network announcing the route; it does not establish ownership, control or intent.",
            Confidence::saturating(85),
        )
        .with_evidence([origin]),
    )
    .unwrap();
    for source in ["cymru", "rdap"] {
        inv.record_source(SourceStatus::new(
            SourceId::from_static(source),
            target.clone(),
            SourceOutcome::Succeeded {
                observations: if source == "cymru" { 2 } else { 1 },
            },
            at(0),
            at(120),
        ));
    }
    inv.finish(at(215)).unwrap();
    inv
}

/// Adds a CT certificate observation for `example.com`, like the CT collector.
pub fn ct_certificate(
    inv: &mut Investigation,
    id: u64,
    names: &[&str],
    not_before: i64,
    not_after: i64,
    issuer: &str,
) -> ObservationId {
    use sentinel_core::{CtCertificate, DomainName, classify_certificate_name};
    let target = DomainName::parse("example.com").unwrap();
    let day = |d: i64| at(0) + chrono::TimeDelta::days(d);
    let certificate = CtCertificate {
        source_entry_id: Some(id),
        serial_number: Some(format!("{id:x}")),
        issuer: Some(issuer.into()),
        common_name: Some(names[0].into()),
        not_before: Some(day(not_before)),
        not_after: Some(day(not_after)),
        names: names
            .iter()
            .map(|n| classify_certificate_name(n, &target))
            .collect(),
        omitted_email_names: 0,
        source_entries: 2,
        issues: vec![],
    };
    inv.add_observation(
        Observation::new(
            Indicator::parse_domain("example.com").unwrap(),
            SourceId::from_static("ct"),
            at(170),
            ObservationData::CtCertificate(certificate),
            Confidence::saturating(80),
            Provenance::https(
                sentinel_core::HttpMethod::Get,
                &url::Url::parse("https://crt.sh/?q=example.com&output=json&deduplicate=Y")
                    .unwrap(),
                200,
            ),
        )
        .with_raw_response_hash(Sha256Digest::of(b"ct")),
    )
}

/// example.com with DNS facts plus CT certificates.
pub fn example_com_with_ct() -> Investigation {
    use sentinel_core::CertificateId;
    let mut b = Builder::new("example.com");
    b.record(
        "example.com",
        DnsRecordData::A {
            address: "93.184.215.14".parse().unwrap(),
        },
    );
    let current = ct_certificate(
        &mut b.inv,
        1002,
        &["example.com", "*.example.com"],
        -60,
        30,
        "CN=Example Issuing CA",
    );
    let old = ct_certificate(
        &mut b.inv,
        900,
        &[
            "www.example.com",
            "api.example.com",
            "m.testexample.com",
            "bad name",
        ],
        -1000,
        -600,
        "CN=Other CA",
    );
    let certificate = CertificateId::new("crtsh", "900").unwrap();
    b.inv
        .add_relationship(
            Relationship::new(
                certificate,
                RelationKind::CoversName,
                Indicator::parse_domain("www.example.com").unwrap(),
                [old],
            )
            .unwrap(),
        )
        .unwrap();
    b.finding(
        "ct.certificates_observed",
        Severity::Info,
        "Certificates observed in CT logs",
        "2 certificate(s) (4 log entries) naming example.com or its subdomains were reported.",
        current,
    );
    b.inv.record_source(SourceStatus::new(
        SourceId::from_static("ct"),
        b.target.clone(),
        SourceOutcome::Succeeded { observations: 2 },
        at(0),
        at(170),
    ));
    b.status(SourceOutcome::Succeeded { observations: 1 });
    b.finish()
}

/// An IP investigation with an AbuseIPDB reputation observation. `isp` lets
/// tests inject hostile text.
pub fn ip_with_reputation(isp: &str) -> Investigation {
    use sentinel_core::{IpReputation, ProviderMetric};
    let target = Indicator::parse_ip("45.33.32.156").unwrap();
    let mut inv = Investigation::new(target.clone(), at(0)).unwrap();
    let metric = |name: &str, value, max| ProviderMetric {
        name: name.into(),
        value,
        max,
    };
    let id = infra(
        &mut inv,
        "45.33.32.156",
        "abuseipdb",
        ObservationData::IpReputation(IpReputation {
            provider: "abuseipdb".into(),
            queried_ip: "45.33.32.156".parse().unwrap(),
            window_days: Some(90),
            metrics: vec![
                metric("abuse_confidence_score", 95, Some(100)),
                metric("total_reports", 41, None),
                metric("num_distinct_users", 12, None),
            ],
            last_reported_at: Some(at(0) - chrono::TimeDelta::days(3)),
            is_allowlisted: Some(false),
            is_tor: Some(false),
            usage_type: Some("Data Center/Web Hosting/Transit".into()),
            isp: Some(isp.into()),
            domain: Some("example.net".into()),
            country_code: Some("US".into()),
            hostnames: vec![],
            context_source: Some("IPinfo (as reported by AbuseIPDB)".into()),
            issues: vec![],
        }),
    );
    inv.add_finding(
        Finding::new(
            FindingCode::from_static("ti.abuseipdb.high_abuse_confidence"),
            Severity::Info,
            "AbuseIPDB reports a high abuse confidence score",
            "AbuseIPDB reports an abuse confidence score of 95/100 for 45.33.32.156.",
            Confidence::saturating(90),
        )
        .with_evidence([id]),
    )
    .unwrap();
    inv.record_source(SourceStatus::new(
        SourceId::from_static("abuseipdb"),
        target,
        SourceOutcome::Succeeded { observations: 1 },
        at(0),
        at(90),
    ));
    inv.finish(at(215)).unwrap();
    inv
}

/// A target with a VirusTotal observation: a report (`found`) or the
/// provider's "no record" answer. `tag` lets tests inject hostile text.
pub fn with_virustotal(target: Indicator, found: bool, tag: &str) -> Investigation {
    use sentinel_core::{ProviderMetric, ProviderNoRecord, ProviderReputation};
    let mut inv = Investigation::new(target.clone(), at(0)).unwrap();
    let metric = |name: &str, value| ProviderMetric {
        name: name.into(),
        value,
        max: None,
    };
    let data = if found {
        ObservationData::ProviderReputation(ProviderReputation {
            provider: "virustotal".into(),
            metrics: vec![
                metric("last_analysis_stats.malicious", 4),
                metric("last_analysis_stats.suspicious", 2),
                metric("last_analysis_stats.undetected", 30),
                metric("last_analysis_stats.harmless", 55),
                metric("last_analysis_stats.timeout", 0),
                metric("total_votes.harmless", 2),
                metric("total_votes.malicious", 5),
            ],
            community_score: Some(-7),
            last_analysis_at: Some(at(0) - chrono::TimeDelta::days(2)),
            tags: vec!["cdn".into(), tag.into()],
            issues: vec![],
        })
    } else {
        ObservationData::ProviderNoRecord(ProviderNoRecord {
            provider: "virustotal".into(),
        })
    };
    let id = inv.add_observation(
        Observation::new(
            target.clone(),
            SourceId::from_static("virustotal"),
            at(160),
            data,
            Confidence::saturating(90),
            Provenance::https(
                sentinel_core::HttpMethod::Get,
                &url::Url::parse("https://www.virustotal.com/api/v3/domains/example.com").unwrap(),
                if found { 200 } else { 404 },
            ),
        )
        .with_raw_response_hash(Sha256Digest::of(b"vt")),
    );
    let (code, title, detail) = if found {
        (
            "ti.virustotal.detections",
            "VirusTotal reports detections for this indicator",
            "In VirusTotal's last analysis, 4 engine(s) of 91 categorized the indicator as malicious and 2 as suspicious.",
        )
    } else {
        (
            "ti.virustotal.not_found",
            "VirusTotal has no record of this indicator",
            "VirusTotal has no record of the indicator. Absence from VirusTotal's dataset is not evidence that the indicator is benign.",
        )
    };
    inv.add_finding(
        Finding::new(
            FindingCode::from_static(code),
            Severity::Info,
            title,
            detail,
            Confidence::saturating(90),
        )
        .with_evidence([id]),
    )
    .unwrap();
    inv.record_source(SourceStatus::new(
        SourceId::from_static("virustotal"),
        target,
        SourceOutcome::Succeeded { observations: 1 },
        at(0),
        at(90),
    ));
    inv.finish(at(215)).unwrap();
    inv
}

/// A domain target with a URLhaus host listing. `value` lets tests inject
/// hostile text into a tag and an attribute.
pub fn with_urlhaus(value: &str) -> Investigation {
    use sentinel_core::{ProviderAttribute, ProviderDate, ProviderListing, ProviderMetric};
    let target = Indicator::parse_domain("vektorex.com").unwrap();
    let mut inv = Investigation::new(target.clone(), at(0)).unwrap();
    let attribute = |name: &str, value: &str| ProviderAttribute {
        name: name.into(),
        value: value.into(),
    };
    let metric = |name: &str, value| ProviderMetric {
        name: name.into(),
        value,
        max: None,
    };
    let id = inv.add_observation(
        Observation::new(
            target.clone(),
            SourceId::from_static("urlhaus"),
            at(160),
            ObservationData::ProviderListing(ProviderListing {
                provider: "urlhaus".into(),
                entry_id: None,
                attributes: vec![
                    attribute("blacklists.spamhaus_dbl", "abused_legit_malware"),
                    attribute("blacklists.surbl", value),
                ],
                metrics: vec![
                    metric("url_count", 120),
                    metric("returned_urls", 2),
                    metric("returned_urls.online", 2),
                ],
                dates: vec![ProviderDate {
                    name: "firstseen".into(),
                    at: at(0) - chrono::TimeDelta::days(30),
                }],
                tags: vec!["AZORult".into(), value.into()],
                issues: vec![],
            }),
            Confidence::saturating(90),
            Provenance::https(
                sentinel_core::HttpMethod::Post,
                &url::Url::parse("https://urlhaus-api.abuse.ch/v1/host/").unwrap(),
                200,
            ),
        )
        .with_raw_response_hash(Sha256Digest::of(b"urlhaus")),
    );
    inv.add_finding(
        Finding::new(
            FindingCode::from_static("ti.urlhaus.host_listed"),
            Severity::Info,
            "URLhaus lists malware URLs on this host",
            "URLhaus reports 120 malware URL(s) observed on vektorex.com.",
            Confidence::saturating(90),
        )
        .with_evidence([id]),
    )
    .unwrap();
    inv.record_source(SourceStatus::new(
        SourceId::from_static("urlhaus"),
        target,
        SourceOutcome::Succeeded { observations: 1 },
        at(0),
        at(90),
    ));
    inv.finish(at(215)).unwrap();
    inv
}

/// example.com with DNS → Cymru → RDAP, and provider claims that disagree
/// about the domain. `value` injects hostile text into a provider listing
/// about the address.
// A single, readable fixture of one whole investigation.
#[allow(clippy::too_many_lines)]
pub fn correlated(value: &str) -> Investigation {
    use sentinel_core::{
        Asn, AsnOrigin, IpPrefix, NetworkRegistration, ProviderAttribute, ProviderListing,
        ProviderMetric, ProviderNoRecord, ProviderReputation, RelationKind, Relationship,
    };
    let mut b = Builder::new("example.com");
    let ip = Indicator::parse_ip("93.184.215.14").unwrap();
    let a = b.record(
        "example.com",
        DnsRecordData::A {
            address: "93.184.215.14".parse().unwrap(),
        },
    );
    b.inv
        .add_relationship(
            Relationship::new(b.target.clone(), RelationKind::ResolvesTo, ip.clone(), [a]).unwrap(),
        )
        .unwrap();
    let asn = Asn::new(15133).unwrap();
    let prefix = IpPrefix::parse("93.184.215.0/24").unwrap();
    let origin = infra(
        &mut b.inv,
        "93.184.215.14",
        "cymru",
        ObservationData::AsnOrigin(AsnOrigin {
            ip: "93.184.215.14".parse().unwrap(),
            asns: vec![asn],
            prefix: Some(prefix),
            country: None,
            registry: None,
            allocated: None,
            source_text: "15133 | 93.184.215.0/24".into(),
            issues: vec![],
        }),
    );
    b.inv
        .add_relationship(
            Relationship::new(ip.clone(), RelationKind::AnnouncedBy, asn, [origin]).unwrap(),
        )
        .unwrap();
    let rdap = infra(
        &mut b.inv,
        "93.184.215.14",
        "rdap",
        ObservationData::NetworkRegistration(NetworkRegistration {
            queried_ip: "93.184.215.14".parse().unwrap(),
            handle: None,
            name: None,
            network_type: None,
            ip_version: None,
            start_address: Some("93.184.215.0".parse().unwrap()),
            end_address: Some("93.184.215.255".parse().unwrap()),
            cidrs: vec![prefix],
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
    b.inv
        .add_relationship(
            Relationship::new(ip.clone(), RelationKind::RegisteredIn, prefix, [rdap]).unwrap(),
        )
        .unwrap();
    let https = |path: &str| {
        Provenance::https(
            sentinel_core::HttpMethod::Get,
            &url::Url::parse(&format!("https://provider.example.net/{path}")).unwrap(),
            200,
        )
    };
    let stat = |n: &str, v| ProviderMetric {
        name: format!("last_analysis_stats.{n}"),
        value: v,
        max: None,
    };
    b.inv.add_observation(
        Observation::new(
            b.target.clone(),
            SourceId::from_static("virustotal"),
            at(170),
            ObservationData::ProviderReputation(ProviderReputation {
                provider: "virustotal".into(),
                metrics: vec![
                    stat("malicious", 3),
                    stat("suspicious", 0),
                    stat("undetected", 20),
                    stat("harmless", 60),
                    stat("timeout", 0),
                ],
                community_score: Some(0),
                last_analysis_at: None,
                tags: vec![],
                issues: vec![],
            }),
            Confidence::saturating(90),
            https("vt"),
        )
        .with_raw_response_hash(Sha256Digest::of(b"vt")),
    );
    b.inv.add_observation(
        Observation::new(
            b.target.clone(),
            SourceId::from_static("urlhaus"),
            at(190),
            ObservationData::ProviderNoRecord(ProviderNoRecord {
                provider: "urlhaus".into(),
            }),
            Confidence::saturating(90),
            https("urlhaus"),
        )
        .with_raw_response_hash(Sha256Digest::of(b"urlhaus")),
    );
    b.inv.add_observation(Observation::new(
        ip,
        SourceId::from_static("urlhaus"),
        at(190),
        ObservationData::ProviderListing(ProviderListing {
            provider: "urlhaus".into(),
            entry_id: None,
            attributes: vec![ProviderAttribute {
                name: "blacklists.surbl".into(),
                value: value.into(),
            }],
            metrics: vec![],
            dates: vec![],
            tags: vec![],
            issues: vec![],
        }),
        Confidence::saturating(60),
        https("urlhaus-ip"),
    ));
    b.inv.add_observation(
        Observation::new(
            Indicator::parse_ip("93.184.215.14").unwrap(),
            SourceId::from_static("abuseipdb"),
            at(180),
            ObservationData::IpReputation(sentinel_core::IpReputation {
                provider: "abuseipdb".into(),
                queried_ip: "93.184.215.14".parse().unwrap(),
                window_days: Some(90),
                metrics: vec![ProviderMetric {
                    name: "total_reports".into(),
                    value: 0,
                    max: None,
                }],
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
            Confidence::saturating(90),
            https("abuseipdb"),
        )
        .with_raw_response_hash(Sha256Digest::of(b"abuseipdb")),
    );
    b.status(SourceOutcome::Succeeded { observations: 1 });
    b.finish()
}

/// A SHA-256 target with a MalwareBazaar listing (or its `hash_not_found`
/// answer). `value` is injected into the tags and the signature.
pub fn with_malwarebazaar(value: &str, found: bool) -> Investigation {
    use sentinel_core::{
        ProviderAttribute, ProviderDate, ProviderListing, ProviderMetric, ProviderNoRecord,
    };
    let target = Indicator::parse_file_hash(
        "e167b20f1acf48f7ce0ae33a218e2c1b300b41c012ededf03e7a3522a4ebe95e",
    )
    .unwrap();
    let mut inv = Investigation::new(target.clone(), at(0)).unwrap();
    let attribute = |name: &str, value: &str| ProviderAttribute {
        name: name.into(),
        value: value.into(),
    };
    let data = if found {
        ObservationData::ProviderListing(ProviderListing {
            provider: "malwarebazaar".into(),
            entry_id: None,
            attributes: vec![
                attribute("signature", value),
                attribute("file_type", "exe"),
                attribute("file_type_mime", "application/x-dosexec"),
            ],
            metrics: vec![ProviderMetric {
                name: "file_size".into(),
                value: 145_408,
                max: None,
            }],
            dates: vec![ProviderDate {
                name: "first_seen".into(),
                at: at(0) - chrono::TimeDelta::days(900),
            }],
            tags: vec!["revengerat".into(), value.into()],
            issues: vec![],
        })
    } else {
        ObservationData::ProviderNoRecord(ProviderNoRecord {
            provider: "malwarebazaar".into(),
        })
    };
    let id = inv.add_observation(
        Observation::new(
            target.clone(),
            SourceId::from_static("malwarebazaar"),
            at(160),
            data,
            Confidence::saturating(90),
            Provenance::https(
                sentinel_core::HttpMethod::Post,
                &url::Url::parse("https://mb-api.abuse.ch/api/v1/").unwrap(),
                200,
            ),
        )
        .with_raw_response_hash(Sha256Digest::of(b"malwarebazaar")),
    );
    let (code, title, detail) = if found {
        (
            "ti.malwarebazaar.sample_listed",
            "MalwareBazaar lists this hash as a malware sample",
            "MalwareBazaar reports the hash as a sample in its malware database (file_type: exe). The classification is MalwareBazaar's, not a Sentinel verdict; Sentinel did not download or execute the sample.",
        )
    } else {
        (
            "ti.malwarebazaar.not_found",
            "MalwareBazaar has no sample for this hash",
            "MalwareBazaar answered hash_not_found for the hash. MalwareBazaar only holds samples submitted to it; absence is not evidence that the file is benign.",
        )
    };
    inv.add_finding(
        Finding::new(
            FindingCode::from_static(code),
            Severity::Info,
            title,
            detail,
            Confidence::saturating(90),
        )
        .with_evidence([id]),
    )
    .unwrap();
    inv.record_source(SourceStatus::new(
        SourceId::from_static("malwarebazaar"),
        target,
        SourceOutcome::Succeeded { observations: 1 },
        at(0),
        at(90),
    ));
    inv.finish(at(215)).unwrap();
    inv
}
