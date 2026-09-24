//! Table output tests.
//!
//! `golden/example_com.txt` pins the layout. After an intentional layout
//! change, regenerate it with `UPDATE_GOLDEN=1 cargo test -p sentinel-report`
//! and review the diff.

#![allow(clippy::unwrap_used)]

mod common;

use common::{Builder, example_com};
use sentinel_core::text::is_unsafe;
use sentinel_core::{
    DnsRecordData, DnsRecordType, NoRecordsReason, Severity, SourceOutcome, SourceStatus, TimeLimit,
};
use sentinel_report::table;

/// Replaces the random investigation ID so output can be compared.
fn stable(output: &str, id: &str) -> String {
    output.replace(id, "00000000-0000-0000-0000-000000000000")
}

#[test]
fn matches_the_golden_layout() {
    let investigation = example_com();
    let output = stable(
        &table::render(&investigation),
        &investigation.id().to_string(),
    );
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden/example_com.txt");
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::write(path, &output).unwrap();
    }
    let golden = std::fs::read_to_string(path).unwrap();
    assert_eq!(output, golden, "table layout changed; see the module docs");
}

#[test]
fn output_is_plain_text() {
    let output = table::render(&example_com());
    assert!(!output.contains('\u{1b}'), "no ANSI escape sequences");
    assert!(output.lines().all(|line| !line.chars().any(is_unsafe)));
}

#[test]
fn hostile_dns_content_cannot_reach_the_terminal() {
    let mut b = Builder::new("example.com");
    let hostile =
        "\u{1b}]0;owned\u{7}\u{1b}[2J\u{1b}[31mv=spf1 +all\r\nFORGED LINE\u{202e}txt.exe\u{0}";
    let id = b.record(
        "example.com",
        DnsRecordData::Txt {
            text: hostile.into(),
        },
    );
    b.record(
        "example.com",
        DnsRecordData::Mx {
            preference: 10,
            exchange: "mail\u{1b}[8m.example.com".into(),
        },
    );
    b.record(
        "example.com",
        DnsRecordData::Caa {
            critical: true,
            tag: "iss\u{9b}ue".into(),
            value: "ca\u{202e}.example".into(),
        },
    );
    b.finding(
        "dns.spf.malformed",
        Severity::Low,
        "SPF record is malformed",
        hostile,
        id,
    );
    b.status(SourceOutcome::Partial {
        observations: 3,
        errors: vec![format!("TXT lookup failed: {hostile}")],
    });
    let output = table::render(&b.finish());

    for line in output.lines() {
        assert!(
            !line.chars().any(is_unsafe),
            "unsafe character in line: {line:?}"
        );
        assert!(
            !line.trim_start().starts_with("FORGED LINE"),
            "line injection: {line:?}"
        );
    }
}

#[test]
fn oversized_values_are_truncated_for_display() {
    let mut b = Builder::new("example.com");
    b.record(
        "example.com",
        DnsRecordData::Txt {
            text: "x".repeat(10_000),
        },
    );
    b.status(SourceOutcome::Succeeded { observations: 1 });
    let output = table::render(&b.finish());
    assert!(output.lines().all(|line| line.chars().count() < 300));
    assert!(output.contains('…'));
}

#[test]
fn distinguishes_not_found_unknown_and_nxdomain() {
    let mut b = Builder::new("example.com");
    b.none("example.com", DnsRecordType::Txt, NoRecordsReason::NoData);
    b.none("example.com", DnsRecordType::A, NoRecordsReason::NxDomain);
    // No CAA and no DMARC observations at all: those lookups failed.
    b.status(SourceOutcome::Partial {
        observations: 2,
        errors: vec!["CAA lookup for example.com failed: DNS query failed".into()],
    });
    let output = table::render(&b.finish());

    assert!(output.contains("A\n  (NXDOMAIN)\n"));
    assert!(output.contains("TXT\n  (none)\n"));
    assert!(output.contains("CAA\n  (not collected)\n"));
    assert!(output.contains("SPF\n  Status:  Not found\n"));
    assert!(output.contains("DMARC\n  Status:  Unknown (lookup failed or not performed)\n"));
    assert!(output.contains("dns  partial"));
    assert!(output.contains("! CAA lookup for example.com failed: DNS query failed"));
}

#[test]
fn findings_are_ordered_by_severity() {
    let mut b = Builder::new("example.com");
    let id = b.record(
        "example.com",
        DnsRecordData::Txt {
            text: "v=spf1 +all".into(),
        },
    );
    b.finding("dns.spf.includes", Severity::Info, "info", "detail", id);
    b.finding(
        "dns.spf.permissive_all",
        Severity::Medium,
        "medium",
        "detail",
        id,
    );
    b.finding("dns.spf.ptr_mechanism", Severity::Low, "low", "detail", id);
    let output = table::render(&b.finish());
    let medium = output.find("dns.spf.permissive_all").unwrap();
    let low = output.find("dns.spf.ptr_mechanism").unwrap();
    let info = output.find("dns.spf.includes").unwrap();
    assert!(medium < low && low < info);
}

#[test]
fn reports_every_source_outcome() {
    let mut b = Builder::new("example.com");
    let target = b.target.clone();
    let pivot = sentinel_core::Indicator::parse_ip("93.184.215.14").unwrap();
    let t = common::at;
    b.inv.record_source(SourceStatus::new(
        sentinel_core::SourceId::from_static("virustotal"),
        target.clone(),
        SourceOutcome::Unavailable {
            reason: "no API key configured".into(),
        },
        t(0),
        t(0),
    ));
    b.inv.record_source(SourceStatus::new(
        sentinel_core::SourceId::from_static("rdap"),
        target.clone(),
        SourceOutcome::Failed {
            error: "request timed out".into(),
        },
        t(0),
        t(900),
    ));
    b.inv.record_source(SourceStatus::new(
        sentinel_core::SourceId::from_static("crtsh"),
        target,
        SourceOutcome::TimedOut {
            limit: TimeLimit::Investigation,
        },
        t(0),
        t(60_000),
    ));
    b.inv.record_source(SourceStatus::new(
        sentinel_core::SourceId::from_static("cymru"),
        pivot,
        SourceOutcome::Succeeded { observations: 1 },
        t(0),
        t(40),
    ));
    let output = table::render(&b.finish());
    assert!(output.contains("virustotal  unavailable no API key configured"));
    assert!(output.contains("rdap        failed      request timed out"));
    assert!(output.contains("crtsh       timed out   investigation deadline"));
    assert!(output.contains("cymru       succeeded   1 observation   0.0 s   on 93.184.215.14"));
    assert!(output.contains("Pivots          1"));
}

#[test]
fn non_domain_targets_without_sources() {
    let target = sentinel_core::Indicator::parse_ip("8.8.8.8").unwrap();
    let mut inv = sentinel_core::Investigation::new(target, common::at(0)).unwrap();
    inv.finish(common::at(1)).unwrap();
    let output = table::render(&inv);
    assert!(output.contains("Type:      IPv4"));
    assert!(!output.contains("\nDNS\n"));
    assert!(output.contains("No source supports this indicator type yet."));
    assert!(output.contains("Findings (0)\n"));
    assert!(output.contains("No findings."));
}

#[test]
fn ip_investigation_matches_the_golden_layout() {
    let investigation = common::ip_8_8_8_8();
    let output = stable(
        &table::render(&investigation),
        &investigation.id().to_string(),
    );
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden/ip_8_8_8_8.txt");
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::write(path, &output).unwrap();
    }
    let golden = std::fs::read_to_string(path).unwrap();
    assert_eq!(output, golden, "table layout changed; see the module docs");
}

#[test]
fn infrastructure_states_and_hostile_values() {
    use sentinel_core::{NetworkRegistration, ObservationData};
    let target = sentinel_core::Indicator::parse_ip("8.8.8.8").unwrap();
    let mut inv = sentinel_core::Investigation::new(target, common::at(0)).unwrap();
    // RDAP with hostile strings; no ASN data at all.
    common::infra(
        &mut inv,
        "8.8.8.8",
        "rdap",
        ObservationData::NetworkRegistration(NetworkRegistration {
            queried_ip: "8.8.8.8".parse().unwrap(),
            handle: None,
            name: Some("\u{1b}]0;pwned\u{7}\u{1b}[2JNET\r\nFORGED LINE\u{202e}".into()),
            network_type: None,
            ip_version: None,
            start_address: None,
            end_address: None,
            cidrs: vec![],
            parent_handle: None,
            country: None,
            status: vec![],
            registered_at: None,
            last_changed_at: None,
            organization: Some("Évil\u{9b}31m Corp".into()),
            abuse_email: None,
            issues: vec![],
        }),
    );
    inv.finish(common::at(1)).unwrap();
    let output = table::render(&inv);
    assert!(output.contains("\nInfrastructure\n"));
    assert!(output.contains("  ASN           (not collected)\n"));
    for line in output.lines() {
        assert!(!line.chars().any(is_unsafe), "unsafe character: {line:?}");
        assert!(!line.trim_start().starts_with("FORGED LINE"));
    }

    // A negative Cymru answer is shown as such.
    let target = sentinel_core::Indicator::parse_ip("8.8.8.8").unwrap();
    let mut inv = sentinel_core::Investigation::new(target, common::at(0)).unwrap();
    common::infra(
        &mut inv,
        "8.8.8.8",
        "cymru",
        ObservationData::DnsNoRecords(sentinel_core::DnsNoRecords::new(
            "8.8.8.8.origin.asn.cymru.com",
            DnsRecordType::Txt,
            NoRecordsReason::NxDomain,
        )),
    );
    let output = table::render(&inv);
    assert!(output.contains("  ASN           (no BGP origin reported)\n"));
    assert!(output.contains("  Network       (not collected)\n"));
}

#[test]
fn domain_investigations_list_pivoted_infrastructure() {
    let mut inv = example_com_with_infra();
    inv.finish(common::at(300)).unwrap_or(());
    let output = table::render(&inv);
    let infra = output.find("\nInfrastructure\n").unwrap();
    assert!(output.find("\nSecurity Analysis\n").unwrap() < infra);
    assert!(output[infra..].contains("93.184.215.14\n  ASN           AS15133  EDGECAST, US\n"));
}

fn example_com_with_infra() -> sentinel_core::Investigation {
    use sentinel_core::{Asn, AsnDescription, AsnOrigin, ObservationData};
    let mut b = Builder::new("example.com");
    b.record(
        "example.com",
        DnsRecordData::A {
            address: "93.184.215.14".parse().unwrap(),
        },
    );
    let asn = Asn::new(15133).unwrap();
    common::infra(
        &mut b.inv,
        "93.184.215.14",
        "cymru",
        ObservationData::AsnOrigin(AsnOrigin {
            ip: "93.184.215.14".parse().unwrap(),
            asns: vec![asn],
            prefix: None,
            country: None,
            registry: None,
            allocated: None,
            source_text: "15133".into(),
            issues: vec![],
        }),
    );
    common::infra(
        &mut b.inv,
        "93.184.215.14",
        "cymru",
        ObservationData::AsnDescription(AsnDescription {
            asn,
            name: Some("EDGECAST, US".into()),
            country: None,
            registry: None,
            allocated: None,
            source_text: String::new(),
            issues: vec![],
        }),
    );
    b.inv
}

#[test]
fn ct_section_matches_the_golden_layout() {
    let investigation = common::example_com_with_ct();
    let output = stable(
        &table::render(&investigation),
        &investigation.id().to_string(),
    );
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/golden/example_com_ct.txt"
    );
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::write(path, &output).unwrap();
    }
    let golden = std::fs::read_to_string(path).unwrap();
    assert_eq!(output, golden, "table layout changed; see the module docs");
}

#[test]
fn ct_section_counts_and_states() {
    let output = table::render(&common::example_com_with_ct());
    let ct = &output[output.find("\nCertificate Transparency\n").unwrap()..];
    assert!(ct.contains("  Certificates  2 (4 log entries)\n"));
    assert!(ct.contains("  Names         4 related · 1 wildcard · 1 unrelated · 1 invalid\n"));
    assert!(ct.contains("· 1 expired\n"));
    assert!(ct.contains(
        "    *.example.com\n    api.example.com\n    example.com\n    www.example.com\n"
    ));
    assert!(
        !ct.contains("testexample"),
        "unrelated names are not listed as related"
    );

    // An empty CT result is shown as such, not hidden.
    let mut b = Builder::new("example.com");
    let id = b.record(
        "example.com",
        DnsRecordData::A {
            address: "93.184.215.14".parse().unwrap(),
        },
    );
    b.finding(
        "ct.no_certificates",
        Severity::Info,
        "No certificates reported by the CT source",
        "x",
        id,
    );
    let output = table::render(&b.finish());
    assert!(output.contains("Certificate Transparency\n────────────────────────────────────────────────────────────\n  No certificates reported by the CT source.\n"));
}

#[test]
fn hostile_ct_values_cannot_reach_the_terminal() {
    let mut b = Builder::new("example.com");
    common::ct_certificate(
        &mut b.inv,
        7,
        &[
            "\u{1b}]0;pwned\u{7}www.example.com",
            "ok.example.com",
            "evil\r\nFORGED LINE\u{202e}",
        ],
        -10,
        10,
        "CN=\u{1b}[2JEvil\r\nCA",
    );
    let output = table::render(&b.finish());
    for line in output.lines() {
        assert!(!line.chars().any(is_unsafe), "unsafe character: {line:?}");
        assert!(!line.trim_start().starts_with("FORGED LINE"));
    }
    assert!(output.contains("    ok.example.com\n"));
}

#[test]
fn threat_intelligence_matches_the_golden_layout() {
    let investigation = common::ip_with_reputation("\u{1b}]0;x");
    let output = stable(
        &table::render(&investigation),
        &investigation.id().to_string(),
    );
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/golden/ip_reputation.txt"
    );
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::write(path, &output).unwrap();
    }
    let golden = std::fs::read_to_string(path).unwrap();
    assert_eq!(output, golden, "table layout changed; see the module docs");
}

#[test]
fn threat_intelligence_is_attributed_unranked_and_terminal_safe() {
    let output = table::render(&common::ip_with_reputation(
        "\u{1b}]0;pwned\u{7}\u{1b}[2JEvil\r\nFORGED LINE\u{202e}",
    ));
    let ti = &output[output.find("\nThreat Intelligence\n").unwrap()..];
    assert!(ti.contains("Provider claims as reported; not verified or scored by Sentinel."));
    assert!(ti.contains("  Metric        abuse_confidence_score = 95 / 100\n"));
    assert!(ti.contains("  Metric        total_reports = 41\n"));
    for word in ["malicious", "safe", "risk", "verdict:"] {
        assert!(!ti.to_lowercase().contains(&format!("{word} ")), "{word}");
    }
    for line in output.lines() {
        assert!(!line.chars().any(is_unsafe), "unsafe character: {line:?}");
        assert!(!line.trim_start().starts_with("FORGED LINE"));
    }
}

#[test]
fn new_source_states_are_distinct() {
    let mut b = Builder::new("example.com");
    let target = b.target.clone();
    let t = common::at;
    for (source, outcome) in [
        (
            "abuseipdb",
            SourceOutcome::Unavailable {
                reason: "API key not configured (set SENTINEL_ABUSEIPDB_KEY)".into(),
            },
        ),
        ("rdap", SourceOutcome::BudgetExhausted { limit: 3 }),
        ("cymru", SourceOutcome::Unsupported),
    ] {
        b.inv.record_source(SourceStatus::new(
            sentinel_core::SourceId::from_static(source),
            target.clone(),
            outcome,
            t(0),
            t(0),
        ));
    }
    let output = table::render(&b.finish());
    assert!(
        output
            .contains("abuseipdb  unavailable API key not configured (set SENTINEL_ABUSEIPDB_KEY)")
    );
    assert!(output.contains("rdap       not run     request budget of 3 requests exhausted"));
    assert!(output.contains("cymru      unsupported no supported indicator in this investigation"));
}

#[test]
fn virustotal_matches_the_golden_layout() {
    let investigation = common::with_virustotal(
        sentinel_core::Indicator::parse_domain("example.com").unwrap(),
        true,
        "\u{1b}[31mred",
    );
    let output = stable(
        &table::render(&investigation),
        &investigation.id().to_string(),
    );
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden/virustotal.txt");
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::write(path, &output).unwrap();
    }
    let golden = std::fs::read_to_string(path).unwrap();
    assert_eq!(output, golden, "table layout changed; see the module docs");
}

#[test]
fn virustotal_claims_are_attributed_and_terminal_safe() {
    let hostile = "\u{1b}]0;pwned\u{7}\u{1b}[2JEvil\r\nFORGED LINE\u{202e}";
    let output = table::render(&common::with_virustotal(
        sentinel_core::Indicator::parse_domain("example.com").unwrap(),
        true,
        hostile,
    ));
    let ti = &output[output.find("\nThreat Intelligence\n").unwrap()..];
    assert!(ti.contains("  Provider      virustotal\n  Indicator     example.com\n"));
    assert!(ti.contains("  Metric        last_analysis_stats.malicious = 4\n"));
    assert!(ti.contains("  Community     -7 (provider-defined score)\n"));
    for line in output.lines() {
        assert!(!line.chars().any(is_unsafe), "unsafe character: {line:?}");
        assert!(!line.trim_start().starts_with("FORGED LINE"));
    }
}

#[test]
fn virustotal_no_record_is_shown_as_an_answer_not_as_missing_data() {
    let output = table::render(&common::with_virustotal(
        sentinel_core::Indicator::parse_file_hash(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        .unwrap(),
        false,
        "",
    ));
    assert!(output.contains("  Record        none (the provider has no record of it)\n"));
    assert!(output.contains("ti.virustotal.not_found"));
    assert!(!output.contains("Metric"));
}

#[test]
fn urlhaus_matches_the_golden_layout() {
    let investigation = common::with_urlhaus("listed");
    let output = stable(
        &table::render(&investigation),
        &investigation.id().to_string(),
    );
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden/urlhaus.txt");
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::write(path, &output).unwrap();
    }
    let golden = std::fs::read_to_string(path).unwrap();
    assert_eq!(output, golden, "table layout changed; see the module docs");
}

#[test]
fn urlhaus_values_cannot_reach_the_terminal() {
    let output = table::render(&common::with_urlhaus(
        "\u{1b}]0;pwned\u{7}\u{1b}[2JEvil\r\nFORGED LINE\u{202e}",
    ));
    let ti = &output[output.find("\nThreat Intelligence\n").unwrap()..];
    assert!(ti.contains("  Provider      urlhaus\n  Indicator     vektorex.com\n"));
    assert!(ti.contains("  Reported      blacklists.spamhaus_dbl = abused_legit_malware\n"));
    assert!(ti.contains("  Metric        url_count = 120\n"));
    for line in output.lines() {
        assert!(!line.chars().any(is_unsafe), "unsafe character: {line:?}");
        assert!(!line.trim_start().starts_with("FORGED LINE"));
    }
}

fn correlation_output(value: &str) -> String {
    let investigation = common::correlated(value);
    let report = sentinel_correlation::correlate(&investigation);
    table::render_correlated(&investigation, &report)
}

#[test]
fn correlation_matches_the_golden_layout() {
    let investigation = common::correlated("listed");
    let report = sentinel_correlation::correlate(&investigation);
    let mut output = stable(
        &table::render_correlated(&investigation, &report),
        &investigation.id().to_string(),
    );
    // Correlation IDs derive from the (random) observation IDs of the fixture.
    for correlation in &report.correlations {
        output = output.replace(&correlation.id().to_string(), "corr-<id>");
    }
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden/correlation.txt");
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::write(path, &output).unwrap();
    }
    let golden = std::fs::read_to_string(path).unwrap();
    assert_eq!(output, golden, "table layout changed; see the module docs");
}

#[test]
fn correlation_is_opt_in_and_only_adds_a_section() {
    let investigation = common::correlated("listed");
    let plain = table::render(&investigation);
    assert!(
        !plain.contains("Correlation ("),
        "the default report is unchanged"
    );
    let report = sentinel_correlation::correlate(&investigation);
    let correlated = table::render_correlated(&investigation, &report);
    let start = correlated.find("\nCorrelation (").unwrap();
    let end = correlated.find("\nSources\n").unwrap();
    let without: String = format!("{}{}", &correlated[..start], &correlated[end..]);
    assert_eq!(without, plain);
}

#[test]
fn correlation_section_shows_evidence_conflicts_and_no_score() {
    let output = correlation_output("listed");
    let section =
        &output[output.find("\nCorrelation (").unwrap()..output.find("\nSources\n").unwrap()];
    for expected in [
        "correlation.domain_ip_infrastructure",
        "Link      example.com --resolves_to--> 93.184.215.14",
        "Link      93.184.215.14 --announced_by--> AS15133",
        "Link      93.184.215.14 --registered_in--> 93.184.215.0/24",
        "↳ cymru · 2026-09-23 17:40:12.160 UTC · confidence 90 · sha256",
        "correlation.source_disagreement",
        "Conflict  For example.com, virustotal report(s) something while urlhaus",
        "Claim     urlhaus · no_record · no record",
        "Observed  ",
        "lowest capture confidence",
    ] {
        assert!(
            section.contains(expected),
            "missing {expected:?} in\n{section}"
        );
    }
    let lower = section.to_lowercase();
    for banned in [
        "score:",
        "risk",
        "threat score",
        "is malicious",
        "compromised",
        "attacker",
    ] {
        assert!(!lower.contains(banned), "{banned}");
    }
}

#[test]
fn hostile_values_cannot_reach_the_terminal_through_correlation() {
    let output = correlation_output("\u{1b}]0;pwned\u{7}\u{1b}[2JEvil\r\nFORGED LINE\u{202e}");
    let section = &output[output.find("\nCorrelation (").unwrap()..];
    assert!(
        section.contains("blacklists.surbl="),
        "the hostile claim is rendered"
    );
    for line in output.lines() {
        assert!(!line.chars().any(is_unsafe), "unsafe character: {line:?}");
        assert!(!line.trim_start().starts_with("FORGED LINE"));
    }
}

#[test]
fn malwarebazaar_matches_the_golden_layout() {
    let investigation = common::with_malwarebazaar("RevengeRAT", true);
    let output = stable(
        &table::render(&investigation),
        &investigation.id().to_string(),
    );
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/golden/malwarebazaar.txt"
    );
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::write(path, &output).unwrap();
    }
    let golden = std::fs::read_to_string(path).unwrap();
    assert_eq!(output, golden, "table layout changed; see the module docs");
}

#[test]
fn malwarebazaar_no_record_hostile_and_long_values() {
    let absent = table::render(&common::with_malwarebazaar("", false));
    assert!(absent.contains("  Provider      malwarebazaar\n"));
    assert!(absent.contains("  Record        none (the provider has no record of it)\n"));
    assert!(absent.contains("ti.malwarebazaar.not_found"));

    let hostile = table::render(&common::with_malwarebazaar(
        "\u{1b}]0;pwned\u{7}\u{1b}[2JEvil\r\nFORGED LINE\u{202e}",
        true,
    ));
    for line in hostile.lines() {
        assert!(!line.chars().any(is_unsafe), "unsafe character: {line:?}");
        assert!(!line.trim_start().starts_with("FORGED LINE"));
    }

    let long = "S".repeat(5_000);
    let output = table::render(&common::with_malwarebazaar(&long, true));
    let line = output
        .lines()
        .find(|l| l.starts_with("  Reported      signature = "))
        .unwrap();
    assert!(line.ends_with('…'), "long values are truncated for display");
    assert!(line.chars().count() < 300, "{}", line.chars().count());
}

#[test]
fn malwarebazaar_every_source_state_is_distinct() {
    let mut b = Builder::new("example.com");
    let target = b.target.clone();
    let t = common::at;
    for outcome in [
        SourceOutcome::Succeeded { observations: 1 },
        SourceOutcome::Partial {
            observations: 1,
            errors: vec!["x".into()],
        },
        SourceOutcome::Unavailable {
            reason:
                "API key not configured (set SENTINEL_MALWAREBAZAAR_KEY or SENTINEL_ABUSECH_KEY)"
                    .into(),
        },
        SourceOutcome::BudgetExhausted { limit: 3 },
        SourceOutcome::Unsupported,
        SourceOutcome::Failed {
            error: "MalwareBazaar rate limit exceeded (HTTP 429)".into(),
        },
        SourceOutcome::TimedOut {
            limit: sentinel_core::TimeLimit::Source,
        },
        SourceOutcome::TimedOut {
            limit: sentinel_core::TimeLimit::Investigation,
        },
    ] {
        b.inv.record_source(SourceStatus::new(
            sentinel_core::SourceId::from_static("malwarebazaar"),
            target.clone(),
            outcome,
            t(0),
            t(0),
        ));
    }
    let output = table::render(&b.finish());
    for expected in [
        "malwarebazaar  succeeded",
        "malwarebazaar  partial",
        "malwarebazaar  unavailable API key not configured (set SENTINEL_MALWAREBAZAAR_KEY or SENTINEL_ABUSECH_KEY)",
        "malwarebazaar  not run     request budget of 3 requests exhausted",
        "malwarebazaar  unsupported no supported indicator in this investigation",
        "malwarebazaar  failed      MalwareBazaar rate limit exceeded (HTTP 429)",
        "malwarebazaar  timed out   source timeout",
        "malwarebazaar  timed out   investigation deadline",
    ] {
        assert!(
            output.contains(expected),
            "missing {expected:?} in\n{output}"
        );
    }
}
