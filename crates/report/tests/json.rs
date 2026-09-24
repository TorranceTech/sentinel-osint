//! JSON output contract: the document shape consumers (SIEM, scripts,
//! future STIX export) depend on.

#![allow(clippy::unwrap_used)]

mod common;

use common::{Builder, example_com};
use sentinel_core::{DnsRecordData, Severity, SourceOutcome};
use sentinel_report::json;
use serde_json::{Value, json};

fn render(investigation: &sentinel_core::Investigation) -> Value {
    let output = json::render(investigation).unwrap();
    assert!(output.ends_with('\n'));
    // The whole output is one JSON document: nothing before or after it.
    serde_json::from_str(&output).unwrap()
}

#[test]
fn document_envelope() {
    let doc = render(&example_com());
    let keys: Vec<&str> = doc
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys, vec!["investigation", "schema_version"]);
    assert_eq!(doc["schema_version"], json::SCHEMA_VERSION);
}

#[test]
fn investigation_shape() {
    let doc = render(&example_com());
    let inv = &doc["investigation"];
    let mut keys: Vec<&str> = inv
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec![
            "findings",
            "finished_at",
            "id",
            "observations",
            "relationships",
            "sources",
            "started_at",
            "target",
            "tool"
        ]
    );
    assert_eq!(
        inv["target"],
        json!({"type": "domain", "value": "example.com"})
    );
    assert_eq!(inv["started_at"], "2026-09-23T17:40:12.000Z");
    assert_eq!(inv["finished_at"], "2026-09-23T17:40:12.215Z");
    assert_eq!(inv["tool"]["name"], "sentinel-osint");
}

#[test]
fn dns_observation_shapes() {
    let doc = render(&example_com());
    let observations = doc["investigation"]["observations"].as_array().unwrap();

    let mx = observations
        .iter()
        .find(|o| o["data"]["data"]["type"] == "MX")
        .unwrap();
    assert_eq!(mx["data"]["kind"], "dns_record");
    assert_eq!(mx["data"]["name"], "example.com");
    assert_eq!(mx["data"]["ttl"], 300);
    assert_eq!(
        mx["data"]["data"],
        json!({"type": "MX", "preference": 10, "exchange": "mail.example.com"})
    );
    assert_eq!(mx["source"], "dns");
    assert_eq!(mx["confidence"], 90);
    assert_eq!(mx["collected_at"], "2026-09-23T17:40:12.150Z");
    assert_eq!(
        mx["provenance"],
        json!({"method": "dns", "query_name": "example.com", "record_type": "MX", "resolver": "system"})
    );
    assert_eq!(mx["raw_response_hash"].as_str().unwrap().len(), 64);
    assert!(mx["id"].is_string());

    let absent = observations
        .iter()
        .find(|o| o["data"]["kind"] == "dns_no_records")
        .unwrap();
    assert_eq!(
        absent["data"],
        json!({"kind": "dns_no_records", "name": "example.com", "record_type": "CNAME", "reason": "no_data"})
    );
    assert!(absent.get("raw_response_hash").is_none());
}

#[test]
fn findings_and_sources_shape() {
    let doc = render(&example_com());
    let inv = &doc["investigation"];
    let finding = &inv["findings"][0];
    assert_eq!(finding["code"], "dns.spf.hardfail");
    assert_eq!(finding["severity"], "info");
    assert_eq!(finding["confidence"], 90);
    assert_eq!(finding["evidence"].as_array().unwrap().len(), 1);
    // Every cited observation exists in the document.
    let ids: Vec<&Value> = inv["observations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| &o["id"])
        .collect();
    for finding in inv["findings"].as_array().unwrap() {
        for evidence in finding["evidence"].as_array().unwrap() {
            assert!(ids.contains(&evidence));
        }
    }
    assert_eq!(
        inv["sources"][0],
        json!({
            "source": "dns",
            "indicator": {"type": "domain", "value": "example.com"},
            "status": "succeeded",
            "observations": 11,
            "started_at": "2026-09-23T17:40:12.000Z",
            "finished_at": "2026-09-23T17:40:12.180Z"
        })
    );
}

#[test]
fn partial_outcome_shape() {
    let mut b = Builder::new("example.com");
    b.status(SourceOutcome::Partial {
        observations: 0,
        errors: vec!["TXT lookup for example.com failed: DNS query timed out".into()],
    });
    let doc = render(&b.finish());
    assert_eq!(doc["investigation"]["sources"][0]["status"], "partial");
    assert_eq!(
        doc["investigation"]["sources"][0]["errors"],
        json!(["TXT lookup for example.com failed: DNS query timed out"])
    );
}

#[test]
fn hostile_content_is_escaped_not_interpreted() {
    let mut b = Builder::new("example.com");
    let hostile = "\"}], \"injected\": true, {\"\u{1b}[31m\n\u{0}";
    let id = b.record(
        "example.com",
        DnsRecordData::Txt {
            text: hostile.into(),
        },
    );
    b.finding("dns.spf.malformed", Severity::Low, "t", hostile, id);
    let doc = render(&b.finish());
    let inv = &doc["investigation"];
    assert!(inv.get("injected").is_none());
    // Evidence is faithful: the exact bytes survive the round trip.
    assert_eq!(inv["observations"][0]["data"]["data"]["text"], hostile);
}

#[test]
fn infrastructure_shapes() {
    let doc = render(&common::ip_8_8_8_8());
    let inv = &doc["investigation"];
    assert_eq!(inv["target"], json!({"type": "ipv4", "value": "8.8.8.8"}));
    let observations = inv["observations"].as_array().unwrap();

    let origin = &observations[0]["data"];
    assert_eq!(
        origin,
        &json!({
            "kind": "asn_origin",
            "ip": "8.8.8.8",
            "asns": [15169],
            "prefix": "8.8.8.0/24",
            "country": "US",
            "registry": "arin",
            "allocated": "2023-12-28",
            "source_text": "15169 | 8.8.8.0/24 | US | arin | 2023-12-28",
            "issues": []
        })
    );
    assert_eq!(observations[1]["data"]["kind"], "asn_description");
    assert_eq!(observations[1]["data"]["name"], "GOOGLE, US");

    let network = &observations[2];
    assert_eq!(network["source"], "rdap");
    assert_eq!(network["provenance"]["method"], "https");
    assert_eq!(network["data"]["kind"], "network_registration");
    assert_eq!(network["data"]["cidrs"], json!(["8.8.8.0/24"]));
    assert_eq!(network["data"]["ip_version"], "v4");
    assert_eq!(network["data"]["registered_at"], "2014-03-14T17:40:12.000Z");
    assert_eq!(network["data"]["organization"], "Google LLC");

    let relationships = inv["relationships"].as_array().unwrap();
    assert_eq!(relationships[0]["kind"], "announced_by");
    assert_eq!(
        relationships[0]["target"],
        json!({"type": "autonomous_system", "value": "AS15169"})
    );
    assert_eq!(relationships[1]["kind"], "registered_in");
    assert_eq!(
        relationships[1]["target"],
        json!({"type": "network", "value": "8.8.8.0/24"})
    );
}

#[test]
fn ct_shapes() {
    let doc = render(&common::example_com_with_ct());
    let inv = &doc["investigation"];
    let cert = inv["observations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["data"]["kind"] == "ct_certificate")
        .unwrap();
    assert_eq!(cert["source"], "ct");
    assert_eq!(cert["data"]["source_entry_id"], 1002);
    assert_eq!(cert["data"]["serial_number"], "3ea");
    assert_eq!(cert["data"]["source_entries"], 2);
    assert_eq!(cert["data"]["omitted_email_names"], 0);
    assert_eq!(
        cert["data"]["names"][1],
        json!({"raw": "*.example.com", "normalized": "example.com", "wildcard": true, "relation": "wildcard"})
    );
    let old = inv["observations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["data"]["source_entry_id"] == 900)
        .unwrap();
    let names = old["data"]["names"].as_array().unwrap();
    assert_eq!(names[2]["relation"], "unrelated");
    assert_eq!(
        names[3],
        json!({"raw": "bad name", "normalized": null, "wildcard": false, "relation": "invalid"})
    );
    let edge = inv["relationships"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["kind"] == "covers_name")
        .unwrap();
    assert_eq!(
        edge["source"],
        json!({"type": "certificate", "value": "crtsh:900"})
    );
    assert_eq!(
        edge["target"],
        json!({"type": "domain", "value": "www.example.com"})
    );
}

#[test]
fn reputation_shape_keeps_provider_metrics_separate_from_confidence() {
    let doc = render(&common::ip_with_reputation("Example ISP"));
    let observation = &doc["investigation"]["observations"][0];
    assert_eq!(observation["source"], "abuseipdb");
    assert_eq!(
        observation["confidence"], 90,
        "Sentinel's confidence in the capture"
    );
    let data = &observation["data"];
    assert_eq!(data["kind"], "ip_reputation");
    assert_eq!(data["provider"], "abuseipdb");
    assert_eq!(data["window_days"], 90);
    assert_eq!(
        data["metrics"][0],
        json!({"name": "abuse_confidence_score", "value": 95, "max": 100}),
        "the provider's metric, with the provider's name"
    );
    assert_eq!(data["context_source"], "IPinfo (as reported by AbuseIPDB)");
    for field in [
        "malicious",
        "risk_score",
        "verdict",
        "threat_score",
        "classification",
    ] {
        assert!(
            data.get(field).is_none(),
            "no Sentinel verdict field: {field}"
        );
    }
}

#[test]
fn virustotal_shapes_keep_provider_figures_separate_from_confidence() {
    let doc = render(&common::with_virustotal(
        sentinel_core::Indicator::parse_domain("example.com").unwrap(),
        true,
        "cdn",
    ));
    let observation = &doc["investigation"]["observations"][0];
    assert_eq!(observation["source"], "virustotal");
    assert_eq!(observation["confidence"], 90);
    let data = &observation["data"];
    assert_eq!(data["kind"], "provider_reputation");
    assert_eq!(data["provider"], "virustotal");
    assert_eq!(
        data["metrics"][0],
        json!({"name": "last_analysis_stats.malicious", "value": 4, "max": null})
    );
    assert_eq!(data["community_score"], -7);
    assert_eq!(data["last_analysis_at"], "2026-09-21T17:40:12.000Z");
    for field in [
        "malicious",
        "risk_score",
        "verdict",
        "threat_score",
        "severity",
    ] {
        assert!(
            data.get(field).is_none(),
            "no Sentinel verdict field: {field}"
        );
    }

    let absent = render(&common::with_virustotal(
        sentinel_core::Indicator::parse_domain("example.com").unwrap(),
        false,
        "",
    ));
    assert_eq!(
        absent["investigation"]["observations"][0]["data"],
        json!({"kind": "provider_no_record", "provider": "virustotal"})
    );
}

#[test]
fn urlhaus_listing_shape_keeps_provider_field_names() {
    let doc = render(&common::with_urlhaus("listed"));
    let observation = &doc["investigation"]["observations"][0];
    assert_eq!(observation["source"], "urlhaus");
    assert_eq!(observation["confidence"], 90);
    assert_eq!(observation["provenance"]["http_method"], "POST");
    let data = &observation["data"];
    assert_eq!(data["kind"], "provider_listing");
    assert_eq!(
        data["attributes"][0],
        json!({"name": "blacklists.spamhaus_dbl", "value": "abused_legit_malware"})
    );
    assert_eq!(
        data["metrics"][0],
        json!({"name": "url_count", "value": 120, "max": null})
    );
    assert_eq!(data["dates"][0]["name"], "firstseen");
    assert_eq!(data["dates"][0]["at"], "2026-08-24T17:40:12.000Z");
    for field in [
        "malicious",
        "risk_score",
        "verdict",
        "threat_score",
        "severity",
        "urls",
        "reporter",
    ] {
        assert!(data.get(field).is_none(), "{field}");
    }
}

#[test]
fn correlation_is_an_additional_member_referencing_observations() {
    let investigation = common::correlated("listed");
    let plain: Value =
        serde_json::from_str(&sentinel_report::json::render(&investigation).unwrap()).unwrap();
    assert!(plain.get("correlation").is_none(), "opt-in");
    let report = sentinel_correlation::correlate(&investigation);
    let text = sentinel_report::json::render_correlated(&investigation, &report).unwrap();
    let doc: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(doc["schema_version"], "0.1");
    assert_eq!(
        doc["investigation"], plain["investigation"],
        "investigation unchanged"
    );
    let ids: Vec<&str> = doc["investigation"]["observations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o["id"].as_str().unwrap())
        .collect();
    let correlations = doc["correlation"]["correlations"].as_array().unwrap();
    assert!(!correlations.is_empty());
    for c in correlations {
        for id in c["evidence"].as_array().unwrap() {
            assert!(ids.contains(&id.as_str().unwrap()), "dangling reference");
        }
        assert!(c["id"].as_str().unwrap().starts_with("corr-"));
        for banned in [
            "score",
            "risk_score",
            "threat_score",
            "malicious",
            "verdict",
        ] {
            assert!(c.get(banned).is_none(), "{banned}");
        }
    }
    let findings = doc["correlation"]["findings"].as_array().unwrap();
    assert_eq!(findings.len(), correlations.len());
    assert!(findings.iter().all(|f| f["severity"] == "info"));
    // Deterministic.
    assert_eq!(
        text,
        sentinel_report::json::render_correlated(
            &investigation,
            &sentinel_correlation::correlate(&investigation)
        )
        .unwrap()
    );
}

#[test]
fn malwarebazaar_listing_shape() {
    let doc = render(&common::with_malwarebazaar("RevengeRAT", true));
    let observation = &doc["investigation"]["observations"][0];
    assert_eq!(observation["source"], "malwarebazaar");
    assert_eq!(observation["indicator"]["type"], "file_hash");
    assert_eq!(observation["provenance"]["http_method"], "POST");
    let data = &observation["data"];
    assert_eq!(data["kind"], "provider_listing");
    assert_eq!(
        data["attributes"][0],
        json!({"name": "signature", "value": "RevengeRAT"})
    );
    assert_eq!(
        data["metrics"][0],
        json!({"name": "file_size", "value": 145_408, "max": null})
    );
    for field in [
        "malicious",
        "verdict",
        "threat_score",
        "severity",
        "file_name",
        "reporter",
    ] {
        assert!(data.get(field).is_none(), "{field}");
    }
    let absent = render(&common::with_malwarebazaar("", false));
    assert_eq!(
        absent["investigation"]["observations"][0]["data"],
        json!({"kind": "provider_no_record", "provider": "malwarebazaar"})
    );
}
