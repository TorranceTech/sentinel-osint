//! The JSON shape of the model is a public contract: `--format json` output,
//! future persistence and downstream tooling depend on it. These tests pin it.

// Test code: panicking on unexpected values is the desired behavior.
#![allow(clippy::unwrap_used)]

use chrono::{TimeZone, Utc};
use sentinel_core::{
    Asn, Confidence, DnsRecord, DnsRecordData, DnsRecordType, Finding, FindingCode, HttpMethod,
    Indicator, Investigation, Observation, ObservationData, Provenance, RelationKind, Relationship,
    Severity, Sha256Digest, SourceId, SourceOutcome, SourceStatus, Timestamp,
};
use serde_json::{Value, json};

const DNS: SourceId = SourceId::from_static("dns");

fn at(sec: u32) -> Timestamp {
    Utc.with_ymd_and_hms(2026, 9, 23, 17, 40, sec).unwrap()
}

fn to_json<T: serde::Serialize>(value: &T) -> Value {
    serde_json::to_value(value).unwrap()
}

#[test]
fn indicator_shape_and_round_trip() {
    let cases = [
        (
            Indicator::parse_domain("Example.COM").unwrap(),
            json!({"type": "domain", "value": "example.com"}),
        ),
        (
            Indicator::parse_ip("8.8.8.8").unwrap(),
            json!({"type": "ipv4", "value": "8.8.8.8"}),
        ),
        (
            Indicator::parse_ip("2001:4860:4860::8888").unwrap(),
            json!({"type": "ipv6", "value": "2001:4860:4860::8888"}),
        ),
        (
            Indicator::parse_url("https://example.com/a").unwrap(),
            json!({"type": "url", "value": "https://example.com/a"}),
        ),
        (
            Indicator::parse_file_hash(
                "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
            )
            .unwrap(),
            json!({"type": "file_hash", "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}),
        ),
    ];
    for (indicator, expected) in cases {
        assert_eq!(to_json(&indicator), expected);
        let back: Indicator = serde_json::from_value(expected).unwrap();
        assert_eq!(back, indicator);
    }
}

#[test]
fn deserialization_revalidates_untrusted_input() {
    for bad in [
        json!({"type": "domain", "value": "not a domain"}),
        json!({"type": "ipv4", "value": "2001:db8::1"}),
        json!({"type": "ipv4", "value": "999.1.1.1"}),
        json!({"type": "file_hash", "value": "zzzz"}),
        json!({"type": "url", "value": "javascript:alert(1)"}),
        json!({"type": "unknown", "value": "x"}),
    ] {
        assert!(
            serde_json::from_value::<Indicator>(bad.clone()).is_err(),
            "{bad}"
        );
    }
}

#[test]
fn observation_shape() {
    let body = b"raw response";
    let obs = Observation::new(
        Indicator::parse_domain("example.com").unwrap(),
        DNS,
        at(12),
        ObservationData::DnsRecord(DnsRecord::new(
            "example.com.",
            3600,
            DnsRecordData::Mx {
                preference: 10,
                exchange: "mail.example.com".into(),
            },
        )),
        Confidence::CERTAIN,
        Provenance::dns("example.com", DnsRecordType::Mx, "system"),
    )
    .with_raw_response_hash(Sha256Digest::of(body));

    let mut value = to_json(&obs);
    assert!(value["id"].is_string());
    value.as_object_mut().unwrap().remove("id");

    assert_eq!(
        value,
        json!({
            "indicator": {"type": "domain", "value": "example.com"},
            "source": "dns",
            "collected_at": "2026-09-23T17:40:12.000Z",
            "data": {
                "kind": "dns_record",
                "name": "example.com",
                "ttl": 3600,
                "data": {"type": "MX", "preference": 10, "exchange": "mail.example.com"}
            },
            "confidence": 100,
            "provenance": {
                "method": "dns",
                "query_name": "example.com",
                "record_type": "MX",
                "resolver": "system"
            },
            "raw_response_hash": Sha256Digest::of(body).to_string()
        })
    );
}

#[test]
fn https_provenance_shape_never_contains_secrets() {
    let url =
        url::Url::parse("https://api.example.com/v2/check?ipAddress=8.8.8.8&key=SECRET").unwrap();
    let value = to_json(&Provenance::https(HttpMethod::Get, &url, 200));
    assert_eq!(
        value,
        json!({
            "method": "https",
            "http_method": "GET",
            "endpoint": "https://api.example.com/v2/check?ipAddress=8.8.8.8&key=REDACTED",
            "status": 200
        })
    );
}

/// Builds a small but complete investigation. Returns it with the ID of the
/// A-record observation.
fn sample_investigation() -> (Investigation, sentinel_core::ObservationId) {
    let target = Indicator::parse_domain("example.com").unwrap();
    let mut inv = Investigation::new(target.clone(), at(0)).unwrap();

    let obs_id = inv.add_observation(Observation::new(
        target.clone(),
        DNS,
        at(1),
        ObservationData::DnsRecord(DnsRecord::new(
            "example.com",
            300,
            DnsRecordData::A {
                address: "93.184.215.14".parse().unwrap(),
            },
        )),
        Confidence::CERTAIN,
        Provenance::dns("example.com", DnsRecordType::A, "system"),
    ));
    let ip = Indicator::parse_ip("93.184.215.14").unwrap();
    inv.add_relationship(
        Relationship::new(target, RelationKind::ResolvesTo, ip.clone(), [obs_id]).unwrap(),
    )
    .unwrap();
    // An IP → ASN edge also serializes as a typed entity.
    let asn_obs = inv.add_observation(Observation::new(
        ip.clone(),
        DNS,
        at(1),
        ObservationData::DnsRecord(DnsRecord::new(
            "14.215.184.93.origin.asn.cymru.com",
            300,
            DnsRecordData::Txt {
                text: "15133 | 93.184.215.0/24 | US | ripencc | 2008-06-02".into(),
            },
        )),
        Confidence::saturating(90),
        Provenance::dns(
            "14.215.184.93.origin.asn.cymru.com",
            DnsRecordType::Txt,
            "system",
        ),
    ));
    inv.add_relationship(
        Relationship::new(
            ip,
            RelationKind::AnnouncedBy,
            Asn::new(15133).unwrap(),
            [asn_obs],
        )
        .unwrap(),
    )
    .unwrap();
    inv.add_finding(
        Finding::new(
            FindingCode::from_static("dns.caa.missing"),
            Severity::Info,
            "No CAA records",
            "Any certificate authority may issue certificates for this domain.",
            Confidence::saturating(95),
        )
        .with_evidence([obs_id]),
    )
    .unwrap();
    let target = inv.target().clone();
    inv.record_source(SourceStatus::new(
        DNS,
        target.clone(),
        SourceOutcome::Succeeded { observations: 2 },
        at(0),
        at(1),
    ));
    inv.record_source(SourceStatus::new(
        SourceId::from_static("virustotal"),
        target,
        SourceOutcome::Unavailable {
            reason: "no API key configured".into(),
        },
        at(0),
        at(0),
    ));
    inv.finish(at(2)).unwrap();
    (inv, obs_id)
}

#[test]
fn investigation_shape() {
    let (inv, obs_id) = sample_investigation();
    let value = to_json(&inv);
    assert_eq!(
        value["target"],
        json!({"type": "domain", "value": "example.com"})
    );
    assert_eq!(value["tool"]["name"], "sentinel-osint");
    assert_eq!(value["started_at"], "2026-09-23T17:40:00.000Z");
    assert_eq!(value["finished_at"], "2026-09-23T17:40:02.000Z");
    assert_eq!(value["observations"].as_array().unwrap().len(), 2);
    assert_eq!(
        value["relationships"][0],
        json!({
            "source": {"type": "domain", "value": "example.com"},
            "kind": "resolves_to",
            "target": {"type": "ipv4", "value": "93.184.215.14"},
            "evidence": [obs_id.to_string()]
        })
    );
    assert_eq!(
        value["relationships"][1]["target"],
        json!({"type": "autonomous_system", "value": "AS15133"})
    );
    assert_eq!(
        value["findings"][0],
        json!({
            "code": "dns.caa.missing",
            "severity": "info",
            "title": "No CAA records",
            "detail": "Any certificate authority may issue certificates for this domain.",
            "confidence": 95,
            "evidence": [obs_id.to_string()]
        })
    );
    assert_eq!(
        value["sources"],
        json!([
            {
                "source": "dns",
                "indicator": {"type": "domain", "value": "example.com"},
                "status": "succeeded",
                "observations": 2,
                "started_at": "2026-09-23T17:40:00.000Z",
                "finished_at": "2026-09-23T17:40:01.000Z"
            },
            {
                "source": "virustotal",
                "indicator": {"type": "domain", "value": "example.com"},
                "status": "unavailable",
                "reason": "no API key configured",
                "started_at": "2026-09-23T17:40:00.000Z",
                "finished_at": "2026-09-23T17:40:00.000Z"
            }
        ])
    );
}

#[test]
fn unfinished_investigation_serializes_null_finish_time() {
    let inv = Investigation::new(Indicator::parse_ip("8.8.8.8").unwrap(), at(0)).unwrap();
    assert_eq!(to_json(&inv)["finished_at"], Value::Null);
}

#[test]
fn source_state_shapes() {
    let target = Indicator::parse_ip("8.8.8.8").unwrap();
    let status = |outcome| {
        to_json(&SourceStatus::new(
            SourceId::from_static("x"),
            target.clone(),
            outcome,
            at(0),
            at(0),
        ))
    };
    assert_eq!(
        status(SourceOutcome::BudgetExhausted { limit: 3 })["status"],
        "budget_exhausted"
    );
    assert_eq!(
        status(SourceOutcome::BudgetExhausted { limit: 3 })["limit"],
        3
    );
    assert_eq!(status(SourceOutcome::Unsupported)["status"], "unsupported");
    assert_eq!(
        status(SourceOutcome::Unavailable { reason: "r".into() })["status"],
        "unavailable"
    );
}
