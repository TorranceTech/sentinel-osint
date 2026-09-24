//! Findings about basic records: non-public addresses and null MX.

use std::net::IpAddr;

use sentinel_core::net::classify;
use sentinel_core::{DnsRecordData, DnsRecordType, Finding, FindingCode, ObservationId, Severity};

use super::{DnsAnswers, finding};

/// A/AAAA records pointing to non-public addresses.
pub(crate) const NON_PUBLIC_ADDRESS: FindingCode =
    FindingCode::from_static("dns.address.non_public");
/// Null MX (RFC 7505): the domain accepts no email.
pub(crate) const NULL_MX: FindingCode = FindingCode::from_static("dns.mx.null");

pub(crate) fn analyze(answers: &DnsAnswers) -> Vec<Finding> {
    let mut findings = Vec::new();

    let mut non_public: Vec<(ObservationId, IpAddr)> = Vec::new();
    for record_type in [DnsRecordType::A, DnsRecordType::Aaaa] {
        for (id, record) in answers.apex(record_type).records() {
            let ip = match record.data() {
                DnsRecordData::A { address } => IpAddr::V4(*address),
                DnsRecordData::Aaaa { address } => IpAddr::V6(*address),
                _ => continue,
            };
            if !classify(ip).is_global() {
                non_public.push((*id, ip));
            }
        }
    }
    if !non_public.is_empty() {
        let listed: Vec<String> = non_public
            .iter()
            .map(|(_, ip)| format!("{ip} ({})", classify(*ip)))
            .collect();
        findings.push(finding(
            NON_PUBLIC_ADDRESS,
            Severity::Low,
            "Public DNS publishes non-public addresses",
            format!(
                "{} resolves to non-public address(es): {}. This can reveal internal addressing. These addresses were not enriched further.",
                answers.domain,
                listed.join(", ")
            ),
            non_public.iter().map(|(id, _)| *id).collect(),
        ));
    }

    let mx = answers.apex(DnsRecordType::Mx).records();
    let is_null_mx = |data: &DnsRecordData| matches!(data, DnsRecordData::Mx { exchange, .. } if exchange.is_empty());
    if mx.len() == 1 && is_null_mx(mx[0].1.data()) {
        findings.push(finding(
            NULL_MX,
            Severity::Info,
            "Domain does not accept email (null MX)",
            format!(
                "{} publishes a null MX record (RFC 7505), declaring that it accepts no email.",
                answers.domain
            ),
            vec![mx[0].0],
        ));
    }
    findings
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::super::QueryResult;
    use super::super::testing::{codes, records};
    use super::*;

    fn answers(apex: Vec<(DnsRecordType, QueryResult)>) -> DnsAnswers {
        DnsAnswers {
            domain: "example.com".into(),
            apex: apex.into_iter().collect::<BTreeMap<_, _>>(),
            dmarc: QueryResult::Failed,
        }
    }

    #[test]
    fn flags_non_public_addresses() {
        let a = records(
            "example.com",
            vec![
                DnsRecordData::A {
                    address: "93.184.215.14".parse().unwrap(),
                },
                DnsRecordData::A {
                    address: "10.0.0.5".parse().unwrap(),
                },
            ],
        );
        let aaaa = records(
            "example.com",
            vec![DnsRecordData::Aaaa {
                address: "fd00::1".parse().unwrap(),
            }],
        );
        let findings = analyze(&answers(vec![
            (DnsRecordType::A, a),
            (DnsRecordType::Aaaa, aaaa),
        ]));
        assert_eq!(codes(&findings), vec!["dns.address.non_public"]);
        assert_eq!(findings[0].evidence().len(), 2);
        assert!(
            findings[0]
                .detail()
                .contains("10.0.0.5 (private (RFC 1918))")
        );
    }

    #[test]
    fn detects_null_mx_only_when_alone() {
        let null = || DnsRecordData::Mx {
            preference: 0,
            exchange: String::new(),
        };
        let real = DnsRecordData::Mx {
            preference: 10,
            exchange: "mail.example.com".into(),
        };
        assert_eq!(
            codes(&analyze(&answers(vec![(
                DnsRecordType::Mx,
                records("example.com", vec![null()])
            )]))),
            vec!["dns.mx.null"]
        );
        assert!(
            analyze(&answers(vec![(
                DnsRecordType::Mx,
                records("example.com", vec![null(), real])
            )]))
            .is_empty()
        );
    }
}
