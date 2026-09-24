//! [`DnsResolver`] implementation backed by `hickory-resolver`.

use std::time::Duration;

use hickory_resolver::TokioResolver;
use hickory_resolver::config::ResolveHosts;
use hickory_resolver::net::NetError;
use hickory_resolver::proto::rr::{Name, RData, Record, RecordType};
use sentinel_core::evidence::normalize_name;
use sentinel_core::{DnsRecord, DnsRecordData, DnsRecordType};

use super::{DnsLookupFuture, DnsQueryError, DnsResolver};

/// Per-attempt timeout of the underlying resolver.
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(3);
/// Attempts per query.
const ATTEMPTS: usize = 2;

/// The system resolver (`/etc/resolv.conf` on Unix, the registry on Windows).
pub struct HickoryResolver {
    inner: TokioResolver,
    description: String,
}

/// The resolver could not be configured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("could not initialize the DNS resolver from the system configuration")]
pub struct DnsSetupError;

impl HickoryResolver {
    /// Creates a resolver using the system's DNS configuration, with:
    ///
    /// - the hosts file **disabled**: `/etc/hosts` entries are local
    ///   configuration, not public DNS intelligence;
    /// - bounded timeouts and attempts.
    ///
    /// Queries are always sent as fully qualified names, so search domains
    /// from the system configuration are never appended (no leaking of
    /// `example.com.corp.internal`-style queries).
    ///
    /// # Errors
    /// [`DnsSetupError`] if the system configuration cannot be read.
    pub fn from_system() -> Result<Self, DnsSetupError> {
        let mut builder = TokioResolver::builder_tokio().map_err(|_| DnsSetupError)?;
        let options = builder.options_mut();
        options.use_hosts_file = ResolveHosts::Never;
        options.timeout = ATTEMPT_TIMEOUT;
        options.attempts = ATTEMPTS;
        let inner = builder.build().map_err(|_| DnsSetupError)?;
        Ok(Self {
            inner,
            description: "system".to_owned(),
        })
    }
}

impl DnsResolver for HickoryResolver {
    fn description(&self) -> &str {
        &self.description
    }

    fn lookup<'a>(&'a self, name: &'a str, record_type: DnsRecordType) -> DnsLookupFuture<'a> {
        Box::pin(async move {
            // Trailing dot: fully qualified, no search-domain expansion.
            let fqdn =
                Name::from_ascii(format!("{name}.")).map_err(|_| DnsQueryError::InvalidName)?;
            let wanted = to_hickory_type(record_type);
            match self.inner.lookup(fqdn, wanted).await {
                Ok(lookup) => {
                    let records: Vec<DnsRecord> = lookup
                        .answers()
                        .iter()
                        .filter(|record| record.record_type() == wanted)
                        .filter_map(convert_record)
                        .collect();
                    if records.is_empty() {
                        Err(DnsQueryError::NoRecords)
                    } else {
                        Ok(records)
                    }
                }
                Err(error) => Err(map_error(&error)),
            }
        })
    }
}

fn map_error(error: &NetError) -> DnsQueryError {
    if error.is_nx_domain() {
        DnsQueryError::NxDomain
    } else if error.is_no_records_found() {
        DnsQueryError::NoRecords
    } else if matches!(error, NetError::Timeout) {
        DnsQueryError::Timeout
    } else {
        tracing::debug!(error = ?error, "DNS lookup failed");
        DnsQueryError::Failure
    }
}

const fn to_hickory_type(record_type: DnsRecordType) -> RecordType {
    match record_type {
        DnsRecordType::A => RecordType::A,
        DnsRecordType::Aaaa => RecordType::AAAA,
        DnsRecordType::Mx => RecordType::MX,
        DnsRecordType::Ns => RecordType::NS,
        DnsRecordType::Txt => RecordType::TXT,
        DnsRecordType::Cname => RecordType::CNAME,
        DnsRecordType::Soa => RecordType::SOA,
        DnsRecordType::Caa => RecordType::CAA,
    }
}

fn name_text(name: &Name) -> String {
    // `to_ascii` escapes non-printable bytes in labels (`\DDD`).
    normalize_name(&name.to_ascii())
}

/// Converts a hickory record into the core model. Content is kept faithful:
/// TXT and CAA bytes are decoded lossily (invalid UTF-8 becomes U+FFFD) and
/// are otherwise unchanged. Size limits are applied by the collector.
fn convert_record(record: &Record) -> Option<DnsRecord> {
    let data = match &record.data {
        RData::A(a) => DnsRecordData::A { address: a.0 },
        RData::AAAA(aaaa) => DnsRecordData::Aaaa { address: aaaa.0 },
        RData::MX(mx) => DnsRecordData::Mx {
            preference: mx.preference,
            exchange: name_text(&mx.exchange),
        },
        RData::NS(ns) => DnsRecordData::Ns {
            nameserver: name_text(&ns.0),
        },
        RData::CNAME(cname) => DnsRecordData::Cname {
            target: name_text(&cname.0),
        },
        RData::SOA(soa) => DnsRecordData::Soa {
            mname: name_text(&soa.mname),
            rname: name_text(&soa.rname),
            serial: soa.serial,
            // Negative values are invalid on the wire; clamp instead of wrapping.
            refresh: u32::try_from(soa.refresh).unwrap_or(0),
            retry: u32::try_from(soa.retry).unwrap_or(0),
            expire: u32::try_from(soa.expire).unwrap_or(0),
            minimum: soa.minimum,
        },
        RData::TXT(txt) => DnsRecordData::Txt {
            text: txt
                .txt_data
                .iter()
                .map(|part| String::from_utf8_lossy(part))
                .collect(),
        },
        RData::CAA(caa) => DnsRecordData::Caa {
            critical: caa.issuer_critical,
            tag: caa.tag.clone(),
            value: String::from_utf8_lossy(&caa.value).into_owned(),
        },
        _ => return None,
    };
    Some(DnsRecord::new(&name_text(&record.name), record.ttl, data))
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    use hickory_resolver::proto::rr::rdata::{A, AAAA, CAA, CNAME, MX, NS, SOA, TXT};

    use super::*;

    fn name(s: &str) -> Name {
        Name::from_str(s).unwrap()
    }

    fn record(data: RData) -> Record {
        Record::from_rdata(name("Example.COM."), 300, data)
    }

    #[test]
    fn converts_every_supported_type() {
        let cases: Vec<(RData, DnsRecordData)> = vec![
            (
                RData::A(A(Ipv4Addr::new(93, 184, 215, 14))),
                DnsRecordData::A {
                    address: Ipv4Addr::new(93, 184, 215, 14),
                },
            ),
            (
                RData::AAAA(AAAA(Ipv6Addr::LOCALHOST)),
                DnsRecordData::Aaaa {
                    address: Ipv6Addr::LOCALHOST,
                },
            ),
            (
                RData::MX(MX::new(10, name("Mail.Example.com."))),
                DnsRecordData::Mx {
                    preference: 10,
                    exchange: "mail.example.com".into(),
                },
            ),
            (
                RData::NS(NS(name("ns1.example.net."))),
                DnsRecordData::Ns {
                    nameserver: "ns1.example.net".into(),
                },
            ),
            (
                RData::CNAME(CNAME(name("edge.cdn.example."))),
                DnsRecordData::Cname {
                    target: "edge.cdn.example".into(),
                },
            ),
            (
                RData::SOA(SOA::new(
                    name("ns.example.com."),
                    name("hostmaster.example.com."),
                    7,
                    3600,
                    -5,
                    1_209_600,
                    300,
                )),
                DnsRecordData::Soa {
                    mname: "ns.example.com".into(),
                    rname: "hostmaster.example.com".into(),
                    serial: 7,
                    refresh: 3600,
                    retry: 0, // negative on the wire: clamped
                    expire: 1_209_600,
                    minimum: 300,
                },
            ),
            (
                RData::TXT(TXT::new(vec!["v=spf1 ".into(), "-all".into()])),
                DnsRecordData::Txt {
                    text: "v=spf1 -all".into(),
                },
            ),
            (
                RData::CAA(CAA::new_issue(true, Some(name("letsencrypt.org")), vec![])),
                DnsRecordData::Caa {
                    critical: true,
                    tag: "issue".into(),
                    value: "letsencrypt.org".into(),
                },
            ),
        ];
        for (rdata, expected) in cases {
            let converted = convert_record(&record(rdata)).unwrap();
            assert_eq!(converted.name(), "example.com");
            assert_eq!(converted.ttl(), 300);
            assert_eq!(converted.data(), &expected);
        }
    }

    #[test]
    fn txt_bytes_are_decoded_lossily_and_kept_faithful() {
        let hostile: Vec<&[u8]> = vec![b"\x1b[31mred\x07", b"\xff\xfe", "ünïcödé".as_bytes()];
        let converted = convert_record(&record(RData::TXT(TXT::from_bytes(hostile)))).unwrap();
        assert_eq!(
            converted.data().txt(),
            Some("\u{1b}[31mred\u{7}\u{FFFD}\u{FFFD}ünïcödé")
        );
    }

    #[test]
    fn unsupported_types_are_ignored() {
        let ptr = RData::PTR(hickory_resolver::proto::rr::rdata::PTR(name("x.example.")));
        assert!(convert_record(&record(ptr)).is_none());
    }

    #[test]
    fn negative_answers_are_not_failures() {
        assert!(DnsQueryError::NxDomain.is_negative_answer());
        assert!(DnsQueryError::NoRecords.is_negative_answer());
        assert!(!DnsQueryError::Timeout.is_negative_answer());
        assert!(!DnsQueryError::Failure.is_negative_answer());
    }
}
