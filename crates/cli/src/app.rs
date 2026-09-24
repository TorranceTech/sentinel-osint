//! The `investigate` command: indicator → engine → report.

use std::sync::Arc;
use std::time::Duration;

use sentinel_collectors::{
    AbuseIpDbCollector, Collector, CtCollector, CymruCollector, DnsCollector, DnsResolver, Engine,
    EngineConfig, HttpClient, HttpConfig, MalwareBazaarCollector, RdapCollector, SystemClock,
    UrlhausCollector, VirusTotalCollector,
};
use sentinel_core::{Indicator, IndicatorError};
use sentinel_report::{json, table};

use crate::args::{Format, InvestigateArgs};
use crate::config::Credentials;

/// Maximum time for a single source run.
const MAX_SOURCE_TIMEOUT: Duration = Duration::from_secs(45);

/// Why the command failed, which also decides the exit code.
#[derive(Debug)]
pub(crate) enum AppError {
    /// The user's input is not acceptable (exit code 2).
    InvalidInput(IndicatorError),
    /// Anything else (exit code 1).
    Fatal(anyhow::Error),
}

impl From<anyhow::Error> for AppError {
    fn from(error: anyhow::Error) -> Self {
        Self::Fatal(error)
    }
}

/// Parses and validates the target before any network activity: syntax
/// first, then the investigation policy (public addresses and names only).
pub(crate) fn parse_target(args: &InvestigateArgs) -> Result<Indicator, IndicatorError> {
    let indicator = match (&args.domain, &args.ip, &args.hash) {
        (Some(domain), _, _) => Indicator::parse_domain(domain)?,
        (_, Some(ip), _) => Indicator::parse_ip(ip)?,
        (_, _, Some(hash)) => Indicator::parse_file_hash(hash)?,
        // clap requires exactly one target; stay total anyway.
        (None, None, None) => return Err(IndicatorError::Empty),
    };
    indicator.ensure_investigable()?;
    Ok(indicator)
}

/// Every collector of this version, sharing one DNS resolver. Providers
/// without credentials are still registered: they report themselves as
/// unavailable instead of silently disappearing.
pub(crate) fn default_collectors(
    resolver: &Arc<dyn DnsResolver>,
    credentials: Credentials,
) -> Vec<Arc<dyn Collector>> {
    vec![
        Arc::new(DnsCollector::new(Arc::clone(resolver))),
        Arc::new(CtCollector::new()),
        Arc::new(CymruCollector::new(Arc::clone(resolver))),
        Arc::new(RdapCollector::new()),
        Arc::new(AbuseIpDbCollector::new(credentials.abuseipdb)),
        Arc::new(VirusTotalCollector::new(credentials.virustotal)),
        Arc::new(UrlhausCollector::new(credentials.abusech)),
        Arc::new(MalwareBazaarCollector::new(credentials.malwarebazaar)),
    ]
}

/// Builds the engine with the given collectors.
fn build_engine(
    args: &InvestigateArgs,
    collectors: Vec<Arc<dyn Collector>>,
) -> anyhow::Result<Engine> {
    let investigation_timeout = Duration::from_secs(args.timeout);
    let config = EngineConfig {
        investigation_timeout,
        source_timeout: MAX_SOURCE_TIMEOUT.min(investigation_timeout),
        ..EngineConfig::default()
    };
    let http = HttpClient::new(HttpConfig::default())?;
    let mut engine = Engine::new(http, Arc::new(SystemClock), config);
    for collector in collectors {
        engine.register(collector)?;
    }
    Ok(engine)
}

/// Runs an investigation and returns the rendered report.
pub(crate) async fn investigate(
    args: &InvestigateArgs,
    target: Indicator,
    collectors: Vec<Arc<dyn Collector>>,
) -> Result<String, AppError> {
    let engine = build_engine(args, collectors)?;
    let run = engine
        .investigate(target)
        .await
        .map_err(AppError::InvalidInput)?;
    // Correlation runs on the finished investigation, after every network
    // request: it is pure and performs no I/O.
    let correlation = args
        .correlate
        .then(|| sentinel_correlation::correlate(&run.investigation));
    let report = match (args.format, &correlation) {
        (Format::Table, None) => table::render(&run.investigation),
        (Format::Table, Some(c)) => table::render_correlated(&run.investigation, c),
        (Format::Json, None) => json::render(&run.investigation).map_err(anyhow::Error::from)?,
        (Format::Json, Some(c)) => {
            json::render_correlated(&run.investigation, c).map_err(anyhow::Error::from)?
        }
    };
    Ok(report)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use sentinel_collectors::DnsQueryError;
    use sentinel_collectors::dns::DnsLookupFuture;
    use sentinel_core::{DnsRecord, DnsRecordData, DnsRecordType};

    use super::*;

    /// Offline resolver for end-to-end tests of the CLI wiring. Counts
    /// every lookup.
    struct FakeResolver(
        HashMap<(&'static str, DnsRecordType), Vec<DnsRecordData>>,
        Arc<AtomicUsize>,
    );

    impl DnsResolver for FakeResolver {
        fn description(&self) -> &'static str {
            "fake"
        }
        fn lookup<'a>(&'a self, name: &'a str, record_type: DnsRecordType) -> DnsLookupFuture<'a> {
            self.1.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                self.0
                    .iter()
                    .find(|((n, t), _)| *n == name && *t == record_type)
                    .map(|(_, data)| {
                        data.iter()
                            .cloned()
                            .map(|d| DnsRecord::new(name, 60, d))
                            .collect()
                    })
                    .ok_or(DnsQueryError::NoRecords)
            })
        }
    }

    fn resolver() -> Arc<dyn DnsResolver> {
        counting_resolver(Arc::new(AtomicUsize::new(0)))
    }

    fn counting_resolver(lookups: Arc<AtomicUsize>) -> Arc<dyn DnsResolver> {
        let mut answers = HashMap::new();
        answers.insert(
            ("example.com", DnsRecordType::A),
            vec![DnsRecordData::A {
                address: "93.184.215.14".parse().unwrap(),
            }],
        );
        answers.insert(
            ("example.com", DnsRecordType::Txt),
            vec![DnsRecordData::Txt {
                text: "v=spf1 ~all".into(),
            }],
        );
        answers.insert(
            ("_dmarc.example.com", DnsRecordType::Txt),
            vec![DnsRecordData::Txt {
                text: "v=DMARC1; p=none".into(),
            }],
        );
        for (name, text) in [
            (
                "14.215.184.93.origin.asn.cymru.com",
                "15133 | 93.184.215.0/24 | US | ripencc | 2008-06-02",
            ),
            (
                "8.8.8.8.origin.asn.cymru.com",
                "15169 | 8.8.8.0/24 | US | arin | 2023-12-28",
            ),
            (
                "AS15133.asn.cymru.com",
                "15133 | US | arin | 2007-03-19 | EDGECAST, US",
            ),
            (
                "AS15169.asn.cymru.com",
                "15169 | US | arin | 2000-03-30 | GOOGLE, US",
            ),
        ] {
            answers.insert(
                (name, DnsRecordType::Txt),
                vec![DnsRecordData::Txt { text: text.into() }],
            );
        }
        Arc::new(FakeResolver(answers, lookups))
    }

    fn args(domain: Option<&str>, ip: Option<&str>, format: Format) -> InvestigateArgs {
        InvestigateArgs {
            domain: domain.map(str::to_owned),
            ip: ip.map(str::to_owned),
            hash: None,
            format,
            output: None,
            timeout: 30,
            correlate: false,
        }
    }

    /// DNS and ASN with the offline resolver. CT and RDAP are left out: their
    /// real endpoints live on the internet (they are tested in
    /// sentinel-collectors against mock servers).
    fn offline_collectors() -> Vec<Arc<dyn Collector>> {
        let resolver = resolver();
        vec![
            Arc::new(DnsCollector::new(Arc::clone(&resolver))),
            Arc::new(CymruCollector::new(resolver)),
        ]
    }

    async fn run(args: &InvestigateArgs) -> String {
        let target = parse_target(args).unwrap();
        investigate(args, target, offline_collectors())
            .await
            .unwrap()
    }

    /// Offline collectors plus AbuseIPDB with the given key. AbuseIPDB is
    /// never contacted here: without a valid key it is unavailable.
    async fn run_with_abuseipdb(args: &InvestigateArgs, key: Option<&str>) -> String {
        let mut collectors = offline_collectors();
        collectors.push(Arc::new(AbuseIpDbCollector::new(
            key.map(secrecy::SecretString::from),
        )));
        investigate(args, parse_target(args).unwrap(), collectors)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn missing_or_invalid_key_is_reported_as_unavailable() {
        let table = run_with_abuseipdb(&args(None, Some("8.8.8.8"), Format::Table), None).await;
        assert!(
            table.contains(
                "abuseipdb  unavailable API key not configured (set SENTINEL_ABUSEIPDB_KEY)"
            ),
            "{table}"
        );
        assert!(
            !table.contains("ti.abuseipdb"),
            "no reputation findings without data"
        );
        assert!(
            table.contains("cymru      succeeded"),
            "other sources keep working"
        );

        let json = run_with_abuseipdb(
            &args(None, Some("8.8.8.8"), Format::Json),
            Some("bad key with spaces"),
        )
        .await;
        let doc: serde_json::Value = serde_json::from_str(&json).unwrap();
        let status = doc["investigation"]["sources"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["source"] == "abuseipdb")
            .unwrap()
            .clone();
        assert_eq!(status["status"], "unavailable");
        assert_eq!(status["reason"], "API key configuration is invalid");
        assert!(
            !json.contains("bad key with spaces"),
            "the configured value never appears"
        );
    }

    #[tokio::test]
    async fn correlation_adds_no_lookups_and_only_a_section() {
        let lookups = Arc::new(AtomicUsize::new(0));
        let run_with = |correlate: bool, format: Format| {
            let lookups = Arc::clone(&lookups);
            async move {
                let resolver = counting_resolver(Arc::clone(&lookups));
                let collectors: Vec<Arc<dyn Collector>> = vec![
                    Arc::new(DnsCollector::new(Arc::clone(&resolver))),
                    Arc::new(CymruCollector::new(resolver)),
                ];
                let mut a = args(Some("example.com"), None, format);
                a.correlate = correlate;
                let before = lookups.load(Ordering::SeqCst);
                let out = investigate(&a, parse_target(&a).unwrap(), collectors)
                    .await
                    .unwrap();
                (out, lookups.load(Ordering::SeqCst) - before)
            }
        };
        let (plain, plain_lookups) = run_with(false, Format::Table).await;
        let (correlated, correlated_lookups) = run_with(true, Format::Table).await;
        assert_eq!(
            plain_lookups, correlated_lookups,
            "correlation must not trigger DNS lookups"
        );
        assert!(!plain.contains("Correlation ("), "off by default");
        assert!(correlated.contains("Correlation ("), "{correlated}");
        assert!(correlated.contains("correlation.domain_ip_infrastructure"));
        assert!(correlated.contains("Link      example.com --resolves_to--> 93.184.215.14"));
        assert!(correlated.contains("Link      93.184.215.14 --announced_by--> AS15133"));
        assert!(correlated.contains("No registered network (registered_in) is recorded"));

        let (json, json_lookups) = run_with(true, Format::Json).await;
        assert_eq!(json_lookups, plain_lookups);
        let doc: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(
            doc["correlation"]["correlations"]
                .as_array()
                .is_some_and(|c| !c.is_empty())
        );
        let (plain_json, _) = run_with(false, Format::Json).await;
        let plain_doc: serde_json::Value = serde_json::from_str(&plain_json).unwrap();
        assert!(plain_doc.get("correlation").is_none());
    }

    #[tokio::test]
    async fn urlhaus_without_key_is_unavailable_never_no_results() {
        let mut collectors = offline_collectors();
        collectors.push(Arc::new(UrlhausCollector::new(None)));
        let args = args(Some("example.com"), None, Format::Table);
        let table = investigate(&args, parse_target(&args).unwrap(), collectors)
            .await
            .unwrap();
        assert!(
            table
                .contains("urlhaus  unavailable API key not configured (set SENTINEL_ABUSECH_KEY)"),
            "{table}"
        );
        assert!(!table.contains("ti.urlhaus"), "{table}");
    }

    #[tokio::test]
    async fn virustotal_without_key_is_unavailable_never_no_results() {
        let mut collectors = offline_collectors();
        collectors.push(Arc::new(VirusTotalCollector::new(None)));
        let args = args(Some("example.com"), None, Format::Table);
        let table = investigate(&args, parse_target(&args).unwrap(), collectors)
            .await
            .unwrap();
        assert!(
            table.contains(
                "virustotal  unavailable API key not configured (set SENTINEL_VIRUSTOTAL_KEY)"
            ),
            "{table}"
        );
        assert!(!table.contains("ti.virustotal"), "{table}");
    }

    #[tokio::test]
    async fn domain_without_key_still_enriches_infrastructure() {
        let table = run_with_abuseipdb(&args(Some("example.com"), None, Format::Table), None).await;
        assert!(table.contains("abuseipdb  unavailable"), "{table}");
        assert!(table.contains("93.184.215.14\n  ASN           AS15133"));
    }

    #[test]
    fn default_collectors_cover_every_source() {
        let ids: Vec<String> = default_collectors(&resolver(), Credentials::from_lookup(|_| None))
            .iter()
            .map(|c| c.id().to_string())
            .collect();
        assert_eq!(
            ids,
            vec![
                "dns",
                "ct",
                "cymru",
                "rdap",
                "abuseipdb",
                "virustotal",
                "urlhaus",
                "malwarebazaar"
            ]
        );
    }

    #[tokio::test]
    async fn domain_investigation_end_to_end_as_table() {
        let output = run(&args(Some("Example[.]COM"), None, Format::Table)).await;
        assert!(output.contains("Target:    example.com"));
        assert!(output.contains("A\n  93.184.215.14\n"));
        assert!(output.contains("dns.spf.softfail"));
        assert!(output.contains("dns.dmarc.policy_none"));
        assert!(output.contains("dns.caa.missing"));
        assert!(output.contains("dns    succeeded"));
    }

    #[tokio::test]
    async fn domain_investigation_end_to_end_as_json() {
        let output = run(&args(Some("example.com"), None, Format::Json)).await;
        let doc: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(doc["schema_version"], json::SCHEMA_VERSION);
        let inv = &doc["investigation"];
        assert_eq!(inv["target"]["value"], "example.com");
        assert_eq!(inv["sources"][0]["source"], "dns");
        assert_eq!(inv["sources"][0]["status"], "succeeded");
        let codes: Vec<&str> = inv["findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["code"].as_str().unwrap())
            .collect();
        assert_eq!(
            codes,
            vec![
                "dns.spf.softfail",
                "dns.dmarc.policy_none",
                "dns.dmarc.no_aggregate_reporting",
                "dns.caa.missing",
                "asn.origin"
            ]
        );
        assert_eq!(inv["relationships"][0]["kind"], "resolves_to");
    }

    #[tokio::test]
    async fn ip_investigation_end_to_end() {
        let output = run(&args(None, Some("8.8.8.8"), Format::Table)).await;
        assert!(output.contains("Type:      IPv4"));
        assert!(output.contains("8.8.8.8\n  ASN           AS15169  GOOGLE, US\n"));
        assert!(output.contains("asn.origin"));
        assert!(output.contains("cymru  succeeded"));

        let json = run(&args(None, Some("8.8.8.8"), Format::Json)).await;
        let doc: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            doc["investigation"]["relationships"][0]["kind"],
            "announced_by"
        );
    }

    #[tokio::test]
    async fn domain_investigation_pivots_to_asn() {
        let output = run(&args(Some("example.com"), None, Format::Table)).await;
        assert!(output.contains("\nInfrastructure\n"));
        assert!(output.contains("93.184.215.14\n  ASN           AS15133  EDGECAST, US\n"));
        assert!(output.contains("cymru  succeeded   2 observations   0.0 s   on 93.184.215.14"));
    }

    #[test]
    fn invalid_or_non_public_targets_are_rejected_before_any_io() {
        for (domain, ip) in [
            (Some("exa mple.com"), None),
            (Some("printer.local"), None),
            (Some("https://example.com/"), None),
            (None, Some("10.0.0.1")),
            (None, Some("169.254.169.254")),
            (None, Some("not-an-ip")),
        ] {
            assert!(
                parse_target(&args(domain, ip, Format::Table)).is_err(),
                "{domain:?} {ip:?}"
            );
        }
    }
}
