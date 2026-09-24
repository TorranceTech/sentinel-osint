//! Human-readable table output.
//!
//! Plain text only: no colors, no terminal control sequences. Every value
//! that can carry external data goes through [`safe`], which replaces
//! control, escape and bidi characters and bounds the length. A hostile TXT
//! record cannot rewrite the analyst's terminal.
//!
//! Layout: header, DNS records, security analysis (SPF/DMARC/CAA status and
//! records: facts), findings (conclusions), correlation (only with
//! [`render_correlated`]), sources, evidence summary.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::net::IpAddr;

use sentinel_core::evidence::{is_dmarc_record, is_spf_record};
use sentinel_core::text::sanitize_single_line;
use sentinel_core::{
    Asn, AsnDescription, AsnOrigin, CtCertificate, DnsRecord, DnsRecordData, DnsRecordType,
    Finding, Indicator, Investigation, IpReputation, NameRelation, NetworkRegistration,
    NoRecordsReason, ObservationData, Provenance, ProviderListing, ProviderMetric,
    ProviderReputation, Severity, SourceOutcome, SourceStatus, TimeLimit,
};
use sentinel_correlation::CorrelationReport;

/// Width of section rules.
const RULE_WIDTH: usize = 60;
/// Column where wrapped finding text starts.
const DETAIL_INDENT: usize = 10;
/// Maximum line width for wrapped text.
const WRAP_WIDTH: usize = 78;
/// Maximum characters shown for a single value (the JSON has the full value).
const MAX_VALUE_CHARS: usize = 200;

/// Record types in display order.
const DISPLAY_ORDER: [DnsRecordType; 8] = [
    DnsRecordType::A,
    DnsRecordType::Aaaa,
    DnsRecordType::Cname,
    DnsRecordType::Mx,
    DnsRecordType::Ns,
    DnsRecordType::Soa,
    DnsRecordType::Txt,
    DnsRecordType::Caa,
];

/// Renders the investigation as plain text.
#[must_use]
pub fn render(investigation: &Investigation) -> String {
    render_parts(investigation, None)
}

/// Renders the investigation with a `Correlation` section.
#[must_use]
pub fn render_correlated(investigation: &Investigation, report: &CorrelationReport) -> String {
    render_parts(investigation, Some(report))
}

fn render_parts(investigation: &Investigation, correlation: Option<&CorrelationReport>) -> String {
    let mut out = String::new();
    let dns = DnsView::new(investigation);

    header(&mut out, investigation);
    if let Some(domain) = investigation.target().as_domain()
        && !dns.is_empty()
    {
        dns_section(&mut out, &dns, domain.as_str());
        security_section(&mut out, &dns, domain.as_str());
    }
    ct_section(&mut out, investigation);
    infrastructure_section(&mut out, investigation);
    threat_intelligence_section(&mut out, investigation);
    findings_section(&mut out, investigation.findings());
    if let Some(report) = correlation {
        crate::correlation::section(&mut out, investigation, report);
    }
    sources_section(&mut out, investigation);
    evidence_section(&mut out, investigation);
    out
}

/// Sanitizes and bounds a value that may contain external data.
pub(crate) fn safe(value: &str) -> String {
    sanitize_single_line(value, MAX_VALUE_CHARS)
}

pub(crate) fn section(out: &mut String, title: &str) {
    let _ = write!(out, "\n{title}\n{}\n", "─".repeat(RULE_WIDTH));
}

fn header(out: &mut String, investigation: &Investigation) {
    let target = investigation.target();
    let _ = writeln!(out, "Sentinel OSINT");
    let _ = writeln!(out, "Threat Intelligence Investigation");
    let _ = writeln!(out);
    let _ = writeln!(out, "Target:    {}", safe(&target.to_string()));
    let _ = writeln!(out, "Type:      {}", target.indicator_type().label());
    let _ = writeln!(
        out,
        "Started:   {}",
        investigation.started_at().format("%Y-%m-%d %H:%M:%S UTC")
    );
    if let Some(duration) = investigation.duration() {
        let _ = writeln!(out, "Duration:  {}", seconds(duration.num_milliseconds()));
    }
    let _ = writeln!(out, "ID:        {}", investigation.id());
}

#[allow(clippy::cast_precision_loss)] // Durations in ms are far below 2^52.
fn seconds(millis: i64) -> String {
    format!("{:.1} s", millis as f64 / 1000.0)
}

// ------------------------------------------------------------------- DNS

/// DNS observations grouped by (query name, record type), from provenance.
struct DnsView<'a> {
    queries: BTreeMap<(String, DnsRecordType), QueryView<'a>>,
}

#[derive(Default)]
struct QueryView<'a> {
    records: Vec<&'a DnsRecord>,
    empty: Option<NoRecordsReason>,
}

impl<'a> DnsView<'a> {
    fn new(investigation: &'a Investigation) -> Self {
        let mut queries: BTreeMap<(String, DnsRecordType), QueryView<'_>> = BTreeMap::new();
        for observation in investigation.observations() {
            let Provenance::Dns(provenance) = observation.provenance() else {
                continue;
            };
            let key = (provenance.query_name().to_owned(), provenance.record_type());
            match observation.data() {
                ObservationData::DnsRecord(record) => {
                    queries.entry(key).or_default().records.push(record);
                }
                ObservationData::DnsNoRecords(none) => {
                    queries.entry(key).or_default().empty = Some(none.reason());
                }
                _ => {}
            }
        }
        Self { queries }
    }

    fn is_empty(&self) -> bool {
        self.queries.is_empty()
    }

    fn get(&self, name: &str, record_type: DnsRecordType) -> Option<&QueryView<'a>> {
        self.queries.get(&(name.to_owned(), record_type))
    }
}

fn dns_section(out: &mut String, dns: &DnsView<'_>, domain: &str) {
    section(out, "DNS");
    for record_type in DISPLAY_ORDER {
        let _ = writeln!(out, "{record_type}");
        match dns.get(domain, record_type) {
            None => {
                let _ = writeln!(out, "  (not collected)");
            }
            Some(view) if view.records.is_empty() => {
                let reason = match view.empty {
                    Some(NoRecordsReason::NxDomain) => "(NXDOMAIN)",
                    _ => "(none)",
                };
                let _ = writeln!(out, "  {reason}");
            }
            Some(view) => {
                for record in &view.records {
                    let _ = writeln!(out, "  {}", record_value(record.data()));
                }
            }
        }
    }
}

fn record_value(data: &DnsRecordData) -> String {
    match data {
        DnsRecordData::A { address } => address.to_string(),
        DnsRecordData::Aaaa { address } => address.to_string(),
        DnsRecordData::Mx {
            preference,
            exchange,
        } if exchange.is_empty() => {
            format!("{preference} . (null MX)")
        }
        DnsRecordData::Mx {
            preference,
            exchange,
        } => format!("{preference} {}", safe(exchange)),
        DnsRecordData::Ns { nameserver } => safe(nameserver),
        DnsRecordData::Cname { target } => safe(target),
        DnsRecordData::Soa {
            mname,
            rname,
            serial,
            ..
        } => {
            format!("{} {} (serial {serial})", safe(mname), safe(rname))
        }
        DnsRecordData::Txt { text } => format!("\"{}\"", safe(text)),
        DnsRecordData::Caa {
            critical,
            tag,
            value,
        } => {
            format!(
                "{} {} \"{}\"",
                u8::from(*critical) * 128,
                safe(tag),
                safe(value)
            )
        }
    }
}

// ------------------------------------------------------ security analysis

/// Presence of a mechanism, from observations only (facts, not findings).
enum Status<'a> {
    Present(Vec<&'a DnsRecord>),
    NotFound,
    Unknown,
}

fn status<'a>(view: Option<&QueryView<'a>>, is_match: impl Fn(&DnsRecord) -> bool) -> Status<'a> {
    match view {
        None => Status::Unknown,
        Some(view) => {
            let matching: Vec<&DnsRecord> = view
                .records
                .iter()
                .copied()
                .filter(|r| is_match(r))
                .collect();
            if matching.is_empty() {
                Status::NotFound
            } else {
                Status::Present(matching)
            }
        }
    }
}

fn security_section(out: &mut String, dns: &DnsView<'_>, domain: &str) {
    section(out, "Security Analysis");
    let txt = |pred: fn(&str) -> bool| move |r: &DnsRecord| r.data().txt().is_some_and(pred);
    let dmarc_name = format!("_dmarc.{domain}");
    let rows = [
        (
            "SPF",
            status(dns.get(domain, DnsRecordType::Txt), txt(is_spf_record)),
        ),
        (
            "DMARC",
            status(
                dns.get(&dmarc_name, DnsRecordType::Txt),
                txt(is_dmarc_record),
            ),
        ),
        ("CAA", status(dns.get(domain, DnsRecordType::Caa), |_| true)),
    ];
    for (name, status) in rows {
        let _ = writeln!(out, "{name}");
        match status {
            Status::Unknown => {
                let _ = writeln!(out, "  Status:  Unknown (lookup failed or not performed)");
            }
            Status::NotFound => {
                let _ = writeln!(out, "  Status:  Not found");
            }
            Status::Present(records) => {
                let _ = writeln!(
                    out,
                    "  Status:  Present ({} record{})",
                    records.len(),
                    plural(records.len())
                );
                for record in records {
                    let _ = writeln!(out, "  Record:  {}", record_value(record.data()));
                }
            }
        }
    }
}

const fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

// ------------------------------------------------ certificate transparency

/// Related names listed before the list is cut (the JSON has all of them).
const MAX_LISTED_NAMES: usize = 50;

fn ct_section(out: &mut String, investigation: &Investigation) {
    let certificates: Vec<&CtCertificate> = investigation
        .observations()
        .iter()
        .filter_map(|o| match o.data() {
            ObservationData::CtCertificate(c) => Some(c),
            _ => None,
        })
        .collect();
    let empty_result = investigation
        .findings()
        .iter()
        .any(|f| f.code().as_str() == "ct.no_certificates");
    if certificates.is_empty() && !empty_result {
        return;
    }
    section(out, "Certificate Transparency");
    if certificates.is_empty() {
        let _ = writeln!(out, "  No certificates reported by the CT source.");
        return;
    }

    let entries: u32 = certificates.iter().map(|c| c.source_entries).sum();
    let mut related = BTreeSet::new();
    let mut wildcard = BTreeSet::new();
    let mut unrelated = BTreeSet::new();
    let mut invalid = 0usize;
    for name in certificates.iter().flat_map(|c| c.names.iter()) {
        match name.relation {
            NameRelation::Invalid => invalid += 1,
            NameRelation::Unrelated => {
                unrelated.insert(name.display_name());
            }
            _ => {
                if name.wildcard {
                    wildcard.insert(name.display_name());
                }
                related.insert(name.display_name());
            }
        }
    }
    let reference = investigation.started_at();
    let expired = certificates
        .iter()
        .filter(|c| c.is_expired_at(reference))
        .count();
    let first = certificates.iter().filter_map(|c| c.not_before).min();
    let last = certificates.iter().filter_map(|c| c.not_after).max();

    row(
        out,
        "Certificates",
        &format!("{} ({entries} log entries)", certificates.len()),
    );
    row(
        out,
        "Names",
        &format!(
            "{} related · {} wildcard · {} unrelated · {invalid} invalid",
            related.len(),
            wildcard.len(),
            unrelated.len()
        ),
    );
    if let (Some(first), Some(last)) = (first, last) {
        row(
            out,
            "Validity",
            &format!(
                "{} → {} · {expired} expired",
                first.format("%Y-%m-%d"),
                last.format("%Y-%m-%d")
            ),
        );
    }
    let _ = writeln!(
        out,
        "  Related names (observed in certificates, not verified to resolve)"
    );
    for name in related.iter().take(MAX_LISTED_NAMES) {
        let _ = writeln!(out, "    {}", safe(name));
    }
    if related.len() > MAX_LISTED_NAMES {
        let _ = writeln!(
            out,
            "    … and {} more (see --format json)",
            related.len() - MAX_LISTED_NAMES
        );
    }
}

// ---------------------------------------------------------- infrastructure

/// ASN and RDAP facts grouped by IP.
#[derive(Default)]
struct IpView<'a> {
    origins: Vec<&'a AsnOrigin>,
    not_announced: bool,
    network: Option<&'a NetworkRegistration>,
}

/// Label column width in the infrastructure section.
const LABEL_WIDTH: usize = 14;

fn infrastructure_section(out: &mut String, investigation: &Investigation) {
    let mut order: Vec<IpAddr> = Vec::new();
    let mut views: BTreeMap<IpAddr, IpView<'_>> = BTreeMap::new();
    let mut descriptions: BTreeMap<Asn, &AsnDescription> = BTreeMap::new();

    if let Some(ip) = investigation.target().as_ip() {
        order.push(ip);
        views.entry(ip).or_default();
    }
    for observation in investigation.observations() {
        let Some(ip) = observation.indicator().as_ip() else {
            continue;
        };
        let view = match observation.data() {
            ObservationData::AsnOrigin(_)
            | ObservationData::NetworkRegistration(_)
            | ObservationData::DnsNoRecords(_) => {
                if !order.contains(&ip) {
                    order.push(ip);
                }
                views.entry(ip).or_default()
            }
            ObservationData::AsnDescription(description) => {
                descriptions.entry(description.asn).or_insert(description);
                continue;
            }
            _ => continue,
        };
        match observation.data() {
            ObservationData::AsnOrigin(origin) => view.origins.push(origin),
            ObservationData::NetworkRegistration(network) => {
                view.network.get_or_insert(network);
            }
            ObservationData::DnsNoRecords(_) => view.not_announced = true,
            _ => {}
        }
    }
    if order.is_empty() {
        return;
    }

    section(out, "Infrastructure");
    for (i, ip) in order.iter().enumerate() {
        if i > 0 {
            let _ = writeln!(out);
        }
        let _ = writeln!(out, "{ip}");
        if let Some(view) = views.get(ip) {
            asn_rows(out, view, &descriptions);
            rdap_rows(out, view.network);
        }
    }
}

fn row(out: &mut String, label: &str, value: &str) {
    let _ = writeln!(out, "  {label:<LABEL_WIDTH$}{value}");
}

fn asn_rows(out: &mut String, view: &IpView<'_>, descriptions: &BTreeMap<Asn, &AsnDescription>) {
    if view.origins.is_empty() {
        let text = if view.not_announced {
            "(no BGP origin reported)"
        } else {
            "(not collected)"
        };
        row(out, "ASN", text);
        return;
    }
    for origin in &view.origins {
        if origin.asns.is_empty() {
            row(out, "ASN", "(unparsable answer)");
        }
        for asn in &origin.asns {
            let name = descriptions
                .get(asn)
                .and_then(|d| d.name.as_deref())
                .map_or(String::new(), |n| format!("  {}", safe(n)));
            row(out, "ASN", &format!("{asn}{name}"));
        }
        if let Some(prefix) = origin.prefix {
            row(out, "BGP prefix", &prefix.to_string());
        }
        let mut registry: Vec<String> = Vec::new();
        registry.extend(origin.registry.as_deref().map(safe));
        registry.extend(origin.country.as_deref().map(safe));
        registry.extend(origin.allocated.map(|d| format!("allocated {d}")));
        if !registry.is_empty() {
            row(out, "Registry", &registry.join(" · "));
        }
    }
}

fn rdap_rows(out: &mut String, network: Option<&NetworkRegistration>) {
    let Some(network) = network else {
        row(out, "Network", "(not collected)");
        return;
    };
    let name = match (&network.name, &network.handle) {
        (Some(name), Some(handle)) => format!("{} ({})", safe(name), safe(handle)),
        (Some(name), None) => safe(name),
        (None, Some(handle)) => safe(handle),
        (None, None) => "(unnamed)".to_owned(),
    };
    row(out, "Network", &name);
    if let (Some(start), Some(end)) = (network.start_address, network.end_address) {
        row(out, "Range", &format!("{start} – {end}"));
    }
    if !network.cidrs.is_empty() {
        let cidrs: Vec<String> = network.cidrs.iter().map(ToString::to_string).collect();
        row(out, "CIDR", &cidrs.join(", "));
    }
    if let Some(kind) = &network.network_type {
        row(out, "Type", &safe(kind));
    }
    if let Some(organization) = &network.organization {
        row(out, "Organization", &safe(organization));
    }
    if let Some(country) = &network.country {
        row(out, "Country", &safe(country));
    }
    let mut dates: Vec<String> = Vec::new();
    dates.extend(
        network
            .registered_at
            .map(|d| format!("registered {}", d.format("%Y-%m-%d"))),
    );
    dates.extend(
        network
            .last_changed_at
            .map(|d| format!("last changed {}", d.format("%Y-%m-%d"))),
    );
    if !dates.is_empty() {
        row(out, "Dates", &dates.join(" · "));
    }
    if let Some(email) = &network.abuse_email {
        row(out, "Abuse contact", &safe(email));
    }
}

// ---------------------------------------------------- threat intelligence

/// Provider claims, attributed and unranked. There is no Sentinel verdict,
/// score or color: the values are the provider's own.
fn threat_intelligence_section(out: &mut String, investigation: &Investigation) {
    let claims: Vec<_> = investigation
        .observations()
        .iter()
        .filter(|o| {
            matches!(
                o.data(),
                ObservationData::IpReputation(_)
                    | ObservationData::ProviderReputation(_)
                    | ObservationData::ProviderListing(_)
                    | ObservationData::ProviderNoRecord(_)
            )
        })
        .collect();
    if claims.is_empty() {
        return;
    }
    section(out, "Threat Intelligence");
    let _ = writeln!(
        out,
        "  Provider claims as reported; not verified or scored by Sentinel."
    );
    for observation in claims {
        let _ = writeln!(out);
        match observation.data() {
            ObservationData::IpReputation(reputation) => ip_reputation_rows(out, reputation),
            ObservationData::ProviderReputation(reputation) => {
                row(out, "Provider", &safe(&reputation.provider));
                row(
                    out,
                    "Indicator",
                    &safe(&observation.indicator().to_string()),
                );
                provider_reputation_rows(out, reputation);
            }
            ObservationData::ProviderListing(listing) => {
                row(out, "Provider", &safe(&listing.provider));
                row(
                    out,
                    "Indicator",
                    &safe(&observation.indicator().to_string()),
                );
                provider_listing_rows(out, listing);
            }
            ObservationData::ProviderNoRecord(absent) => {
                row(out, "Provider", &safe(&absent.provider));
                row(
                    out,
                    "Indicator",
                    &safe(&observation.indicator().to_string()),
                );
                row(out, "Record", "none (the provider has no record of it)");
            }
            _ => {}
        }
    }
}

fn metric_rows(out: &mut String, metrics: &[ProviderMetric]) {
    for metric in metrics {
        let value = metric.max.map_or_else(
            || metric.value.to_string(),
            |max| format!("{} / {max}", metric.value),
        );
        row(out, "Metric", &format!("{} = {value}", safe(&metric.name)));
    }
}

fn issue_rows(out: &mut String, issues: &[String]) {
    if !issues.is_empty() {
        row(out, "Issues", &format!("{} (see findings)", issues.len()));
    }
}

fn provider_listing_rows(out: &mut String, listing: &ProviderListing) {
    row(out, "Record", "listed in the provider's database");
    if let Some(id) = &listing.entry_id {
        row(out, "Entry", &safe(id));
    }
    for attribute in &listing.attributes {
        row(
            out,
            "Reported",
            &format!("{} = {}", safe(&attribute.name), safe(&attribute.value)),
        );
    }
    metric_rows(out, &listing.metrics);
    for date in &listing.dates {
        row(
            out,
            "Date",
            &format!(
                "{} = {}",
                safe(&date.name),
                date.at.format("%Y-%m-%d %H:%M UTC")
            ),
        );
    }
    if !listing.tags.is_empty() {
        row(out, "Tags", &safe(&listing.tags.join(", ")));
    }
    issue_rows(out, &listing.issues);
}

fn ip_reputation_rows(out: &mut String, reputation: &IpReputation) {
    let window = reputation
        .window_days
        .map_or_else(String::new, |d| format!(" (last {d} days)"));
    row(
        out,
        "Provider",
        &format!("{}{window}", safe(&reputation.provider)),
    );
    row(out, "IP", &reputation.queried_ip.to_string());
    metric_rows(out, &reputation.metrics);
    let last = reputation.last_reported_at.map_or_else(
        || "never / not in window".to_owned(),
        |t| t.format("%Y-%m-%d %H:%M UTC").to_string(),
    );
    row(out, "Last reported", &last);
    for (label, value) in [
        ("Usage type", &reputation.usage_type),
        ("ISP", &reputation.isp),
        ("Domain", &reputation.domain),
        ("Country", &reputation.country_code),
    ] {
        if let Some(value) = value {
            row(out, label, &safe(value));
        }
    }
    if let Some(source) = &reputation.context_source {
        row(out, "Context from", &safe(source));
    }
    issue_rows(out, &reputation.issues);
}

fn provider_reputation_rows(out: &mut String, reputation: &ProviderReputation) {
    metric_rows(out, &reputation.metrics);
    if let Some(score) = reputation.community_score {
        row(
            out,
            "Community",
            &format!("{score} (provider-defined score)"),
        );
    }
    let last = reputation.last_analysis_at.map_or_else(
        || "not reported".to_owned(),
        |t| t.format("%Y-%m-%d %H:%M UTC").to_string(),
    );
    row(out, "Last analysis", &last);
    if !reputation.tags.is_empty() {
        row(out, "Tags", &safe(&reputation.tags.join(", ")));
    }
    issue_rows(out, &reputation.issues);
}

// ---------------------------------------------------------------- findings

fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
        Severity::Info => "INFO",
    }
}

fn findings_section(out: &mut String, findings: &[Finding]) {
    section(out, &format!("Findings ({})", findings.len()));
    if findings.is_empty() {
        let _ = writeln!(out, "  No findings.");
        return;
    }
    let mut sorted: Vec<&Finding> = findings.iter().collect();
    // Most severe first; stable, so analyzer order is kept within a level.
    sorted.sort_by_key(|finding| std::cmp::Reverse(finding.severity()));
    for (i, finding) in sorted.iter().enumerate() {
        if i > 0 {
            let _ = writeln!(out);
        }
        let _ = writeln!(
            out,
            "  {:<width$}{}",
            severity_label(finding.severity()),
            safe(finding.code().as_str()),
            width = DETAIL_INDENT - 2
        );
        wrap(out, &safe(finding.title()));
        wrap(out, &sanitize_single_line(finding.detail(), 1000));
    }
}

/// Writes `text` word-wrapped at [`WRAP_WIDTH`], indented by [`DETAIL_INDENT`].
fn wrap(out: &mut String, text: &str) {
    let indent = " ".repeat(DETAIL_INDENT);
    let mut line = String::new();
    for word in text.split_whitespace() {
        if !line.is_empty()
            && DETAIL_INDENT + line.chars().count() + 1 + word.chars().count() > WRAP_WIDTH
        {
            let _ = writeln!(out, "{indent}{line}");
            line.clear();
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        let _ = writeln!(out, "{indent}{line}");
    }
}

// ----------------------------------------------------------------- sources

fn sources_section(out: &mut String, investigation: &Investigation) {
    section(out, "Sources");
    let statuses = investigation.sources();
    if statuses.is_empty() {
        let _ = writeln!(
            out,
            "  No source supports this indicator type yet. See docs/DATA-SOURCES.md."
        );
        return;
    }
    let width = statuses
        .iter()
        .map(|s| s.source().as_str().len())
        .max()
        .unwrap_or(0)
        + 2;
    for status in statuses {
        let (state, detail, errors) = describe(status);
        let mut line = format!("  {:<width$}{state:<12}{detail}", status.source().as_str());
        if status.indicator() != investigation.target() {
            let _ = write!(line, "   on {}", safe(&status.indicator().to_string()));
        }
        let _ = writeln!(out, "{}", line.trim_end());
        for error in errors {
            let _ = writeln!(out, "  {:<width$}  ! {}", "", safe(error));
        }
    }
}

fn describe(status: &SourceStatus) -> (&'static str, String, &[String]) {
    let took = seconds(status.duration().num_milliseconds());
    match status.outcome() {
        SourceOutcome::Succeeded { observations } => (
            "succeeded",
            format!(
                "{observations} observation{}   {took}",
                plural(*observations)
            ),
            &[],
        ),
        SourceOutcome::Partial {
            observations,
            errors,
        } => (
            "partial",
            format!(
                "{observations} observation{}   {took}",
                plural(*observations)
            ),
            errors.as_slice(),
        ),
        SourceOutcome::Unavailable { reason } => ("unavailable", safe(reason), &[]),
        SourceOutcome::BudgetExhausted { limit } => (
            "not run",
            format!("request budget of {limit} requests exhausted"),
            &[],
        ),
        SourceOutcome::Unsupported => (
            "unsupported",
            "no supported indicator in this investigation".to_owned(),
            &[],
        ),
        SourceOutcome::Failed { error } => ("failed", safe(error), &[]),
        SourceOutcome::TimedOut { limit } => (
            "timed out",
            match limit {
                TimeLimit::Source => "source timeout".to_owned(),
                TimeLimit::Investigation => "investigation deadline".to_owned(),
            },
            &[],
        ),
    }
}

// ---------------------------------------------------------------- evidence

fn evidence_section(out: &mut String, investigation: &Investigation) {
    section(out, "Evidence");
    let observations = investigation.observations();
    let digests = observations
        .iter()
        .filter(|o| o.raw_response_hash().is_some())
        .count();
    let _ = writeln!(
        out,
        "  Observations    {} ({digests} with response digest)",
        observations.len()
    );
    let _ = writeln!(
        out,
        "  Relationships   {}",
        investigation.relationships().len()
    );
    let pivots: Vec<&Indicator> = {
        let mut seen: Vec<&Indicator> = Vec::new();
        for status in investigation.sources() {
            if status.indicator() != investigation.target() && !seen.contains(&status.indicator()) {
                seen.push(status.indicator());
            }
        }
        seen
    };
    if !pivots.is_empty() {
        let _ = writeln!(out, "  Pivots          {}", pivots.len());
    }
    let _ = writeln!(
        out,
        "  Details         --format json (IDs, provenance, timestamps, digests)"
    );
}
