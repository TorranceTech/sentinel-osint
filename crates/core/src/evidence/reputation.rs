//! Threat-intelligence reputation observations.
//!
//! A reputation observation records **what a provider claims** about an
//! indicator ([`IpReputation`] for IP-only providers, [`ProviderReputation`]
//! for providers that cover several indicator types), or that the provider
//! has no record of it ([`ProviderNoRecord`]). Sentinel does not turn a claim
//! into a verdict of its own:
//!
//! - provider metrics keep the provider's name and meaning
//!   ([`ProviderMetric`]: e.g. `abuse_confidence_score` from `abuseipdb`).
//!   They are never merged into a Sentinel score;
//! - Sentinel's own [`Confidence`](crate::Confidence) on the observation
//!   expresses how reliably the response was captured and parsed. It is
//!   unrelated to the provider's metrics;
//! - there is no `malicious` flag.

use std::net::IpAddr;

use serde::Serialize;

use crate::time::Timestamp;

/// A numeric metric exactly as a provider defines it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProviderMetric {
    /// The provider's metric name, e.g. `abuse_confidence_score`.
    pub name: String,
    /// The value reported by the provider.
    pub value: u64,
    /// The provider's documented maximum, if the metric is bounded
    /// (e.g. 100 for a percentage).
    pub max: Option<u64>,
}

/// An IP reputation claim by one provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IpReputation {
    /// Provider identifier, e.g. `abuseipdb`.
    pub provider: String,
    /// The IP that was looked up.
    pub queried_ip: IpAddr,
    /// Look-back window the provider applied, in days, if the query set one.
    pub window_days: Option<u16>,
    /// Provider metrics (the provider owns their meaning).
    pub metrics: Vec<ProviderMetric>,
    /// When the IP was last reported to the provider.
    #[serde(serialize_with = "crate::time::serialize_opt")]
    pub last_reported_at: Option<Timestamp>,
    /// Provider's allow-list flag, when it reports one (may be unknown).
    pub is_allowlisted: Option<bool>,
    /// Provider's Tor flag, when it reports one.
    pub is_tor: Option<bool>,
    /// Usage type as reported (e.g. `Data Center/Web Hosting/Transit`).
    pub usage_type: Option<String>,
    /// ISP as reported.
    pub isp: Option<String>,
    /// Domain associated with the IP, as reported.
    pub domain: Option<String>,
    /// Country code as reported.
    pub country_code: Option<String>,
    /// Hostnames as reported (bounded).
    pub hostnames: Vec<String>,
    /// Where the provider says the context fields (usage type, ISP, domain,
    /// country) come from, e.g. `IPinfo` for `AbuseIPDB`.
    pub context_source: Option<String>,
    /// Problems with the response (fixed descriptions).
    pub issues: Vec<String>,
}

/// A reputation summary by one provider for any indicator type (the
/// observation's indicator is the subject).
///
/// Holds only the provider's aggregate figures, never per-engine or
/// per-user data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProviderReputation {
    /// Provider identifier, e.g. `virustotal`.
    pub provider: String,
    /// Provider metrics (the provider owns their meaning), e.g.
    /// `last_analysis_stats.malicious` from `virustotal`.
    pub metrics: Vec<ProviderMetric>,
    /// A signed community score as the provider defines it (for
    /// `virustotal`, its `reputation` attribute). Never a Sentinel score.
    pub community_score: Option<i64>,
    /// When the provider last analyzed the indicator, as reported.
    #[serde(serialize_with = "crate::time::serialize_opt")]
    pub last_analysis_at: Option<Timestamp>,
    /// Tags as reported (bounded).
    pub tags: Vec<String>,
    /// Problems with the response (fixed descriptions).
    pub issues: Vec<String>,
}

impl ProviderReputation {
    /// The value of a provider metric by name.
    #[must_use]
    pub fn metric(&self, name: &str) -> Option<u64> {
        self.metrics
            .iter()
            .find(|m| m.name == name)
            .map(|m| m.value)
    }
}

/// A classification exactly as a provider reports it, under the
/// provider's field name (e.g. `url_status = online` from `urlhaus`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProviderAttribute {
    /// The provider's field name, e.g. `threat` or `blacklists.surbl`.
    pub name: String,
    /// The value as reported (a bounded token).
    pub value: String,
}

/// A date reported by a provider, under the provider's field name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProviderDate {
    /// The provider's field name, e.g. `date_added`.
    pub name: String,
    /// The reported time, in UTC.
    #[serde(serialize_with = "crate::time::serialize")]
    pub at: Timestamp,
}

/// An entry of a provider's threat database that matches the indicator
/// (for example a URLhaus malware-URL or host entry).
///
/// Holds the provider's own classifications, counts and dates, never the
/// indicators, files or reporters listed in the entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProviderListing {
    /// Provider identifier, e.g. `urlhaus`.
    pub provider: String,
    /// The provider's identifier of the entry, if it has one.
    pub entry_id: Option<String>,
    /// Classifications as reported (a name may repeat, e.g. one per
    /// malware family).
    pub attributes: Vec<ProviderAttribute>,
    /// Counts as reported by the provider, or counted by Sentinel over the
    /// provider's returned list (documented per metric name).
    pub metrics: Vec<ProviderMetric>,
    /// Dates as reported, in UTC.
    pub dates: Vec<ProviderDate>,
    /// Tags as reported (bounded).
    pub tags: Vec<String>,
    /// Problems with the response (fixed descriptions).
    pub issues: Vec<String>,
}

impl ProviderListing {
    /// The values of a provider attribute by name, in order.
    pub fn attribute<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> {
        self.attributes
            .iter()
            .filter(move |a| a.name == name)
            .map(|a| a.value.as_str())
    }

    /// The value of a metric by name.
    #[must_use]
    pub fn metric(&self, name: &str) -> Option<u64> {
        self.metrics
            .iter()
            .find(|m| m.name == name)
            .map(|m| m.value)
    }

    /// A reported date by name.
    #[must_use]
    pub fn date(&self, name: &str) -> Option<Timestamp> {
        self.dates.iter().find(|d| d.name == name).map(|d| d.at)
    }
}

/// The provider answered that it has no record of the indicator (evidence
/// of absence from the provider's dataset, not of benign use).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProviderNoRecord {
    /// Provider identifier, e.g. `virustotal`.
    pub provider: String,
}

impl IpReputation {
    /// The value of a provider metric by name.
    #[must_use]
    pub fn metric(&self, name: &str) -> Option<u64> {
        self.metrics
            .iter()
            .find(|m| m.name == name)
            .map(|m| m.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_are_looked_up_by_provider_name() {
        let reputation = IpReputation {
            provider: "abuseipdb".into(),
            queried_ip: "8.8.8.8".parse().unwrap(),
            window_days: Some(90),
            metrics: vec![ProviderMetric {
                name: "abuse_confidence_score".into(),
                value: 0,
                max: Some(100),
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
        };
        assert_eq!(reputation.metric("abuse_confidence_score"), Some(0));
        assert_eq!(reputation.metric("total_reports"), None);
    }

    #[test]
    fn provider_listing_lookups_and_json_shape() {
        use chrono::TimeZone;
        let at = chrono::Utc
            .with_ymd_and_hms(2019, 1, 19, 1, 33, 26)
            .unwrap();
        let listing = ProviderListing {
            provider: "urlhaus".into(),
            entry_id: Some("105821".into()),
            attributes: vec![
                ProviderAttribute {
                    name: "payloads.signature".into(),
                    value: "Heodo".into(),
                },
                ProviderAttribute {
                    name: "payloads.signature".into(),
                    value: "Emotet".into(),
                },
            ],
            metrics: vec![],
            dates: vec![ProviderDate {
                name: "date_added".into(),
                at,
            }],
            tags: vec![],
            issues: vec![],
        };
        assert_eq!(
            listing.attribute("payloads.signature").collect::<Vec<_>>(),
            vec!["Heodo", "Emotet"]
        );
        assert_eq!(listing.date("date_added"), Some(at));
        assert_eq!(listing.date("last_online"), None);
        let json = serde_json::to_value(&listing).unwrap();
        assert_eq!(json["dates"][0]["at"], "2019-01-19T01:33:26.000Z");
        assert!(json.get("malicious").is_none(), "no verdict field");
    }

    #[test]
    fn provider_reputation_metrics_and_json_shape() {
        let reputation = ProviderReputation {
            provider: "virustotal".into(),
            metrics: vec![ProviderMetric {
                name: "last_analysis_stats.malicious".into(),
                value: 3,
                max: None,
            }],
            community_score: Some(-12),
            last_analysis_at: None,
            tags: vec![],
            issues: vec![],
        };
        assert_eq!(reputation.metric("last_analysis_stats.malicious"), Some(3));
        assert_eq!(reputation.metric("malicious"), None);
        let json = serde_json::to_value(&reputation).unwrap();
        assert_eq!(json["community_score"], -12);
        assert!(json["last_analysis_at"].is_null());
        assert!(json.get("malicious").is_none(), "no verdict field");
    }
}
