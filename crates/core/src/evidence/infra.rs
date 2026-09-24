//! Infrastructure observations: IP → ASN (BGP origin) and RDAP registration.
//!
//! These are **facts reported by a source**, normalized into typed fields.
//! Fidelity rules:
//! - A field the source returned in an invalid form is left empty and the
//!   problem is recorded in `issues` (fixed texts, never source content).
//!   The value is never "repaired" into something the source did not say.
//! - Small responses (ASN TXT answers) keep the source text verbatim in
//!   `source_text`. Large ones (RDAP JSON) are covered by the observation's
//!   `raw_response_hash` instead of being stored.
//! - Free-text values (names, emails) are stored as received, bounded in
//!   length by the collector, and sanitized only when rendered.
//! - Personal data is not modeled: RDAP contacts are reduced to the
//!   registrant *organization* name and an abuse mailbox.

use std::net::IpAddr;

use chrono::NaiveDate;
use serde::Serialize;

use crate::entity::Asn;
use crate::net::IpPrefix;
use crate::time::Timestamp;

/// IP → origin AS mapping (e.g. Team Cymru `origin.asn.cymru.com`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AsnOrigin {
    /// The IP that was looked up.
    pub ip: IpAddr,
    /// Origin AS numbers announcing the covering route. More than one means
    /// the prefix is announced by multiple origins (MOAS).
    pub asns: Vec<Asn>,
    /// The BGP prefix covering the IP, if reported and valid.
    pub prefix: Option<IpPrefix>,
    /// Country code as reported by the source (ISO 3166 alpha-2), if valid.
    pub country: Option<String>,
    /// Regional Internet Registry as reported (e.g. `arin`, `ripencc`).
    pub registry: Option<String>,
    /// Allocation date as reported.
    pub allocated: Option<NaiveDate>,
    /// The answer exactly as received (bounded).
    pub source_text: String,
    /// Problems with the answer (fixed descriptions).
    pub issues: Vec<String>,
}

/// AS number → description (e.g. Team Cymru `AS<n>.asn.cymru.com`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AsnDescription {
    /// The AS number that was looked up.
    pub asn: Asn,
    /// The AS name as reported (bounded).
    pub name: Option<String>,
    /// Country code as reported, if valid.
    pub country: Option<String>,
    /// Registry as reported.
    pub registry: Option<String>,
    /// Allocation date as reported.
    pub allocated: Option<NaiveDate>,
    /// The answer exactly as received (bounded).
    pub source_text: String,
    /// Problems with the answer (fixed descriptions).
    pub issues: Vec<String>,
}

/// IP version as reported by RDAP (`ipVersion`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum IpVersion {
    /// `v4`
    V4,
    /// `v6`
    V6,
}

/// An RDAP "ip network" object (RFC 9083 §5.4), reduced to what is useful for
/// infrastructure intelligence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NetworkRegistration {
    /// The IP that was looked up.
    pub queried_ip: IpAddr,
    /// Registry handle, e.g. `NET-8-8-8-0-2`.
    pub handle: Option<String>,
    /// Network name, e.g. `GOGL`.
    pub name: Option<String>,
    /// Allocation type as reported, e.g. `DIRECT ALLOCATION`.
    pub network_type: Option<String>,
    /// Reported IP version.
    pub ip_version: Option<IpVersion>,
    /// First address of the registered range.
    pub start_address: Option<IpAddr>,
    /// Last address of the registered range.
    pub end_address: Option<IpAddr>,
    /// CIDR blocks of the range (`cidr0` extension), if reported and valid.
    pub cidrs: Vec<IpPrefix>,
    /// Handle of the parent network.
    pub parent_handle: Option<String>,
    /// Country code, if valid.
    pub country: Option<String>,
    /// Status values, e.g. `active`.
    pub status: Vec<String>,
    /// `registration` event.
    #[serde(serialize_with = "crate::time::serialize_opt")]
    pub registered_at: Option<Timestamp>,
    /// `last changed` event.
    #[serde(serialize_with = "crate::time::serialize_opt")]
    pub last_changed_at: Option<Timestamp>,
    /// Name of the registrant *organization* (never an individual's name).
    pub organization: Option<String>,
    /// Abuse mailbox of a non-individual abuse contact.
    pub abuse_email: Option<String>,
    /// Problems with the response (fixed descriptions).
    pub issues: Vec<String>,
}

impl NetworkRegistration {
    /// Whether the reported range (start–end) contains the queried IP.
    /// `None` if the range is not known.
    #[must_use]
    pub fn range_contains_queried_ip(&self) -> Option<bool> {
        let (start, end) = (self.start_address?, self.end_address?);
        Some(match (start, end, self.queried_ip) {
            (IpAddr::V4(s), IpAddr::V4(e), IpAddr::V4(ip)) => s <= ip && ip <= e,
            (IpAddr::V6(s), IpAddr::V6(e), IpAddr::V6(ip)) => s <= ip && ip <= e,
            _ => false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registration(start: &str, end: &str, ip: &str) -> NetworkRegistration {
        NetworkRegistration {
            queried_ip: ip.parse().unwrap(),
            handle: None,
            name: None,
            network_type: None,
            ip_version: None,
            start_address: Some(start.parse().unwrap()),
            end_address: Some(end.parse().unwrap()),
            cidrs: Vec::new(),
            parent_handle: None,
            country: None,
            status: Vec::new(),
            registered_at: None,
            last_changed_at: None,
            organization: None,
            abuse_email: None,
            issues: Vec::new(),
        }
    }

    #[test]
    fn range_containment() {
        assert_eq!(
            registration("8.8.8.0", "8.8.8.255", "8.8.8.8").range_contains_queried_ip(),
            Some(true)
        );
        assert_eq!(
            registration("8.8.8.0", "8.8.8.255", "8.8.9.1").range_contains_queried_ip(),
            Some(false)
        );
        assert_eq!(
            registration("2001:db8::", "2001:db8::ffff", "8.8.8.8").range_contains_queried_ip(),
            Some(false)
        );
        let mut unknown = registration("8.8.8.0", "8.8.8.255", "8.8.8.8");
        unknown.end_address = None;
        assert_eq!(unknown.range_contains_queried_ip(), None);
    }
}
