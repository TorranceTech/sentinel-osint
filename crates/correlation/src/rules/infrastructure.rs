//! C1: domain → IP (DNS) → origin AS (BGP) and registered network (RDAP).

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use sentinel_core::{Entity, IpPrefix, ObservationData, ObservationId, RelationKind, Relationship};

use super::{Emit, ip_of, joined, source_status_text};
use crate::index::EvidenceIndex;
use crate::model::{Conflict, CorrelationKind, Draft};

/// Routing and registration are context, not attribution.
pub const ROUTING_IS_NOT_OWNERSHIP: &str = "A BGP origin and a registry allocation describe routing and registration context; they do not establish who operates the address, ownership or intent.";
/// One answer listed several origin ASes.
pub const MOAS: &str = "An observation lists more than one origin AS for the address (multiple-origin announcement, common for anycast and CDNs); this is routing data, not a disagreement.";

pub(super) fn correlate(index: &EvidenceIndex<'_>, emit: &mut Emit) {
    for resolves in index.of_kind(RelationKind::ResolvesTo) {
        let ip_entity = resolves.target();
        let Some(ip) = ip_of(ip_entity) else { continue };
        let announced = index.from(RelationKind::AnnouncedBy, ip_entity);
        let registered = index.from(RelationKind::RegisteredIn, ip_entity);
        if announced.is_empty() && registered.is_empty() {
            continue;
        }

        let mut draft = Draft {
            limitations: vec![ROUTING_IS_NOT_OWNERSHIP.to_owned()],
            ..Draft::default()
        };
        draft.subjects.push(resolves.source().clone());
        draft.subjects.push(ip_entity.clone());
        draft.links.push(resolves.clone());
        for link in announced.iter().chain(&registered) {
            draft.subjects.push(link.target().clone());
            draft.links.push((*link).clone());
        }

        let asns = per_observation(&announced);
        let networks = per_observation(&registered);
        if asns.values().any(|set| set.len() > 1) {
            draft.limitations.push(MOAS.to_owned());
        }
        disagreement(
            &asns,
            &format!("Different observations report different origin ASes for {ip}"),
            &mut draft,
        );
        disagreement(
            &networks,
            &format!("Different observations report different registered networks for {ip}"),
            &mut draft,
        );
        containment(index, ip, &announced, &registered, &mut draft);

        let Entity::Indicator(ip_indicator) = ip_entity else {
            continue;
        };
        if announced.is_empty() {
            draft.gaps.push(format!(
                "No origin AS (announced_by) is recorded for {ip}{}.",
                source_status_text(index, ip_indicator)
            ));
        }
        if registered.is_empty() {
            draft.gaps.push(format!(
                "No registered network (registered_in) is recorded for {ip}{}.",
                source_status_text(index, ip_indicator)
            ));
        }

        let asn_text = targets(&announced);
        let net_text = targets(&registered);
        let mut parts = vec![format!("{} resolves to {ip} (DNS)", resolves.source())];
        if !asn_text.is_empty() {
            parts.push(format!("{ip} is announced by {asn_text} (BGP origin)"));
        }
        if !net_text.is_empty() {
            parts.push(format!("{ip} is registered in {net_text} (registry)"));
        }
        draft.summary = format!(
            "{}. Each link cites its own observations; nothing here is an ownership or maliciousness claim.",
            parts.join("; ")
        );
        emit.push(CorrelationKind::DomainIpInfrastructure, draft);
    }
}

/// The target entities each observation supports, per observation.
fn per_observation(links: &[&Relationship]) -> BTreeMap<ObservationId, BTreeSet<Entity>> {
    let mut map: BTreeMap<ObservationId, BTreeSet<Entity>> = BTreeMap::new();
    for link in links {
        for id in link.evidence() {
            map.entry(*id).or_default().insert(link.target().clone());
        }
    }
    map
}

/// Different observations naming different sets is a conflict.
fn disagreement(
    per_observation: &BTreeMap<ObservationId, BTreeSet<Entity>>,
    description: &str,
    draft: &mut Draft,
) {
    let distinct: BTreeSet<&BTreeSet<Entity>> = per_observation.values().collect();
    if distinct.len() > 1 {
        let sides: Vec<String> = distinct
            .iter()
            .map(|set| joined(set.iter().map(ToString::to_string)))
            .collect();
        draft.conflicts.push(Conflict {
            description: format!("{description}: {}.", sides.join(" vs. ")),
            evidence: per_observation.keys().copied().collect(),
        });
    }
}

/// Reported prefixes or ranges that do not contain the IP, and a routing
/// prefix that does not overlap any registered network.
fn containment(
    index: &EvidenceIndex<'_>,
    ip: IpAddr,
    announced: &[&Relationship],
    registered: &[&Relationship],
    draft: &mut Draft,
) {
    let evidence_of = |links: &[&Relationship]| -> BTreeSet<ObservationId> {
        links
            .iter()
            .flat_map(|l| l.evidence().iter().copied())
            .collect()
    };
    let mut bgp_prefixes: Vec<(IpPrefix, ObservationId)> = Vec::new();
    for id in evidence_of(announced) {
        let Some(observation) = index.observation(id) else {
            continue;
        };
        if let ObservationData::AsnOrigin(origin) = observation.data()
            && let Some(prefix) = origin.prefix
        {
            if prefix.contains(ip) {
                bgp_prefixes.push((prefix, id));
            } else {
                draft.conflicts.push(Conflict {
                    description: format!(
                        "The BGP prefix {prefix} reported for {ip} does not contain the address."
                    ),
                    evidence: vec![id],
                });
            }
        }
    }
    for id in evidence_of(registered) {
        let Some(observation) = index.observation(id) else {
            continue;
        };
        if let ObservationData::NetworkRegistration(network) = observation.data()
            && network.range_contains_queried_ip() == Some(false)
        {
            draft.conflicts.push(Conflict {
                description: format!(
                    "The registered range reported for {ip} does not contain the address."
                ),
                evidence: vec![id],
            });
        }
    }
    let registered_prefixes: Vec<(IpPrefix, &ObservationId)> = registered
        .iter()
        .filter_map(|l| match l.target() {
            Entity::Network(prefix) => l.evidence().first().map(|id| (*prefix, id)),
            _ => None,
        })
        .collect();
    for (bgp, bgp_id) in &bgp_prefixes {
        if !registered_prefixes.is_empty()
            && !registered_prefixes
                .iter()
                .any(|(net, _)| overlaps(*bgp, *net))
        {
            let mut evidence = vec![*bgp_id];
            evidence.extend(registered_prefixes.iter().map(|(_, id)| **id));
            draft.conflicts.push(Conflict {
                description: format!(
                    "The routing prefix {bgp} and the registered network(s) {} for {ip} do not overlap.",
                    joined(registered_prefixes.iter().map(|(n, _)| n.to_string()))
                ),
                evidence,
            });
        }
    }
}

/// Two prefixes overlap iff one contains the other's network address.
fn overlaps(a: IpPrefix, b: IpPrefix) -> bool {
    a.contains(b.network()) || b.contains(a.network())
}

fn targets(links: &[&Relationship]) -> String {
    let set: BTreeSet<String> = links.iter().map(|l| l.target().to_string()).collect();
    joined(set)
}
