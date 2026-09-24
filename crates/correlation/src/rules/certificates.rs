//! C2: certificates that list the investigated domain.
//! C5: related CT names that also appear in DNS data already collected.
//!
//! Only names the CT collector classified as related have `covers_*`
//! edges, so only those are considered. Nothing is resolved: a CT name
//! without DNS data stays without DNS data.

use std::collections::{BTreeMap, BTreeSet};

use sentinel_core::{
    DnsRecordData, DomainName, Entity, Indicator, ObservationData, ObservationId, RelationKind,
    Relationship,
};

use super::{Emit, MAX_LINKS, joined_bounded};
use crate::index::EvidenceIndex;
use crate::model::{CorrelationKind, Draft};

/// What a certificate does not show.
pub const CERTIFICATE_IS_NOT_PROOF: &str = "A certificate listing a name does not show that the name resolves, that the certificate is deployed, who controls the name, or anything about intent.";
/// CT names were not resolved.
pub const CT_NAMES_NOT_RESOLVED: &str = "Names seen only in Certificate Transparency were not resolved; correlation never performs DNS or HTTP requests.";

/// Certificate links listed per name in `ct_dns_names` (DNS links are
/// always all listed).
const CT_LINKS_PER_NAME: usize = 5;

const COVERS: [RelationKind; 2] = [RelationKind::CoversName, RelationKind::CoversWildcard];

pub(super) fn correlate(index: &EvidenceIndex<'_>, emit: &mut Emit) {
    let Indicator::Domain(target) = index.investigation().target() else {
        return;
    };
    domain_certificate(index, target, emit);
    ct_dns_names(index, target, emit);
}

fn domain_certificate(index: &EvidenceIndex<'_>, target: &DomainName, emit: &mut Emit) {
    let target_entity = Entity::Indicator(Indicator::Domain(target.clone()));
    let mut links: Vec<&Relationship> = COVERS
        .iter()
        .flat_map(|kind| index.to(*kind, &target_entity))
        .collect();
    if links.is_empty() {
        return;
    }
    let certificates: BTreeSet<&Entity> = links.iter().map(|l| l.source()).collect();
    let wildcard = links
        .iter()
        .filter(|l| l.kind() == RelationKind::CoversWildcard)
        .count();
    let mut draft = Draft {
        limitations: vec![CERTIFICATE_IS_NOT_PROOF.to_owned()],
        ..Draft::default()
    };
    links.sort_by(|a, b| (a.source(), a.kind()).cmp(&(b.source(), b.kind())));
    if links.len() > MAX_LINKS {
        draft.limitations.push(format!(
            "{} of {} certificate links are listed; the rest are in the investigation's relationships.",
            MAX_LINKS,
            links.len()
        ));
        links.truncate(MAX_LINKS);
    }
    draft.subjects.push(target_entity.clone());
    for link in &links {
        draft.subjects.push(link.source().clone());
        draft.links.push((*link).clone());
    }
    // The domain's own address records, when collected, as context.
    draft.supporting = index
        .observations_about(&Indicator::Domain(target.clone()))
        .iter()
        .filter(|o| {
            matches!(o.data(), ObservationData::DnsRecord(r)
                if matches!(r.data(), DnsRecordData::A { .. } | DnsRecordData::Aaaa { .. })
                    && r.name() == target.as_str())
        })
        .map(|o| o.id())
        .collect();
    let dns_note = if draft.supporting.is_empty() {
        String::new()
    } else {
        " The domain also has DNS address records in this investigation.".to_owned()
    };
    draft.summary = format!(
        "{} certificate(s) reported by Certificate Transparency list {target}{}.{dns_note}",
        certificates.len(),
        if wildcard > 0 {
            format!(" ({wildcard} as the wildcard *.{target})")
        } else {
            String::new()
        }
    );
    emit.push(CorrelationKind::DomainCertificate, draft);
}

/// Domain names that appear in DNS data (relationship endpoints of DNS
/// relationships and owner names of DNS records), with the DNS record
/// observations that name them.
fn dns_names(index: &EvidenceIndex<'_>) -> BTreeMap<DomainName, Vec<ObservationId>> {
    let mut names: BTreeMap<DomainName, Vec<ObservationId>> = BTreeMap::new();
    for kind in [
        RelationKind::ResolvesTo,
        RelationKind::AliasOf,
        RelationKind::HasMailExchanger,
        RelationKind::HasNameserver,
    ] {
        for link in index.of_kind(kind) {
            for entity in [link.source(), link.target()] {
                if let Entity::Indicator(Indicator::Domain(name)) = entity {
                    names.entry(name.clone()).or_default();
                }
            }
        }
    }
    for (_, observations) in index.by_indicator() {
        for observation in observations {
            if let ObservationData::DnsRecord(record) = observation.data()
                && let Ok(name) = DomainName::parse(record.name())
            {
                names.entry(name).or_default().push(observation.id());
            }
        }
    }
    names
}

fn ct_dns_names(index: &EvidenceIndex<'_>, target: &DomainName, emit: &mut Emit) {
    let mut ct_names: BTreeSet<&DomainName> = BTreeSet::new();
    for kind in COVERS {
        for link in index.of_kind(kind) {
            if let Entity::Indicator(Indicator::Domain(name)) = link.target()
                && name != target
                && name.is_subdomain_of(target)
            {
                ct_names.insert(name);
            }
        }
    }
    if ct_names.is_empty() {
        return;
    }
    let in_dns = dns_names(index);
    let shared: Vec<&DomainName> = ct_names
        .iter()
        .copied()
        .filter(|n| in_dns.contains_key(*n))
        .collect();
    if shared.is_empty() {
        return;
    }
    let mut draft = Draft {
        limitations: vec![
            CERTIFICATE_IS_NOT_PROOF.to_owned(),
            CT_NAMES_NOT_RESOLVED.to_owned(),
        ],
        ..Draft::default()
    };
    let ct_only = ct_names.len() - shared.len();
    if ct_only > 0 {
        draft.gaps.push(format!(
            "{ct_only} related name(s) seen in Certificate Transparency have no DNS data in this investigation; they were not resolved (by design)."
        ));
    }
    let mut sampled = false;
    for name in &shared {
        let entity = Entity::Indicator(Indicator::Domain((*name).clone()));
        draft.subjects.push(entity.clone());
        let mut ct_links: Vec<&Relationship> = COVERS
            .iter()
            .flat_map(|kind| index.to(*kind, &entity))
            .collect();
        if ct_links.len() > CT_LINKS_PER_NAME {
            sampled = true;
            ct_links.truncate(CT_LINKS_PER_NAME);
        }
        let dns_links = [
            RelationKind::ResolvesTo,
            RelationKind::AliasOf,
            RelationKind::HasMailExchanger,
            RelationKind::HasNameserver,
        ]
        .iter()
        .flat_map(|kind| {
            index
                .from(*kind, &entity)
                .into_iter()
                .chain(index.to(*kind, &entity))
        });
        for link in ct_links.into_iter().chain(dns_links) {
            draft.links.push(link.clone());
        }
        // DNS records whose owner name is this name.
        if let Some(records) = in_dns.get(*name) {
            draft.supporting.extend(records.iter().copied());
        }
    }
    if sampled {
        draft.limitations.push(format!(
            "At most {CT_LINKS_PER_NAME} certificate links are listed per name; every DNS link is listed. The rest are in the investigation's relationships."
        ));
    }
    draft.summary = format!(
        "{} name(s) under {target} appear both in Certificate Transparency and in DNS data already collected: {}.",
        shared.len(),
        joined_bounded(shared.iter().map(ToString::to_string))
    );
    emit.push(CorrelationKind::CtDnsNames, draft);
}
