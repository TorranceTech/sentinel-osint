//! C6: several indicators connect to the same AS, network, IP or
//! certificate. A shared element is a fact about the data, not evidence of
//! a common owner, operator or intent.

use std::collections::{BTreeMap, BTreeSet};

use sentinel_core::{Entity, RelationKind, Relationship};

use super::{Emit, joined_bounded};
use crate::index::EvidenceIndex;
use crate::model::{CorrelationKind, Draft};

/// What sharing does not mean.
pub const SHARING_IS_NOT_ATTRIBUTION: &str = "Shared hosting, CDNs, anycast, large providers and multi-domain certificates connect unrelated parties; a shared element does not imply a common owner, operator, actor, campaign or intent.";

/// Certificate groups reported at most (those listing the most names).
pub const MAX_CERTIFICATE_GROUPS: usize = 20;

pub(super) fn correlate(index: &EvidenceIndex<'_>, emit: &mut Emit) -> Option<String> {
    // Grouped by the shared element: the target of the edge, except for
    // certificates, which are the source of `covers_*` edges.
    for kind in [
        RelationKind::AnnouncedBy,
        RelationKind::RegisteredIn,
        RelationKind::ResolvesTo,
    ] {
        let mut groups: BTreeMap<&Entity, Vec<&Relationship>> = BTreeMap::new();
        for link in index.of_kind(kind) {
            groups.entry(link.target()).or_default().push(link);
        }
        for (shared, links) in groups {
            let members: BTreeSet<&Entity> = links.iter().map(|l| l.source()).collect();
            if members.len() >= 2 {
                emit_group(shared, kind, &members, &links, emit);
            }
        }
    }

    let mut certificates: BTreeMap<&Entity, Vec<&Relationship>> = BTreeMap::new();
    for kind in [RelationKind::CoversName, RelationKind::CoversWildcard] {
        for link in index.of_kind(kind) {
            certificates.entry(link.source()).or_default().push(link);
        }
    }
    let mut groups: Vec<(&Entity, Vec<&Relationship>, BTreeSet<&Entity>)> = certificates
        .into_iter()
        .map(|(cert, links)| {
            let names: BTreeSet<&Entity> = links.iter().map(|l| l.target()).collect();
            (cert, links, names)
        })
        .filter(|(_, _, names)| names.len() >= 2)
        .collect();
    // Most names first; ties by certificate, so the choice is deterministic.
    groups.sort_by(|a, b| b.2.len().cmp(&a.2.len()).then_with(|| a.0.cmp(b.0)));
    let total = groups.len();
    for (cert, links, names) in groups.into_iter().take(MAX_CERTIFICATE_GROUPS) {
        emit_group(cert, RelationKind::CoversName, &names, &links, emit);
    }
    (total > MAX_CERTIFICATE_GROUPS).then(|| {
        format!(
            "{MAX_CERTIFICATE_GROUPS} of {total} certificates listing several names are reported as shared infrastructure (those listing the most names)."
        )
    })
}

fn emit_group(
    shared: &Entity,
    kind: RelationKind,
    members: &BTreeSet<&Entity>,
    links: &[&Relationship],
    emit: &mut Emit,
) {
    let mut draft = Draft {
        limitations: vec![SHARING_IS_NOT_ATTRIBUTION.to_owned()],
        ..Draft::default()
    };
    draft.subjects.push(shared.clone());
    draft.subjects.extend(members.iter().map(|m| (*m).clone()));
    draft.links.extend(links.iter().map(|l| (*l).clone()));
    let listed = joined_bounded(members.iter().map(ToString::to_string));
    draft.summary = match kind {
        RelationKind::AnnouncedBy => format!(
            "{} addresses are announced by the same origin AS {shared}: {listed}.",
            members.len()
        ),
        RelationKind::RegisteredIn => format!(
            "{} addresses are registered in the same network {shared}: {listed}.",
            members.len()
        ),
        RelationKind::ResolvesTo => format!(
            "{} names resolve to the same address {shared}: {listed}.",
            members.len()
        ),
        _ => format!(
            "Certificate {shared} lists {} names: {listed}.",
            members.len()
        ),
    };
    emit.push(CorrelationKind::SharedInfrastructure, draft);
}
