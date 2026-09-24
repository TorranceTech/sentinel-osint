//! C3: several providers report on the same indicator.
//! C4: provider claims about the same indicator disagree.
//!
//! Providers are counted by source, never by observation. Claims are
//! listed side by side in the providers' own terms; nothing is combined.

use std::collections::{BTreeMap, BTreeSet};

use sentinel_core::text::sanitize_single_line;
use sentinel_core::{
    Indicator, IpReputation, Observation, ObservationData, ProviderListing, ProviderMetric,
    ProviderReputation, SourceId,
};

use super::{Emit, indicator_entity};
use crate::index::EvidenceIndex;
use crate::model::{Conflict, CorrelationKind, Draft, ProviderClaim, ProviderStance};

/// Each provider decides on its own.
pub const OWN_CLASSIFICATIONS: &str = "Each provider made its own classification with its own data and methods; the claims are listed, not combined, weighted or scored.";
/// Disagreement is not resolved.
pub const NOT_RESOLVED: &str = "Sentinel does not decide which provider is right; a disagreement is neither a verdict of maliciousness nor of benign use.";

const MAX_SUMMARY_CHARS: usize = 300;
/// `last_analysis_stats` counters that must all be known to read "does
/// not flag" from a VirusTotal-style report.
const ENGINE_COUNTERS: [&str; 5] = [
    "last_analysis_stats.malicious",
    "last_analysis_stats.suspicious",
    "last_analysis_stats.undetected",
    "last_analysis_stats.harmless",
    "last_analysis_stats.timeout",
];

pub(super) fn correlate(index: &EvidenceIndex<'_>, emit: &mut Emit) {
    for (indicator, observations) in index.by_indicator() {
        let claims: Vec<ProviderClaim> = observations.iter().filter_map(|o| claim(o)).collect();
        if claims.is_empty() {
            continue;
        }
        let providers: BTreeSet<&SourceId> = claims.iter().map(|c| &c.provider).collect();
        if providers.len() >= 2 {
            multiple_sources(indicator, &claims, providers.len(), emit);
        }
        disagreement(indicator, &claims, emit);
    }
}

fn multiple_sources(
    indicator: &Indicator,
    claims: &[ProviderClaim],
    providers: usize,
    emit: &mut Emit,
) {
    let listed: Vec<String> = claims
        .iter()
        .map(|c| format!("{} ({})", c.provider, c.stance.as_str()))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let draft = Draft {
        summary: format!(
            "{providers} providers report on {indicator}: {}. Each claim is the provider's own.",
            listed.join(", ")
        ),
        subjects: vec![indicator_entity(indicator)],
        claims: claims.to_vec(),
        limitations: vec![OWN_CLASSIFICATIONS.to_owned()],
        ..Draft::default()
    };
    emit.push(CorrelationKind::MultipleSources, draft);
}

fn disagreement(indicator: &Indicator, claims: &[ProviderClaim], emit: &mut Emit) {
    let mut conflicts = Vec::new();
    let flags: Vec<&ProviderClaim> = claims
        .iter()
        .filter(|c| c.stance == ProviderStance::Flags)
        .collect();
    let others: Vec<&ProviderClaim> = claims
        .iter()
        .filter(|c| {
            matches!(
                c.stance,
                ProviderStance::DoesNotFlag | ProviderStance::NoRecord
            )
        })
        .collect();
    let flag_providers: BTreeSet<&SourceId> = flags.iter().map(|c| &c.provider).collect();
    // Across providers: at least one provider flags, another does not.
    let across: Vec<&&ProviderClaim> = others
        .iter()
        .filter(|c| !flag_providers.contains(&c.provider))
        .collect();
    if !flags.is_empty() && !across.is_empty() {
        conflicts.push(Conflict {
            description: format!(
                "For {indicator}, {} report(s) something while {} do(es) not ({}).",
                names(&flag_providers),
                names(&across.iter().map(|c| &c.provider).collect()),
                across
                    .iter()
                    .map(|c| format!("{}: {}", c.provider, c.stance.as_str()))
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            evidence: flags
                .iter()
                .chain(across.iter().copied())
                .map(|c| c.observation)
                .collect(),
        });
    }
    // Within one provider: different answers in different observations.
    let mut per_provider: BTreeMap<&SourceId, BTreeSet<ProviderStance>> = BTreeMap::new();
    for claim in claims {
        if claim.stance != ProviderStance::Unclear {
            per_provider
                .entry(&claim.provider)
                .or_default()
                .insert(claim.stance);
        }
    }
    for (provider, stances) in &per_provider {
        if stances.len() > 1 {
            conflicts.push(Conflict {
                description: format!(
                    "{provider} answered differently for {indicator} in different observations ({}).",
                    stances
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                evidence: claims
                    .iter()
                    .filter(|c| &&c.provider == provider)
                    .map(|c| c.observation)
                    .collect(),
            });
        }
    }
    if conflicts.is_empty() {
        return;
    }
    let involved: BTreeSet<_> = conflicts
        .iter()
        .flat_map(|c| c.evidence.iter().copied())
        .collect();
    let draft = Draft {
        summary: format!(
            "Provider claims about {indicator} disagree; both sides are kept with their evidence."
        ),
        subjects: vec![indicator_entity(indicator)],
        claims: claims
            .iter()
            .filter(|c| involved.contains(&c.observation))
            .cloned()
            .collect(),
        conflicts,
        limitations: vec![OWN_CLASSIFICATIONS.to_owned(), NOT_RESOLVED.to_owned()],
        ..Draft::default()
    };
    emit.push(CorrelationKind::SourceDisagreement, draft);
}

fn names(providers: &BTreeSet<&SourceId>) -> String {
    providers
        .iter()
        .map(|p| p.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// A provider claim, if the observation is a reputation claim.
pub(crate) fn claim(observation: &Observation) -> Option<ProviderClaim> {
    let (stance, summary) = match observation.data() {
        ObservationData::IpReputation(r) => ip_reputation(r),
        ObservationData::ProviderReputation(r) => provider_reputation(r),
        ObservationData::ProviderListing(l) => provider_listing(l),
        ObservationData::ProviderNoRecord(_) => (ProviderStance::NoRecord, "no record".to_owned()),
        _ => return None,
    };
    Some(ProviderClaim {
        provider: observation.source().clone(),
        observation: observation.id(),
        stance,
        summary: sanitize_single_line(&summary, MAX_SUMMARY_CHARS),
        collected_at: observation.collected_at(),
    })
}

fn metrics(metrics: &[ProviderMetric]) -> Vec<String> {
    metrics
        .iter()
        .map(|m| match m.max {
            Some(max) => format!("{}={}/{max}", m.name, m.value),
            None => format!("{}={}", m.name, m.value),
        })
        .collect()
}

fn ip_reputation(r: &IpReputation) -> (ProviderStance, String) {
    let stance = match r.metric("total_reports") {
        Some(0) => ProviderStance::DoesNotFlag,
        Some(_) => ProviderStance::Flags,
        None => ProviderStance::Unclear,
    };
    (stance, metrics(&r.metrics).join(", "))
}

fn provider_reputation(r: &ProviderReputation) -> (ProviderStance, String) {
    let counters: Vec<Option<u64>> = ENGINE_COUNTERS.iter().map(|n| r.metric(n)).collect();
    let flagged = counters[0].unwrap_or(0) + counters[1].unwrap_or(0);
    let complete = counters.iter().all(Option::is_some);
    let engines: u64 = counters.iter().flatten().sum();
    let stance = if flagged > 0 {
        ProviderStance::Flags
    } else if complete && engines > 0 {
        ProviderStance::DoesNotFlag
    } else {
        ProviderStance::Unclear
    };
    let mut parts = metrics(&r.metrics);
    if let Some(score) = r.community_score {
        parts.push(format!("community_score={score}"));
    }
    (stance, parts.join(", "))
}

fn provider_listing(l: &ProviderListing) -> (ProviderStance, String) {
    let mut parts = vec!["listed".to_owned()];
    parts.extend(
        l.attributes
            .iter()
            .map(|a| format!("{}={}", a.name, a.value)),
    );
    parts.extend(metrics(&l.metrics));
    (ProviderStance::Flags, parts.join(", "))
}
