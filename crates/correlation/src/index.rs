//! In-memory indexes over a finished investigation. Built once; every rule
//! reads them instead of scanning lists repeatedly. All maps are ordered,
//! so iteration order is deterministic.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use sentinel_core::{
    Entity, Indicator, Investigation, Observation, ObservationId, RelationKind, Relationship,
    SourceOutcome, SourceStatus,
};

/// Read-only indexes of one investigation.
pub struct EvidenceIndex<'a> {
    investigation: &'a Investigation,
    by_id: HashMap<ObservationId, &'a Observation>,
    duplicate_ids: usize,
    /// Relationships, one per edge, in a canonical order.
    relationships: Vec<&'a Relationship>,
    by_kind_source: BTreeMap<(RelationKind, Entity), Vec<usize>>,
    by_kind_target: BTreeMap<(RelationKind, Entity), Vec<usize>>,
    by_indicator: BTreeMap<&'a Indicator, Vec<&'a Observation>>,
    entities: BTreeSet<&'a Entity>,
    indicators: BTreeSet<Indicator>,
}

impl<'a> EvidenceIndex<'a> {
    /// Indexes `investigation`.
    #[must_use]
    pub fn new(investigation: &'a Investigation) -> Self {
        let mut by_id = HashMap::new();
        let mut duplicate_ids = 0;
        let mut by_indicator: BTreeMap<&Indicator, Vec<&Observation>> = BTreeMap::new();
        for observation in investigation.observations() {
            // Keep the first observation with an ID; later reuses are ignored.
            if by_id.contains_key(&observation.id()) {
                duplicate_ids += 1;
                continue;
            }
            by_id.insert(observation.id(), observation);
            by_indicator
                .entry(observation.indicator())
                .or_default()
                .push(observation);
        }
        for observations in by_indicator.values_mut() {
            observations.sort_by_key(|o| (o.source().clone(), o.collected_at(), o.id()));
        }

        let mut relationships: Vec<&Relationship> = investigation.relationships().iter().collect();
        relationships.sort_by(|a, b| {
            (a.kind(), a.source(), a.target()).cmp(&(b.kind(), b.source(), b.target()))
        });
        // The investigation merges identical edges; stay safe anyway.
        relationships.dedup_by(|a, b| a.is_same_edge(b));
        let mut by_kind_source: BTreeMap<(RelationKind, Entity), Vec<usize>> = BTreeMap::new();
        let mut by_kind_target: BTreeMap<(RelationKind, Entity), Vec<usize>> = BTreeMap::new();
        let mut entities = BTreeSet::new();
        for (i, relationship) in relationships.iter().enumerate() {
            by_kind_source
                .entry((relationship.kind(), relationship.source().clone()))
                .or_default()
                .push(i);
            by_kind_target
                .entry((relationship.kind(), relationship.target().clone()))
                .or_default()
                .push(i);
            entities.insert(relationship.source());
            entities.insert(relationship.target());
        }
        let mut indicators: BTreeSet<Indicator> =
            by_indicator.keys().map(|i| (*i).clone()).collect();
        indicators.insert(investigation.target().clone());

        Self {
            investigation,
            by_id,
            duplicate_ids,
            relationships,
            by_kind_source,
            by_kind_target,
            by_indicator,
            entities,
            indicators,
        }
    }

    /// The indexed investigation.
    #[must_use]
    pub const fn investigation(&self) -> &'a Investigation {
        self.investigation
    }

    /// An observation by ID.
    #[must_use]
    pub fn observation(&self, id: ObservationId) -> Option<&'a Observation> {
        self.by_id.get(&id).copied()
    }

    /// How many observations reused an ID already seen (ignored).
    #[must_use]
    pub const fn duplicate_ids(&self) -> usize {
        self.duplicate_ids
    }

    /// Whether `entity` appears in the investigation (target, observation
    /// subject or relationship endpoint).
    #[must_use]
    pub fn knows_entity(&self, entity: &Entity) -> bool {
        self.entities.contains(entity)
            || matches!(entity, Entity::Indicator(i) if self.indicators.contains(i))
    }

    /// Relationships of one kind, in canonical order.
    pub fn of_kind(&self, kind: RelationKind) -> impl Iterator<Item = &'a Relationship> + '_ {
        self.relationships
            .iter()
            .copied()
            .filter(move |r| r.kind() == kind)
    }

    /// Relationships of `kind` whose source is `entity`.
    #[must_use]
    pub fn from(&self, kind: RelationKind, entity: &Entity) -> Vec<&'a Relationship> {
        self.lookup(&self.by_kind_source, kind, entity)
    }

    /// Relationships of `kind` whose target is `entity`.
    #[must_use]
    pub fn to(&self, kind: RelationKind, entity: &Entity) -> Vec<&'a Relationship> {
        self.lookup(&self.by_kind_target, kind, entity)
    }

    fn lookup(
        &self,
        map: &BTreeMap<(RelationKind, Entity), Vec<usize>>,
        kind: RelationKind,
        entity: &Entity,
    ) -> Vec<&'a Relationship> {
        map.get(&(kind, entity.clone()))
            .map(|ids| ids.iter().map(|i| self.relationships[*i]).collect())
            .unwrap_or_default()
    }

    /// Observations about each indicator, grouped and ordered.
    pub fn by_indicator(
        &self,
    ) -> impl Iterator<Item = (&'a Indicator, &Vec<&'a Observation>)> + '_ {
        self.by_indicator.iter().map(|(i, o)| (*i, o))
    }

    /// Observations about one indicator.
    #[must_use]
    pub fn observations_about(&self, indicator: &Indicator) -> &[&'a Observation] {
        self.by_indicator.get(indicator).map_or(&[], Vec::as_slice)
    }

    /// Source runs against `indicator` that did not succeed.
    #[must_use]
    pub fn unsuccessful_sources(&self, indicator: &Indicator) -> Vec<&'a SourceStatus> {
        self.investigation
            .sources()
            .iter()
            .filter(|s| s.indicator() == indicator)
            .filter(|s| !matches!(s.outcome(), SourceOutcome::Succeeded { .. }))
            .collect()
    }
}
