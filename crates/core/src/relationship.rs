//! Evidence-backed relationships between entities.

use std::fmt;

use serde::Serialize;

use crate::entity::{Entity, EntityType};
use crate::error::ModelError;
use crate::evidence::ObservationId;

/// The kind of a relationship. Each kind is only valid between specific
/// entity types (see [`RelationKind::allows`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationKind {
    /// Domain → IP (A/AAAA record).
    ResolvesTo,
    /// Domain → domain (CNAME record): the source is an alias of the target.
    AliasOf,
    /// Domain → domain (MX record).
    HasMailExchanger,
    /// Domain → domain (NS record).
    HasNameserver,
    /// IP → autonomous system: the AS originates (announces in BGP) a route
    /// covering the IP. This is a routing fact, not ownership.
    AnnouncedBy,
    /// IP → network: a registry (RDAP) reports the IP inside this
    /// registered allocation.
    RegisteredIn,
    /// Certificate → domain: the certificate lists the name. Not evidence
    /// that the name resolves or that the certificate is deployed.
    CoversName,
    /// Certificate → domain: the certificate lists the wildcard `*.<domain>`.
    CoversWildcard,
}

impl RelationKind {
    /// Machine-readable identifier, same as the serialized form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ResolvesTo => "resolves_to",
            Self::AliasOf => "alias_of",
            Self::HasMailExchanger => "has_mail_exchanger",
            Self::HasNameserver => "has_nameserver",
            Self::AnnouncedBy => "announced_by",
            Self::RegisteredIn => "registered_in",
            Self::CoversName => "covers_name",
            Self::CoversWildcard => "covers_wildcard",
        }
    }

    /// Whether this kind may connect `source` to `target`.
    #[must_use]
    pub const fn allows(self, source: EntityType, target: EntityType) -> bool {
        match self {
            Self::ResolvesTo => matches!(source, EntityType::Domain) && target.is_ip(),
            Self::AliasOf | Self::HasMailExchanger | Self::HasNameserver => {
                matches!(source, EntityType::Domain) && matches!(target, EntityType::Domain)
            }
            Self::AnnouncedBy => source.is_ip() && matches!(target, EntityType::AutonomousSystem),
            Self::RegisteredIn => source.is_ip() && matches!(target, EntityType::Network),
            Self::CoversName | Self::CoversWildcard => {
                matches!(source, EntityType::Certificate) && matches!(target, EntityType::Domain)
            }
        }
    }
}

impl fmt::Display for RelationKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A directed, typed edge `source --kind--> target`, justified by at least
/// one observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Relationship {
    source: Entity,
    kind: RelationKind,
    target: Entity,
    evidence: Vec<ObservationId>,
}

impl Relationship {
    /// Creates a relationship.
    ///
    /// Duplicate evidence IDs are removed (first occurrence kept).
    ///
    /// # Errors
    /// - [`ModelError::InvalidRelationship`] if `kind` does not allow these
    ///   entity types (e.g. an IP that "resolves to" a domain).
    /// - [`ModelError::MissingEvidence`] if no evidence is given.
    pub fn new(
        source: impl Into<Entity>,
        kind: RelationKind,
        target: impl Into<Entity>,
        evidence: impl IntoIterator<Item = ObservationId>,
    ) -> Result<Self, ModelError> {
        let source = source.into();
        let target = target.into();
        if !kind.allows(source.entity_type(), target.entity_type()) {
            return Err(ModelError::InvalidRelationship {
                kind,
                source_type: source.entity_type(),
                target_type: target.entity_type(),
            });
        }
        let mut ids = Vec::new();
        for id in evidence {
            if !ids.contains(&id) {
                ids.push(id);
            }
        }
        if ids.is_empty() {
            return Err(ModelError::MissingEvidence);
        }
        Ok(Self {
            source,
            kind,
            target,
            evidence: ids,
        })
    }

    /// Source entity.
    #[must_use]
    pub const fn source(&self) -> &Entity {
        &self.source
    }

    /// Relationship kind.
    #[must_use]
    pub const fn kind(&self) -> RelationKind {
        self.kind
    }

    /// Target entity.
    #[must_use]
    pub const fn target(&self) -> &Entity {
        &self.target
    }

    /// Observations that justify this relationship.
    #[must_use]
    pub fn evidence(&self) -> &[ObservationId] {
        &self.evidence
    }

    /// Whether `other` describes the same edge (same source, kind, target).
    #[must_use]
    pub fn is_same_edge(&self, other: &Self) -> bool {
        self.kind == other.kind && self.source == other.source && self.target == other.target
    }

    /// Adds evidence from another relationship describing the same edge.
    pub(crate) fn merge_evidence(&mut self, other: &Self) {
        for id in &other.evidence {
            if !self.evidence.contains(id) {
                self.evidence.push(*id);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::Asn;
    use crate::indicator::Indicator;

    fn domain(s: &str) -> Indicator {
        Indicator::parse_domain(s).unwrap()
    }

    fn ip(s: &str) -> Indicator {
        Indicator::parse_ip(s).unwrap()
    }

    #[test]
    fn accepts_valid_relationships() {
        let e = ObservationId::new_random();
        assert!(
            Relationship::new(
                domain("example.com"),
                RelationKind::ResolvesTo,
                ip("8.8.8.8"),
                [e]
            )
            .is_ok()
        );
        assert!(
            Relationship::new(
                domain("example.com"),
                RelationKind::ResolvesTo,
                ip("2001:4860::1"),
                [e]
            )
            .is_ok()
        );
        assert!(
            Relationship::new(
                domain("example.com"),
                RelationKind::HasMailExchanger,
                domain("mx.example.com"),
                [e]
            )
            .is_ok()
        );
        assert!(
            Relationship::new(
                ip("8.8.8.8"),
                RelationKind::AnnouncedBy,
                Asn::new(15169).unwrap(),
                [e]
            )
            .is_ok()
        );
    }

    #[test]
    fn registered_in_connects_ips_to_networks_only() {
        let e = ObservationId::new_random();
        let net = crate::net::IpPrefix::parse("8.8.8.0/24").unwrap();
        assert!(Relationship::new(ip("8.8.8.8"), RelationKind::RegisteredIn, net, [e]).is_ok());
        assert!(
            Relationship::new(domain("example.com"), RelationKind::RegisteredIn, net, [e]).is_err()
        );
        assert!(Relationship::new(ip("8.8.8.8"), RelationKind::AnnouncedBy, net, [e]).is_err());
        assert_eq!(RelationKind::AnnouncedBy.as_str(), "announced_by");
        assert_eq!(RelationKind::RegisteredIn.as_str(), "registered_in");
    }

    #[test]
    fn certificate_relationships_connect_certificates_to_domains_only() {
        let e = ObservationId::new_random();
        let cert = crate::entity::CertificateId::new("crtsh", "1").unwrap();
        assert!(
            Relationship::new(
                cert.clone(),
                RelationKind::CoversName,
                domain("www.example.com"),
                [e]
            )
            .is_ok()
        );
        assert!(
            Relationship::new(
                cert.clone(),
                RelationKind::CoversWildcard,
                domain("example.com"),
                [e]
            )
            .is_ok()
        );
        assert!(Relationship::new(cert, RelationKind::CoversName, ip("8.8.8.8"), [e]).is_err());
        assert!(
            Relationship::new(
                domain("example.com"),
                RelationKind::CoversName,
                domain("www.example.com"),
                [e]
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_type_mismatches() {
        let e = ObservationId::new_random();
        let err = Relationship::new(
            ip("8.8.8.8"),
            RelationKind::ResolvesTo,
            domain("example.com"),
            [e],
        )
        .unwrap_err();
        assert_eq!(
            err,
            ModelError::InvalidRelationship {
                kind: RelationKind::ResolvesTo,
                source_type: EntityType::Ipv4,
                target_type: EntityType::Domain,
            }
        );
        assert!(
            Relationship::new(
                domain("example.com"),
                RelationKind::AnnouncedBy,
                Asn::new(1).unwrap(),
                [e]
            )
            .is_err()
        );
    }

    #[test]
    fn requires_evidence_and_deduplicates_it() {
        assert_eq!(
            Relationship::new(
                domain("example.com"),
                RelationKind::ResolvesTo,
                ip("8.8.8.8"),
                []
            ),
            Err(ModelError::MissingEvidence)
        );
        let e = ObservationId::new_random();
        let rel = Relationship::new(
            domain("example.com"),
            RelationKind::ResolvesTo,
            ip("8.8.8.8"),
            [e, e],
        )
        .unwrap();
        assert_eq!(rel.evidence(), &[e]);
    }
}
