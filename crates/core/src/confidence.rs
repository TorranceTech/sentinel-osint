//! Confidence scores.
//!
//! Sentinel uses a 0–100 integer scale, the same scale as the STIX 2.1
//! `confidence` property. That way scores export to STIX without conversion.

use std::fmt;

use serde::{Deserialize, Serialize};

/// How confident a source or analysis is in a piece of information (0–100).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "u8", into = "u8")]
pub struct Confidence(u8);

impl Confidence {
    /// No confidence at all.
    pub const NONE: Self = Self(0);
    /// Full confidence, e.g. an authoritative DNS answer.
    pub const CERTAIN: Self = Self(100);

    /// Creates a confidence score, rejecting values above 100.
    ///
    /// # Errors
    /// Returns [`ConfidenceError`] if `value > 100`.
    pub const fn new(value: u8) -> Result<Self, ConfidenceError> {
        if value > 100 {
            Err(ConfidenceError(value))
        } else {
            Ok(Self(value))
        }
    }

    /// Creates a confidence score, clamping values above 100 to 100.
    #[must_use]
    pub const fn saturating(value: u8) -> Self {
        if value > 100 { Self(100) } else { Self(value) }
    }

    /// The numeric score (0–100).
    #[must_use]
    pub const fn value(self) -> u8 {
        self.0
    }

    /// The qualitative level of this score, following the STIX 2.1
    /// "None / Low / Med / High" scale (STIX 2.1, Appendix A).
    #[must_use]
    pub const fn level(self) -> ConfidenceLevel {
        match self.0 {
            0 => ConfidenceLevel::None,
            1..=29 => ConfidenceLevel::Low,
            30..=69 => ConfidenceLevel::Medium,
            _ => ConfidenceLevel::High,
        }
    }
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl TryFrom<u8> for Confidence {
    type Error = ConfidenceError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<Confidence> for u8 {
    fn from(value: Confidence) -> Self {
        value.0
    }
}

/// Qualitative confidence level (STIX 2.1 None/Low/Med/High scale).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidenceLevel {
    /// Score 0.
    None,
    /// Score 1–29.
    Low,
    /// Score 30–69.
    Medium,
    /// Score 70–100.
    High,
}

impl ConfidenceLevel {
    /// Human-readable label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::None => "None",
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
        }
    }
}

/// A confidence value outside the 0–100 range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("confidence must be between 0 and 100, got {0}")]
pub struct ConfidenceError(pub u8);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_values_above_100() {
        assert_eq!(Confidence::new(101), Err(ConfidenceError(101)));
        assert_eq!(Confidence::new(100).map(Confidence::value), Ok(100));
    }

    #[test]
    fn saturating_clamps() {
        assert_eq!(Confidence::saturating(250), Confidence::CERTAIN);
        assert_eq!(Confidence::saturating(42).value(), 42);
    }

    #[test]
    fn levels_follow_stix_scale() {
        assert_eq!(Confidence::saturating(0).level(), ConfidenceLevel::None);
        assert_eq!(Confidence::saturating(1).level(), ConfidenceLevel::Low);
        assert_eq!(Confidence::saturating(29).level(), ConfidenceLevel::Low);
        assert_eq!(Confidence::saturating(30).level(), ConfidenceLevel::Medium);
        assert_eq!(Confidence::saturating(69).level(), ConfidenceLevel::Medium);
        assert_eq!(Confidence::saturating(70).level(), ConfidenceLevel::High);
        assert_eq!(Confidence::saturating(100).level(), ConfidenceLevel::High);
    }

    #[test]
    fn ordering_allows_taking_the_minimum() {
        let weakest = [Confidence::saturating(90), Confidence::saturating(60)]
            .into_iter()
            .min();
        assert_eq!(weakest, Some(Confidence::saturating(60)));
    }
}
