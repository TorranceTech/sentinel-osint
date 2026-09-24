//! Findings: analytic judgments derived from observations.

use std::borrow::Cow;
use std::fmt;

use serde::Serialize;

use crate::confidence::Confidence;
use crate::evidence::ObservationId;

/// Severity of a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational; no action implied.
    Info,
    /// Low impact.
    Low,
    /// Medium impact.
    Medium,
    /// High impact.
    High,
}

impl Severity {
    /// Human-readable label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Info => "Info",
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Stable, machine-readable identifier of a kind of finding, such as
/// `dns.dmarc.missing`. Consumers (SIEM rules, future ATT&CK mapping) key on
/// the code, never on the human-readable title.
///
/// Lowercase ASCII letters, digits and `_`, in dot-separated segments.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct FindingCode(Cow<'static, str>);

impl FindingCode {
    /// Creates a code from a static string. An invalid code in a `const`
    /// item is a compile-time error.
    ///
    /// # Panics
    /// Panics if `code` is not a valid finding code.
    #[must_use]
    pub const fn from_static(code: &'static str) -> Self {
        assert!(is_valid_code(code), "invalid finding code");
        Self(Cow::Borrowed(code))
    }

    /// The code.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for FindingCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

const fn is_valid_code(code: &str) -> bool {
    let bytes = code.as_bytes();
    if bytes.is_empty() || bytes.len() > 64 {
        return false;
    }
    let mut previous_was_dot = true; // rejects a leading dot
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'.' {
            if previous_was_dot {
                return false;
            }
            previous_was_dot = true;
        } else if b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' {
            previous_was_dot = false;
        } else {
            return false;
        }
        i += 1;
    }
    !previous_was_dot // rejects a trailing dot
}

/// A security-relevant conclusion drawn from one or more observations.
///
/// Titles and details are written by Sentinel's analyzers, not copied from
/// sources. External values quoted in them should be kept minimal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    code: FindingCode,
    severity: Severity,
    title: String,
    detail: String,
    confidence: Confidence,
    evidence: Vec<ObservationId>,
}

impl Finding {
    /// Creates a finding without evidence. Attach evidence with
    /// [`Finding::with_evidence`].
    #[must_use]
    pub fn new(
        code: FindingCode,
        severity: Severity,
        title: impl Into<String>,
        detail: impl Into<String>,
        confidence: Confidence,
    ) -> Self {
        Self {
            code,
            severity,
            title: title.into(),
            detail: detail.into(),
            confidence,
            evidence: Vec::new(),
        }
    }

    /// Adds evidence (duplicates are ignored).
    #[must_use]
    pub fn with_evidence(mut self, evidence: impl IntoIterator<Item = ObservationId>) -> Self {
        for id in evidence {
            if !self.evidence.contains(&id) {
                self.evidence.push(id);
            }
        }
        self
    }

    /// Stable finding code.
    #[must_use]
    pub const fn code(&self) -> &FindingCode {
        &self.code
    }

    /// Severity.
    #[must_use]
    pub const fn severity(&self) -> Severity {
        self.severity
    }

    /// Short title.
    #[must_use]
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Explanation.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }

    /// Confidence in the finding.
    #[must_use]
    pub const fn confidence(&self) -> Confidence {
        self.confidence
    }

    /// Observations supporting the finding.
    #[must_use]
    pub fn evidence(&self) -> &[ObservationId] {
        &self.evidence
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_codes() {
        assert!(is_valid_code("dns.dmarc.missing"));
        assert!(is_valid_code("dns.spf.plus_all"));
        assert!(is_valid_code("ti"));
        for bad in [
            "", ".dns", "dns.", "dns..spf", "DNS.spf", "dns spf", "dns-spf",
        ] {
            assert!(!is_valid_code(bad), "{bad:?}");
        }
    }

    #[test]
    fn severity_ordering() {
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn evidence_is_deduplicated() {
        const CODE: FindingCode = FindingCode::from_static("dns.dmarc.policy_none");
        let id = ObservationId::new_random();
        let finding = Finding::new(
            CODE,
            Severity::Low,
            "DMARC policy is not enforced",
            "p=none only monitors; spoofed mail is still delivered.",
            Confidence::saturating(90),
        )
        .with_evidence([id, id]);
        assert_eq!(finding.evidence(), &[id]);
        assert_eq!(finding.code().as_str(), "dns.dmarc.policy_none");
    }
}
