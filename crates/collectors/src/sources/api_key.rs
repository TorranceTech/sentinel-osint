//! API key handling shared by keyed providers.
//!
//! One implementation for every provider: the key is validated once, held
//! as a [`SecretString`], described only by its state in `Debug` output,
//! and scrubbed from any response text before it is stored.

use secrecy::{ExposeSecret, SecretString};

use crate::collector::Availability;

/// Longest accepted API key.
const MAX_KEY_LEN: usize = 256;

/// Issue recorded when a response echoed the key.
pub(crate) const ECHOED_KEY_ISSUE: &str = "response contained the API key; it was redacted";

/// Configuration state of a provider API key.
pub(crate) enum ApiKey {
    Missing,
    Invalid,
    Present(SecretString),
}

impl ApiKey {
    /// Classifies a configured value. The key is validated but never
    /// inspected otherwise.
    pub(crate) fn new(key: Option<SecretString>) -> Self {
        match key {
            None => Self::Missing,
            Some(secret) if is_valid_key(secret.expose_secret()) => Self::Present(secret),
            Some(_) => Self::Invalid,
        }
    }

    /// The only text used to describe the key (`Debug` of collectors).
    pub(crate) const fn state(&self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Invalid => "invalid",
            Self::Present(_) => "configured",
        }
    }

    /// Availability of a collector keyed by this key. `missing_reason`
    /// names the environment variable to set.
    pub(crate) const fn availability(&self, missing_reason: &'static str) -> Availability {
        match self {
            Self::Present(_) => Availability::Ready,
            Self::Missing => Availability::Unavailable {
                reason: missing_reason,
            },
            Self::Invalid => Availability::Unavailable {
                reason: "API key configuration is invalid",
            },
        }
    }
}

/// Header-safe, non-empty, bounded: printable ASCII without spaces.
fn is_valid_key(key: &str) -> bool {
    !key.is_empty() && key.len() <= MAX_KEY_LEN && key.bytes().all(|b| b.is_ascii_graphic())
}

/// A (misbehaving or malicious) endpoint could echo the key back in a text
/// field. Replaces it with `REDACTED` in every given field and reports
/// whether anything was redacted.
pub(crate) fn redact_echoed_key<'a>(
    key: &SecretString,
    fields: impl IntoIterator<Item = &'a mut String>,
) -> bool {
    let secret = key.expose_secret();
    let mut found = false;
    for value in fields {
        if value.contains(secret) {
            *value = value.replace(secret, "REDACTED");
            found = true;
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_states() {
        assert_eq!(ApiKey::new(None).state(), "missing");
        assert_eq!(
            ApiKey::new(Some(SecretString::from("abc123"))).state(),
            "configured"
        );
        let long = "k".repeat(MAX_KEY_LEN + 1);
        for bad in ["", " ", "a b", "line\nbreak", "tab\tkey", "ünïcode", &long] {
            assert_eq!(
                ApiKey::new(Some(SecretString::from(bad))).state(),
                "invalid",
                "{bad:?}"
            );
        }
        assert_eq!(
            ApiKey::new(None).availability("set X"),
            Availability::Unavailable { reason: "set X" }
        );
        assert_eq!(
            ApiKey::new(Some(SecretString::from("k"))).availability("set X"),
            Availability::Ready
        );
    }

    #[test]
    fn redaction() {
        let key = SecretString::from("SECRET");
        let mut a = "has SECRET twice: SECRET".to_owned();
        let mut b = "clean".to_owned();
        assert!(redact_echoed_key(&key, [&mut a, &mut b]));
        assert_eq!(a, "has REDACTED twice: REDACTED");
        assert_eq!(b, "clean");
        assert!(!redact_echoed_key(&key, [&mut b]));
    }
}
