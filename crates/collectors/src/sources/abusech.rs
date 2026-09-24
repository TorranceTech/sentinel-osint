//! Field conventions shared by the abuse.ch APIs (URLhaus, MalwareBazaar):
//! short classification tokens, digit-string counts, `YYYY-MM-DD HH:MM:SS`
//! timestamps and bounded tag lists. One implementation, used by every
//! abuse.ch parser. Problems are reported through `issue`; values are
//! never invented or repaired.

use std::collections::BTreeSet;

use chrono::{DateTime, Datelike, NaiveDateTime, Utc};
use serde_json::{Map, Value};

use crate::sources::truncate_chars;

/// Tags kept per list.
pub(crate) const MAX_TAGS: usize = 32;
/// Characters kept per tag.
pub(crate) const MAX_TAG_CHARS: usize = 64;
/// Longest accepted classification token.
pub(crate) const MAX_TOKEN_CHARS: usize = 64;
/// Counts above this are treated as corrupt.
const MAX_PLAUSIBLE_COUNT: u64 = 1_000_000_000;

/// Short classification tokens only: letters, digits, `_`, `-`, `.`, `/`,
/// `+` and spaces (e.g. `malware_download`, `not listed`,
/// `application/x-dosexec`). No control, bidi or markup characters.
pub(crate) fn is_token(s: &str) -> bool {
    let s = s.trim();
    !s.is_empty()
        && s.chars().count() <= MAX_TOKEN_CHARS
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/' | '+' | ' '))
}

pub(crate) fn token(
    map: &Map<String, Value>,
    key: &str,
    required: bool,
    issue: &mut impl FnMut(&str),
) -> Option<String> {
    match map.get(key) {
        None | Some(Value::Null) => {
            if required {
                issue(&format!("{key} is missing"));
            }
            None
        }
        // `larted` is documented as "true or false" and shown as a string.
        Some(Value::Bool(b)) => Some(b.to_string()),
        Some(Value::String(s)) if is_token(s) => Some(s.trim().to_owned()),
        Some(Value::String(_)) => {
            issue(&format!("{key} is not a short token"));
            None
        }
        Some(_) => {
            issue(&format!("{key} has an unexpected type"));
            None
        }
    }
}

/// Counts are documented as strings of digits (e.g. `"120"`) or null.
pub(crate) fn count(value: Option<&Value>, key: &str, issue: &mut impl FnMut(&str)) -> Option<u64> {
    let parsed = match value {
        None | Some(Value::Null) => return None,
        Some(Value::Number(n)) => n.as_u64(),
        Some(Value::String(s)) if s.len() <= 12 && s.bytes().all(|b| b.is_ascii_digit()) => {
            s.parse().ok()
        }
        Some(_) => None,
    };
    match parsed {
        Some(n) if n <= MAX_PLAUSIBLE_COUNT => Some(n),
        Some(_) => {
            issue(&format!("{key} is out of range"));
            None
        }
        None => {
            issue(&format!("{key} is not a non-negative integer"));
            None
        }
    }
}

/// `YYYY-MM-DD HH:MM:SS UTC`. Fields documented as UTC also accept the
/// form without the suffix (`utc_documented`); others require it.
pub(crate) fn timestamp(
    map: &Map<String, Value>,
    key: &str,
    utc_documented: bool,
    issue: &mut impl FnMut(&str),
) -> Option<DateTime<Utc>> {
    let text = match map.get(key) {
        None | Some(Value::Null) => return None,
        Some(Value::String(s)) => s.trim(),
        Some(_) => {
            issue(&format!("{key} has an unexpected type"));
            return None;
        }
    };
    let bare = match text.strip_suffix(" UTC") {
        Some(bare) => bare,
        None if utc_documented => text,
        None => {
            issue(&format!("{key} has no explicit UTC time zone"));
            return None;
        }
    };
    match NaiveDateTime::parse_from_str(bare, "%Y-%m-%d %H:%M:%S") {
        Ok(at) if (1990..=9999).contains(&at.year()) => Some(at.and_utc()),
        Ok(_) => {
            issue(&format!("{key} is outside the plausible date range"));
            None
        }
        Err(_) => {
            issue(&format!("{key} is not a documented timestamp"));
            None
        }
    }
}

pub(crate) fn tags(value: Option<&Value>, what: &str, issue: &mut impl FnMut(&str)) -> Vec<String> {
    match value {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(items)) => {
            if items.len() > MAX_TAGS {
                issue("tags has too many entries; the rest were ignored");
            }
            let mut seen = BTreeSet::new();
            items
                .iter()
                .take(MAX_TAGS)
                .filter_map(|item| match item.as_str() {
                    Some(s) if !s.trim().is_empty() => {
                        let (kept, truncated) = truncate_chars(s.trim(), MAX_TAG_CHARS);
                        if truncated {
                            issue("a tag was truncated");
                        }
                        seen.insert(kept.clone()).then_some(kept)
                    }
                    Some(_) => None,
                    None => {
                        issue("a tag has an unexpected type");
                        None
                    }
                })
                .collect()
        }
        Some(_) => {
            issue(&format!("{what} has an unexpected type"));
            Vec::new()
        }
    }
}
