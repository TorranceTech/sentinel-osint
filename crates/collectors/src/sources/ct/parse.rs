//! Parsing of crt.sh JSON responses.
//!
//! Observed format (a JSON array; checked on 2026-09-23):
//!
//! ```json
//! [{"issuer_ca_id": 413868, "issuer_name": "C=US, O=…, CN=…",
//!   "common_name": "example.com", "name_value": "*.example.com\nexample.com",
//!   "id": 28361996564, "not_before": "2026-07-29T22:10:08",
//!   "not_after": "2026-10-27T22:17:21",
//!   "serial_number": "0624d0ab311558780b7d5213b9631831", "result_count": 3}]
//! ```
//!
//! The body (size-capped by the HTTP client) is parsed into a
//! `serde_json::Value` (recursion-limited), then a fixed set of fields is
//! extracted with type, value and size checks. Invalid fields are left empty
//! and recorded as issues. Entries that are not objects are counted and skipped.

use chrono::{DateTime, Datelike, NaiveDateTime, TimeDelta, Utc};
use serde_json::{Map, Value};

use crate::sources::truncate_chars;

/// Array entries examined.
pub(crate) const MAX_ENTRIES: usize = 5000;
/// Name lines examined per entry.
pub(crate) const MAX_NAME_LINES: usize = 200;
const MAX_ISSUER: usize = 512;
const MAX_COMMON_NAME: usize = 256;
const MAX_SERIAL_HEX: usize = 64;
/// Longer validity periods are flagged as implausible.
const MAX_PLAUSIBLE_VALIDITY_DAYS: i64 = 100 * 366;

/// One entry, validated but not yet classified or deduplicated.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct Entry {
    pub(crate) id: Option<u64>,
    pub(crate) issuer: Option<String>,
    pub(crate) common_name: Option<String>,
    pub(crate) names: Vec<String>,
    pub(crate) not_before: Option<DateTime<Utc>>,
    pub(crate) not_after: Option<DateTime<Utc>>,
    pub(crate) serial_number: Option<String>,
    pub(crate) issues: Vec<String>,
}

impl Entry {
    fn issue(&mut self, issue: &str) {
        if !self.issues.iter().any(|i| i == issue) {
            self.issues.push(issue.to_owned());
        }
    }
}

/// The parsed response.
#[derive(Debug, Default)]
pub(crate) struct Parsed {
    pub(crate) entries: Vec<Entry>,
    /// Array length as received.
    pub(crate) total: usize,
    /// Entries that were not JSON objects.
    pub(crate) invalid: usize,
}

/// Parses a crt.sh JSON response.
///
/// # Errors
/// A fixed description if the body is not a JSON array.
pub(crate) fn parse_response(body: &[u8]) -> Result<Parsed, &'static str> {
    let document: Value =
        serde_json::from_slice(body).map_err(|_| "CT response is not valid JSON")?;
    let items = document
        .as_array()
        .ok_or("CT response is not a JSON array")?;
    let mut parsed = Parsed {
        total: items.len(),
        ..Parsed::default()
    };
    for item in items.iter().take(MAX_ENTRIES) {
        match item.as_object() {
            Some(object) => parsed.entries.push(parse_entry(object)),
            None => parsed.invalid += 1,
        }
    }
    Ok(parsed)
}

fn parse_entry(object: &Map<String, Value>) -> Entry {
    let mut entry = Entry::default();

    entry.id = match object.get("id") {
        None | Some(Value::Null) => None,
        Some(value) => value.as_u64().or_else(|| {
            entry.issue("id is not a non-negative integer");
            None
        }),
    };
    entry.issuer = text(object, "issuer_name", MAX_ISSUER, &mut entry);
    entry.common_name = text(object, "common_name", MAX_COMMON_NAME, &mut entry);
    entry.serial_number =
        text(object, "serial_number", MAX_SERIAL_HEX + 1, &mut entry).and_then(|serial| {
            let serial = serial.to_ascii_lowercase();
            if serial.len() <= MAX_SERIAL_HEX && serial.bytes().all(|b| b.is_ascii_hexdigit()) {
                Some(serial)
            } else {
                entry.issue("serial_number is not a hexadecimal serial");
                None
            }
        });

    match object.get("name_value") {
        None | Some(Value::Null) => entry.issue("name_value is missing"),
        Some(Value::String(names)) => {
            let lines: Vec<&str> = names.split('\n').filter(|l| !l.trim().is_empty()).collect();
            if lines.len() > MAX_NAME_LINES {
                entry.issue("too many names; the rest were ignored");
            }
            entry.names = lines
                .into_iter()
                .take(MAX_NAME_LINES)
                .map(str::to_owned)
                .collect();
        }
        Some(_) => entry.issue("name_value has an unexpected type"),
    }

    entry.not_before = timestamp(object, "not_before", &mut entry);
    entry.not_after = timestamp(object, "not_after", &mut entry);
    if let (Some(start), Some(end)) = (entry.not_before, entry.not_after) {
        if end < start {
            entry.issue("not_after is before not_before");
        } else if end - start > TimeDelta::days(MAX_PLAUSIBLE_VALIDITY_DAYS) {
            entry.issue("validity period is implausibly long");
        }
    }
    entry
}

fn text(object: &Map<String, Value>, key: &str, max: usize, entry: &mut Entry) -> Option<String> {
    match object.get(key) {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) if value.trim().is_empty() => None,
        Some(Value::String(value)) => {
            let (kept, truncated) = truncate_chars(value.trim(), max);
            if truncated {
                entry.issue(&format!("{key} was truncated"));
            }
            Some(kept)
        }
        Some(_) => {
            entry.issue(&format!("{key} has an unexpected type"));
            None
        }
    }
}

/// crt.sh returns `YYYY-MM-DDTHH:MM:SS` without an offset. These are
/// interpreted as UTC. RFC 3339 values with an offset are also accepted.
fn timestamp(object: &Map<String, Value>, key: &str, entry: &mut Entry) -> Option<DateTime<Utc>> {
    let value = match object.get(key) {
        None | Some(Value::Null) => return None,
        Some(Value::String(value)) => value.trim(),
        Some(_) => {
            entry.issue(&format!("{key} has an unexpected type"));
            return None;
        }
    };
    let parsed = DateTime::parse_from_rfc3339(value)
        .map(|d| d.with_timezone(&Utc))
        .ok()
        .or_else(|| {
            NaiveDateTime::parse_from_str(value, "%Y-%m-%dT%H:%M:%S%.f")
                .ok()
                .map(|naive| naive.and_utc())
        });
    match parsed {
        Some(date) if (1970..=9999).contains(&date.year()) => Some(date),
        Some(_) => {
            entry.issue(&format!("{key} is outside the plausible date range"));
            None
        }
        None => {
            entry.issue(&format!("{key} is not a valid timestamp"));
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_observed_format() {
        let body = br#"[{"issuer_ca_id": 413868, "issuer_name": "C=US, O=SSL Corporation, CN=Cloudflare TLS Issuing ECC CA 3",
            "common_name": "example.com", "name_value": "*.example.com\nexample.com", "id": 28361996564,
            "not_before": "2026-07-29T22:10:08", "not_after": "2026-10-27T22:17:21",
            "serial_number": "0624D0AB311558780B7D5213B9631831", "result_count": 3}]"#;
        let parsed = parse_response(body).unwrap();
        let e = &parsed.entries[0];
        assert_eq!(e.id, Some(28_361_996_564));
        assert_eq!(e.names, vec!["*.example.com", "example.com"]);
        assert_eq!(
            e.serial_number.as_deref(),
            Some("0624d0ab311558780b7d5213b9631831")
        );
        assert_eq!(
            e.not_before.unwrap().to_rfc3339(),
            "2026-07-29T22:10:08+00:00"
        );
        assert!(e.issues.is_empty(), "{:?}", e.issues);
    }

    #[test]
    fn timestamps_with_offsets_fractions_and_bad_values() {
        let body = br#"[
            {"name_value": "a.example.com", "not_before": "2026-01-01T10:00:00+02:00", "not_after": "2026-06-01T00:00:00.123"},
            {"name_value": "a.example.com", "not_before": "yesterday", "not_after": 17},
            {"name_value": "a.example.com", "not_before": "1900-01-01T00:00:00", "not_after": "2026-01-01T00:00:00"},
            {"name_value": "a.example.com", "not_before": "2026-01-01T00:00:00", "not_after": "2025-01-01T00:00:00"},
            {"name_value": "a.example.com", "not_before": "2000-01-01T00:00:00", "not_after": "9999-12-31T23:59:59"}
        ]"#;
        let entries = parse_response(body).unwrap().entries;
        assert_eq!(
            entries[0].not_before.unwrap().to_rfc3339(),
            "2026-01-01T08:00:00+00:00"
        );
        assert!(entries[0].not_after.is_some());
        assert!(entries[0].issues.is_empty());
        assert_eq!(
            entries[1].issues,
            vec![
                "not_before is not a valid timestamp",
                "not_after has an unexpected type"
            ]
        );
        assert_eq!(
            entries[2].issues,
            vec!["not_before is outside the plausible date range"]
        );
        assert_eq!(entries[3].issues, vec!["not_after is before not_before"]);
        assert_eq!(
            entries[4].issues,
            vec!["validity period is implausibly long"]
        );
    }

    #[test]
    fn wrong_types_nulls_and_missing_fields() {
        let body = br#"[{"id": -5, "issuer_name": 42, "common_name": null, "name_value": ["x"], "serial_number": "zz"}, 7, "str", null, {}]"#;
        let parsed = parse_response(body).unwrap();
        assert_eq!(parsed.total, 5);
        assert_eq!(parsed.invalid, 3);
        let e = &parsed.entries[0];
        assert_eq!(
            (
                e.id,
                e.issuer.clone(),
                e.common_name.clone(),
                e.serial_number.clone()
            ),
            (None, None, None, None)
        );
        for expected in [
            "id is not a non-negative integer",
            "issuer_name has an unexpected type",
            "name_value has an unexpected type",
            "serial_number is not a hexadecimal serial",
        ] {
            assert!(
                e.issues.iter().any(|i| i == expected),
                "{expected}: {:?}",
                e.issues
            );
        }
        assert_eq!(parsed.entries[1].issues, vec!["name_value is missing"]);
    }

    #[test]
    fn rejects_non_arrays_and_deep_nesting() {
        for body in [
            "",
            "{",
            "{}",
            "null",
            "\"x\"",
            r#"{"error": "rate limited"}"#,
        ] {
            assert!(parse_response(body.as_bytes()).is_err(), "{body:?}");
        }
        let deep = format!("{}{}", "[".repeat(100_000), "]".repeat(100_000));
        assert!(parse_response(deep.as_bytes()).is_err());
        assert_eq!(parse_response(b"[]").unwrap().entries.len(), 0);
    }

    #[test]
    fn huge_arrays_and_strings_are_bounded() {
        let names: Vec<String> = (0..1000).map(|i| format!("n{i}.example.com")).collect();
        let big = format!(
            r#"{{"name_value": "{}", "issuer_name": "{}"}}"#,
            names.join("\\n"),
            "I".repeat(100_000)
        );
        let small = r#"{"name_value": "a.example.com"}"#;
        let mut items = vec![big.as_str()];
        items.extend(std::iter::repeat_n(small, MAX_ENTRIES + 9));
        let body = format!("[{}]", items.join(","));
        let parsed = parse_response(body.as_bytes()).unwrap();
        assert_eq!(parsed.total, MAX_ENTRIES + 10);
        assert_eq!(parsed.entries.len(), MAX_ENTRIES);
        let e = &parsed.entries[0];
        assert_eq!(e.names.len(), MAX_NAME_LINES);
        assert_eq!(e.issuer.as_ref().unwrap().chars().count(), MAX_ISSUER);
        assert!(
            e.issues
                .iter()
                .any(|i| i == "too many names; the rest were ignored")
        );
        assert!(e.issues.iter().any(|i| i == "issuer_name was truncated"));
    }
}
