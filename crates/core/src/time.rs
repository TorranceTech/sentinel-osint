//! Timestamps.
//!
//! All timestamps in the model are UTC. They are serialized as RFC 3339 with
//! millisecond precision and a `Z` suffix (for example
//! `2026-09-23T17:40:12.123Z`), which is also the format STIX 2.1 expects.

use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serializer;

/// A point in time, always in UTC.
pub type Timestamp = DateTime<Utc>;

/// Formats a timestamp as RFC 3339 with millisecond precision and a `Z` suffix.
#[must_use]
pub fn format_rfc3339(ts: &Timestamp) -> String {
    ts.to_rfc3339_opts(SecondsFormat::Millis, true)
}

pub(crate) fn serialize<S: Serializer>(ts: &Timestamp, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&format_rfc3339(ts))
}

// `serialize_with` hands us `&Option<T>`, so the signature is fixed.
#[allow(clippy::ref_option)]
pub(crate) fn serialize_opt<S: Serializer>(
    ts: &Option<Timestamp>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match ts {
        Some(ts) => serialize(ts, serializer),
        None => serializer.serialize_none(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn formats_with_millis_and_z_suffix() {
        let ts = Utc.with_ymd_and_hms(2026, 9, 23, 17, 40, 12).unwrap();
        assert_eq!(format_rfc3339(&ts), "2026-09-23T17:40:12.000Z");
    }
}
