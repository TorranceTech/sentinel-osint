//! The single entry point of wall-clock time into Sentinel.
//!
//! `sentinel-core` never reads the clock. Timestamps for observations and
//! source statuses come from a [`Clock`], which tests can replace.

use chrono::Utc;
use sentinel_core::Timestamp;

/// Source of the current time.
pub trait Clock: Send + Sync {
    /// The current time (UTC).
    fn now(&self) -> Timestamp;
}

/// The system clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        Utc::now()
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use chrono::TimeZone;

    /// A clock that always returns the same instant.
    #[derive(Debug, Clone, Copy)]
    pub(crate) struct FixedClock(pub(crate) Timestamp);

    impl Default for FixedClock {
        fn default() -> Self {
            Self(Utc.with_ymd_and_hms(2026, 9, 23, 12, 0, 0).unwrap())
        }
    }

    impl Clock for FixedClock {
        fn now(&self) -> Timestamp {
            self.0
        }
    }
}
