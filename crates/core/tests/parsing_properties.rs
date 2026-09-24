//! Property tests: parsers are the boundary for untrusted input, so they
//! must never panic, and anything they accept must satisfy the documented
//! invariants.

// Test code: panicking on unexpected values is the desired behavior.
#![allow(clippy::unwrap_used)]

use proptest::prelude::*;
use sentinel_core::{DomainName, FileHash, Indicator, IndicatorType};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn parsers_never_panic(input in any::<String>()) {
        let _ = Indicator::parse_domain(&input);
        let _ = Indicator::parse_ip(&input);
        let _ = Indicator::parse_url(&input);
        let _ = Indicator::parse_file_hash(&input);
    }

    #[test]
    fn accepted_domains_satisfy_invariants(input in "[a-zA-Z0-9._\\-\\[\\]() ]{0,80}") {
        if let Ok(domain) = DomainName::parse(&input) {
            let s = domain.as_str();
            prop_assert!(s.len() <= DomainName::MAX_LENGTH);
            prop_assert!(s.contains('.'));
            prop_assert!(!s.ends_with('.'));
            prop_assert!(s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-_.".contains(&b)));
            for label in domain.labels() {
                prop_assert!(!label.is_empty() && label.len() <= DomainName::MAX_LABEL_LENGTH);
            }
            // Normalization is idempotent.
            prop_assert_eq!(DomainName::parse(s).unwrap(), domain.clone());
        }
    }

    #[test]
    fn valid_hostnames_are_accepted(labels in prop::collection::vec("[a-z][a-z0-9]{0,20}", 2..5)) {
        let name = labels.join(".");
        prop_assert!(DomainName::parse(&name).is_ok(), "{}", name);
        prop_assert!(DomainName::parse(&name.to_uppercase()).is_ok());
    }

    #[test]
    fn hex_digests_of_supported_lengths_are_accepted(hex in "[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}") {
        let hash = FileHash::parse(&hex).unwrap();
        prop_assert_eq!(hash.as_str(), hex.to_ascii_lowercase());
        prop_assert_eq!(hash.algorithm().hex_len(), hex.len());
    }

    #[test]
    fn any_ip_round_trips(ip in any::<std::net::IpAddr>()) {
        let indicator = Indicator::parse_ip(&ip.to_string()).unwrap();
        prop_assert_eq!(indicator.as_ip(), Some(ip));
        let kind = indicator.indicator_type();
        prop_assert!(matches!(kind, IndicatorType::Ipv4 | IndicatorType::Ipv6));
    }

    #[test]
    fn indicators_round_trip_through_json(input in "[a-z]{1,10}\\.[a-z]{2,6}") {
        let indicator = Indicator::parse_domain(&input).unwrap();
        let json = serde_json::to_string(&indicator).unwrap();
        let back: Indicator = serde_json::from_str(&json).unwrap();
        prop_assert_eq!(back, indicator);
    }
}
