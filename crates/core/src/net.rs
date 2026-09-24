//! Classification of IP addresses by routing scope.
//!
//! This is used for two security decisions:
//!
//! 1. **Investigation policy.** Only globally routable addresses can be
//!    investigated. External sources know nothing useful about private
//!    addresses, and sending internal addresses to third parties leaks
//!    information about the analyst's environment.
//! 2. **SSRF defense.** The HTTP client refuses to connect to non-global
//!    addresses (see `docs/THREAT-MODEL.md`, T3).
//!
//! The classification is intentionally **conservative**. Ranges whose global
//! reachability is ambiguous (for example the whole IETF protocol assignment
//! block `2001::/23`) are treated as non-global.
//!
//! `std::net::IpAddr::is_global` is still unstable, which is why this module exists.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Serialize, Serializer};

/// The routing scope of an IP address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressScope {
    /// Globally routable unicast address.
    Global,
    /// `0.0.0.0` or `::`.
    Unspecified,
    /// `127.0.0.0/8` or `::1`.
    Loopback,
    /// RFC 1918 private ranges.
    Private,
    /// RFC 6598 carrier-grade NAT (`100.64.0.0/10`).
    SharedAddressSpace,
    /// `169.254.0.0/16` or `fe80::/10`. Includes cloud metadata endpoints.
    LinkLocal,
    /// IPv6 unique local addresses (`fc00::/7`).
    UniqueLocal,
    /// Documentation ranges (RFC 5737, RFC 3849, RFC 9637).
    Documentation,
    /// Benchmarking ranges (RFC 2544, RFC 5180).
    Benchmarking,
    /// Multicast.
    Multicast,
    /// `255.255.255.255`.
    Broadcast,
    /// Any other reserved or special-purpose range.
    Reserved,
}

impl AddressScope {
    /// Whether this scope is globally routable.
    #[must_use]
    pub const fn is_global(self) -> bool {
        matches!(self, Self::Global)
    }

    /// Human-readable description.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::Global => "globally routable",
            Self::Unspecified => "unspecified",
            Self::Loopback => "loopback",
            Self::Private => "private (RFC 1918)",
            Self::SharedAddressSpace => "shared address space (carrier-grade NAT)",
            Self::LinkLocal => "link-local",
            Self::UniqueLocal => "unique local (IPv6)",
            Self::Documentation => "documentation",
            Self::Benchmarking => "benchmarking",
            Self::Multicast => "multicast",
            Self::Broadcast => "broadcast",
            Self::Reserved => "reserved",
        }
    }
}

impl fmt::Display for AddressScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.description())
    }
}

/// Classifies an IP address.
#[must_use]
pub fn classify(ip: IpAddr) -> AddressScope {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    }
}

/// Returns `true` if the address is globally routable.
#[must_use]
pub fn is_global(ip: IpAddr) -> bool {
    classify(ip).is_global()
}

/// Classifies an IPv4 address.
#[must_use]
// One arm per RFC range keeps the table auditable, even when arms share a result.
#[allow(clippy::match_same_arms)]
pub fn classify_v4(ip: Ipv4Addr) -> AddressScope {
    use AddressScope as S;
    match ip.octets() {
        [0, 0, 0, 0] => S::Unspecified,
        [255, 255, 255, 255] => S::Broadcast,
        // 0.0.0.0/8 "this network", 192.0.0.0/24 IETF protocol assignments,
        // 192.88.99.0/24 deprecated 6to4 relay anycast.
        [0, ..] | [192, 0, 0, _] | [192, 88, 99, _] => S::Reserved,
        [10, ..] | [192, 168, ..] => S::Private,
        [172, b, ..] if (16..=31).contains(&b) => S::Private,
        [100, b, ..] if (64..=127).contains(&b) => S::SharedAddressSpace,
        [127, ..] => S::Loopback,
        [169, 254, ..] => S::LinkLocal,
        [192, 0, 2, _] | [198, 51, 100, _] | [203, 0, 113, _] => S::Documentation,
        [198, 18 | 19, ..] => S::Benchmarking,
        [224..=239, ..] => S::Multicast,
        [240..=255, ..] => S::Reserved,
        _ => S::Global,
    }
}

/// Classifies an IPv6 address. Addresses that embed an IPv4 address
/// (IPv4-mapped, NAT64 well-known prefix, 6to4) are classified by the
/// embedded address.
#[must_use]
#[allow(clippy::match_same_arms)]
pub fn classify_v6(ip: Ipv6Addr) -> AddressScope {
    use AddressScope as S;

    if ip.is_unspecified() {
        return S::Unspecified;
    }
    if ip.is_loopback() {
        return S::Loopback;
    }
    if let Some(v4) = ip.to_ipv4_mapped() {
        return classify_v4(v4);
    }

    let seg = ip.segments();
    match seg {
        // IPv4-compatible addresses (::/96), deprecated.
        [0, 0, 0, 0, 0, 0, _, _] => S::Reserved,
        // NAT64 well-known prefix 64:ff9b::/96 embeds an IPv4 address.
        [0x64, 0xff9b, 0, 0, 0, 0, hi, lo] => classify_v4(v4_from_segments(hi, lo)),
        // 6to4 (2002::/16) embeds an IPv4 address in segments 1–2.
        [0x2002, hi, lo, ..] => classify_v4(v4_from_segments(hi, lo)),
        [0x2001, 0x0db8, ..] => S::Documentation,
        [0x3fff, b, ..] if b < 0x1000 => S::Documentation,
        [0x2001, 0x0002, 0, ..] => S::Benchmarking,
        // 64:ff9b:1::/48 local-use NAT64, 100::/64 discard-only,
        // 2001::/23 IETF protocol assignments (includes Teredo).
        [0x64, 0xff9b, 1, ..] | [0x100, 0, 0, 0, ..] => S::Reserved,
        [0x2001, b, ..] if b < 0x0200 => S::Reserved,
        [a, ..] if a & 0xfe00 == 0xfc00 => S::UniqueLocal,
        [a, ..] if a & 0xffc0 == 0xfe80 => S::LinkLocal,
        [a, ..] if a & 0xff00 == 0xff00 => S::Multicast,
        // Only 2000::/3 is allocated for global unicast.
        [a, ..] if a & 0xe000 == 0x2000 => S::Global,
        _ => S::Reserved,
    }
}

/// A validated IP network in CIDR notation, such as `8.8.8.0/24`.
///
/// Parsing is strict: the prefix length must fit the address family and all
/// host bits must be zero. `8.8.8.1/24` is rejected, not silently rounded,
/// because a source that returns it is reporting something inconsistent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IpPrefix {
    network: IpAddr,
    len: u8,
}

/// Why a string is not a valid CIDR prefix. Never echoes the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PrefixError {
    /// Not of the form `address/length`.
    #[error("not in address/length form")]
    Syntax,
    /// The address part is not an IP address.
    #[error("invalid network address")]
    Address,
    /// The length exceeds 32 (IPv4) or 128 (IPv6).
    #[error("prefix length out of range")]
    Length,
    /// Bits beyond the prefix length are set.
    #[error("host bits are set")]
    HostBits,
}

impl IpPrefix {
    /// Parses `address/length`.
    ///
    /// # Errors
    /// [`PrefixError`] describing the problem.
    pub fn parse(input: &str) -> Result<Self, PrefixError> {
        let (address, len) = input.trim().split_once('/').ok_or(PrefixError::Syntax)?;
        let address: IpAddr = address.parse().map_err(|_| PrefixError::Address)?;
        // Only plain decimal digits: no sign, no leading "+", bounded length.
        if len.is_empty() || len.len() > 3 || !len.bytes().all(|b| b.is_ascii_digit()) {
            return Err(PrefixError::Length);
        }
        let len: u8 = len.parse().map_err(|_| PrefixError::Length)?;
        Self::new(address, len)
    }

    /// Builds a prefix from its parts (e.g. RDAP `cidr0` objects).
    ///
    /// # Errors
    /// [`PrefixError::Length`] or [`PrefixError::HostBits`].
    pub fn new(network: IpAddr, len: u8) -> Result<Self, PrefixError> {
        let max = match network {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if len > max {
            return Err(PrefixError::Length);
        }
        if mask(network, len) != network {
            return Err(PrefixError::HostBits);
        }
        Ok(Self { network, len })
    }

    /// The network address.
    #[must_use]
    pub const fn network(&self) -> IpAddr {
        self.network
    }

    /// The prefix length.
    #[must_use]
    pub const fn len(&self) -> u8 {
        self.len
    }

    /// Whether the prefix length is zero (the whole address space).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Whether `ip` is inside this network (same family only).
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {
                mask(ip, self.len) == self.network
            }
            _ => false,
        }
    }
}

/// `ip` with every bit after the first `len` bits cleared.
fn mask(ip: IpAddr, len: u8) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let bits = u32::from(v4);
            let kept = if len == 0 {
                0
            } else {
                bits & (u32::MAX << (32 - u32::from(len.min(32))))
            };
            IpAddr::V4(Ipv4Addr::from(kept))
        }
        IpAddr::V6(v6) => {
            let bits = u128::from(v6);
            let kept = if len == 0 {
                0
            } else {
                bits & (u128::MAX << (128 - u32::from(len.min(128))))
            };
            IpAddr::V6(Ipv6Addr::from(kept))
        }
    }
}

impl fmt::Display for IpPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.len)
    }
}

impl Serialize for IpPrefix {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

fn v4_from_segments(hi: u16, lo: u16) -> Ipv4Addr {
    let [a, b] = hi.to_be_bytes();
    let [c, d] = lo.to_be_bytes();
    Ipv4Addr::new(a, b, c, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> AddressScope {
        classify(s.parse().unwrap())
    }

    #[test]
    fn classifies_ipv4_ranges() {
        let cases = [
            ("8.8.8.8", AddressScope::Global),
            ("1.1.1.1", AddressScope::Global),
            ("0.0.0.0", AddressScope::Unspecified),
            ("0.1.2.3", AddressScope::Reserved),
            ("10.0.0.1", AddressScope::Private),
            ("172.16.0.1", AddressScope::Private),
            ("172.31.255.255", AddressScope::Private),
            ("172.32.0.1", AddressScope::Global),
            ("192.168.1.1", AddressScope::Private),
            ("100.64.0.1", AddressScope::SharedAddressSpace),
            ("100.128.0.1", AddressScope::Global),
            ("127.0.0.1", AddressScope::Loopback),
            ("169.254.169.254", AddressScope::LinkLocal),
            ("192.0.0.8", AddressScope::Reserved),
            ("192.0.2.10", AddressScope::Documentation),
            ("198.51.100.10", AddressScope::Documentation),
            ("203.0.113.10", AddressScope::Documentation),
            ("198.18.0.1", AddressScope::Benchmarking),
            ("198.19.255.255", AddressScope::Benchmarking),
            ("224.0.0.1", AddressScope::Multicast),
            ("240.0.0.1", AddressScope::Reserved),
            ("255.255.255.255", AddressScope::Broadcast),
        ];
        for (ip, expected) in cases {
            assert_eq!(v4(ip), expected, "{ip}");
        }
    }

    #[test]
    fn classifies_ipv6_ranges() {
        let cases = [
            ("2001:4860:4860::8888", AddressScope::Global),
            ("2606:4700:4700::1111", AddressScope::Global),
            ("::", AddressScope::Unspecified),
            ("::1", AddressScope::Loopback),
            ("fe80::1", AddressScope::LinkLocal),
            ("fc00::1", AddressScope::UniqueLocal),
            ("fd12:3456::1", AddressScope::UniqueLocal),
            ("ff02::1", AddressScope::Multicast),
            ("2001:db8::1", AddressScope::Documentation),
            ("3fff::1", AddressScope::Documentation),
            ("2001:2::1", AddressScope::Benchmarking),
            ("2001::1", AddressScope::Reserved),
            ("100::1", AddressScope::Reserved),
            ("::1.2.3.4", AddressScope::Reserved),
            ("4000::1", AddressScope::Reserved),
        ];
        for (ip, expected) in cases {
            assert_eq!(v4(ip), expected, "{ip}");
        }
    }

    #[test]
    fn parses_strict_prefixes() {
        let p = IpPrefix::parse("8.8.8.0/24").unwrap();
        assert_eq!(p.to_string(), "8.8.8.0/24");
        assert!(p.contains("8.8.8.8".parse().unwrap()));
        assert!(!p.contains("8.8.9.8".parse().unwrap()));
        assert!(!p.contains("::1".parse().unwrap()));
        let v6 = IpPrefix::parse("2001:4860::/32").unwrap();
        assert!(v6.contains("2001:4860:4860::8888".parse().unwrap()));
        assert!(
            IpPrefix::parse("0.0.0.0/0")
                .unwrap()
                .contains("1.2.3.4".parse().unwrap())
        );
        assert!(
            IpPrefix::parse("1.2.3.4/32")
                .unwrap()
                .contains("1.2.3.4".parse().unwrap())
        );
    }

    #[test]
    fn rejects_invalid_prefixes() {
        let cases = [
            ("8.8.8.0", PrefixError::Syntax),
            ("8.8.8/24", PrefixError::Address),
            ("8.8.8.0/33", PrefixError::Length),
            ("8.8.8.0/+24", PrefixError::Length),
            ("8.8.8.0/", PrefixError::Length),
            ("8.8.8.0/99999999999", PrefixError::Length),
            ("::/129", PrefixError::Length),
            ("8.8.8.1/24", PrefixError::HostBits),
            ("2001:db8::1/64", PrefixError::HostBits),
            ("fe80::1%eth0/64", PrefixError::Address),
        ];
        for (input, expected) in cases {
            assert_eq!(IpPrefix::parse(input), Err(expected), "{input}");
        }
    }

    #[test]
    fn embedded_ipv4_is_classified_by_the_embedded_address() {
        // IPv4-mapped, NAT64 and 6to4 must not be usable to smuggle
        // private addresses past the policy.
        assert_eq!(v4("::ffff:127.0.0.1"), AddressScope::Loopback);
        assert_eq!(v4("::ffff:8.8.8.8"), AddressScope::Global);
        assert_eq!(v4("64:ff9b::10.0.0.1"), AddressScope::Private);
        assert_eq!(v4("64:ff9b::8.8.8.8"), AddressScope::Global);
        assert_eq!(v4("2002:a9fe:a9fe::1"), AddressScope::LinkLocal); // 169.254.169.254
        assert_eq!(v4("2002:0808:0808::1"), AddressScope::Global);
    }
}
