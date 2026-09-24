//! SHA-256 digests of raw source responses.

use std::fmt;
use std::str::FromStr;

use serde::{Serialize, Serializer};
use sha2::{Digest, Sha256};

/// SHA-256 digest of a raw response body.
///
/// Storing the digest instead of the body lets an analyst prove later that a
/// response they re-fetched or archived is the one the observation was based
/// on, without keeping potentially sensitive raw content around.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    /// Computes the SHA-256 digest of `bytes`.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    /// The raw digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sha256Digest({self})")
    }
}

/// Error parsing a hex SHA-256 digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("expected 64 hexadecimal characters")]
pub struct DigestParseError;

impl FromStr for Sha256Digest {
    type Err = DigestParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = s.as_bytes();
        if bytes.len() != 64 {
            return Err(DigestParseError);
        }
        let mut out = [0u8; 32];
        for (slot, pair) in out.iter_mut().zip(bytes.chunks_exact(2)) {
            let hi = hex_value(pair[0]).ok_or(DigestParseError)?;
            let lo = hex_value(pair[1]).ok_or(DigestParseError)?;
            *slot = (hi << 4) | lo;
        }
        Ok(Self(out))
    }
}

const fn hex_value(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn matches_known_vectors() {
        assert_eq!(Sha256Digest::of(b"").to_string(), EMPTY_SHA256);
        assert_eq!(
            Sha256Digest::of(b"abc").to_string(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn round_trips_through_hex() {
        let digest = Sha256Digest::of(b"sentinel");
        assert_eq!(digest.to_string().parse::<Sha256Digest>(), Ok(digest));
        assert_eq!(
            EMPTY_SHA256.to_uppercase().parse::<Sha256Digest>(),
            Ok(Sha256Digest::of(b""))
        );
    }

    #[test]
    fn rejects_invalid_hex() {
        assert!("abc".parse::<Sha256Digest>().is_err());
        assert!("g".repeat(64).parse::<Sha256Digest>().is_err());
        // 64 bytes but multibyte characters must not panic.
        assert!("é".repeat(32).parse::<Sha256Digest>().is_err());
    }
}
