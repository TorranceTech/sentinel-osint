//! File hashes.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::IndicatorError;

/// Supported file hash algorithms. The algorithm is inferred from the length
/// of the hex digest, so a hash value alone is unambiguous.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HashAlgorithm {
    /// MD5 (32 hex characters). Weak, but still ubiquitous in threat intel.
    Md5,
    /// SHA-1 (40 hex characters).
    Sha1,
    /// SHA-256 (64 hex characters).
    Sha256,
}

impl HashAlgorithm {
    /// Length of the hex-encoded digest.
    #[must_use]
    pub const fn hex_len(self) -> usize {
        match self {
            Self::Md5 => 32,
            Self::Sha1 => 40,
            Self::Sha256 => 64,
        }
    }

    /// Infers the algorithm from a hex digest length.
    #[must_use]
    pub const fn from_hex_len(len: usize) -> Option<Self> {
        match len {
            32 => Some(Self::Md5),
            40 => Some(Self::Sha1),
            64 => Some(Self::Sha256),
            _ => None,
        }
    }

    /// Display name (`MD5`, `SHA-1`, `SHA-256`).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Md5 => "MD5",
            Self::Sha1 => "SHA-1",
            Self::Sha256 => "SHA-256",
        }
    }
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A validated file hash: lowercase hex of an MD5, SHA-1 or SHA-256 digest.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct FileHash {
    algorithm: HashAlgorithm,
    hex: String,
}

impl FileHash {
    /// Parses a hex digest and infers its algorithm from the length.
    ///
    /// # Errors
    /// Returns [`IndicatorError::InvalidFileHash`] if the input is not hex
    /// or has an unsupported length.
    pub fn parse(input: &str) -> Result<Self, IndicatorError> {
        let s = input.trim();
        if s.is_empty() {
            return Err(IndicatorError::Empty);
        }
        if !s.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(IndicatorError::InvalidFileHash(
                "must contain only hexadecimal characters",
            ));
        }
        let algorithm =
            HashAlgorithm::from_hex_len(s.len()).ok_or(IndicatorError::InvalidFileHash(
                "length must be 32 (MD5), 40 (SHA-1) or 64 (SHA-256) hex characters",
            ))?;
        Ok(Self {
            algorithm,
            hex: s.to_ascii_lowercase(),
        })
    }

    /// The hash algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> HashAlgorithm {
        self.algorithm
    }

    /// The lowercase hex digest.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.hex
    }
}

impl fmt::Display for FileHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.hex)
    }
}

impl TryFrom<String> for FileHash {
    type Error = IndicatorError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<FileHash> for String {
    fn from(value: FileHash) -> Self {
        value.hex
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn infers_algorithm_from_length() {
        let md5 = FileHash::parse("d41d8cd98f00b204e9800998ecf8427e").unwrap();
        assert_eq!(md5.algorithm(), HashAlgorithm::Md5);

        let sha1 = FileHash::parse("da39a3ee5e6b4b0d3255bfef95601890afd80709").unwrap();
        assert_eq!(sha1.algorithm(), HashAlgorithm::Sha1);

        let sha256 =
            FileHash::parse("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                .unwrap();
        assert_eq!(sha256.algorithm(), HashAlgorithm::Sha256);
    }

    #[test]
    fn normalizes_to_lowercase() {
        let h = FileHash::parse("  D41D8CD98F00B204E9800998ECF8427E ").unwrap();
        assert_eq!(h.as_str(), "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn rejects_invalid_hashes() {
        for input in [
            "",
            "xyz",
            "d41d8cd98f00b204e9800998ecf8427",   // 31 chars
            "d41d8cd98f00b204e9800998ecf8427ez", // 32 chars, non-hex
            "0x41d8cd98f00b204e9800998ecf8427e",
            "d41d8cd9 8f00b204e9800998ecf8427e",
        ] {
            assert!(
                FileHash::parse(input).is_err(),
                "{input:?} should be invalid"
            );
        }
    }
}
