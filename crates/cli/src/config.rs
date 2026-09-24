//! Provider credentials from the environment.
//!
//! Keys are read once into `SecretString`s and handed to collectors. They
//! are never printed, logged or stored in the investigation. A variable
//! that is set but not valid UTF-8 is passed on as an empty secret, which
//! the collector reports as an invalid configuration (never as "no data").

use std::ffi::OsString;

use secrecy::SecretString;
use sentinel_collectors::sources::{abuseipdb, malwarebazaar, urlhaus, virustotal};

/// Optional provider credentials.
pub(crate) struct Credentials {
    pub(crate) abuseipdb: Option<SecretString>,
    pub(crate) virustotal: Option<SecretString>,
    /// abuse.ch Auth-Key (URLhaus).
    pub(crate) abusech: Option<SecretString>,
    /// MalwareBazaar Auth-Key: `SENTINEL_MALWAREBAZAAR_KEY`, or else the
    /// shared abuse.ch key `SENTINEL_ABUSECH_KEY`.
    pub(crate) malwarebazaar: Option<SecretString>,
}

impl Credentials {
    /// Reads credentials from the process environment.
    pub(crate) fn from_env() -> Self {
        Self::from_lookup(|name| std::env::var_os(name))
    }

    /// Reads credentials through `lookup` (testable without touching the
    /// process environment).
    pub(crate) fn from_lookup(lookup: impl Fn(&str) -> Option<OsString>) -> Self {
        let secret = |name: &str| {
            lookup(name).map(|value| SecretString::from(value.into_string().unwrap_or_default()))
        };
        Self {
            abuseipdb: secret(abuseipdb::API_KEY_ENV),
            virustotal: secret(virustotal::API_KEY_ENV),
            abusech: secret(urlhaus::API_KEY_ENV),
            malwarebazaar: secret(malwarebazaar::API_KEY_ENV)
                .or_else(|| secret(malwarebazaar::FALLBACK_API_KEY_ENV)),
        }
    }
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::*;

    #[test]
    fn reads_the_documented_variable_only() {
        let set = Credentials::from_lookup(|name| match name {
            "SENTINEL_ABUSEIPDB_KEY" => Some(OsString::from("a")),
            "SENTINEL_VIRUSTOTAL_KEY" => Some(OsString::from("v")),
            "SENTINEL_ABUSECH_KEY" => Some(OsString::from("c")),
            _ => None,
        });
        assert_eq!(set.abuseipdb.unwrap().expose_secret(), "a");
        assert_eq!(set.virustotal.unwrap().expose_secret(), "v");
        assert_eq!(set.abusech.unwrap().expose_secret(), "c");
        let unset = Credentials::from_lookup(|_| None);
        assert!(unset.abuseipdb.is_none() && unset.virustotal.is_none() && unset.abusech.is_none());
    }

    #[test]
    fn malwarebazaar_key_prefers_its_own_variable_then_the_abusech_key() {
        let both = Credentials::from_lookup(|name| match name {
            "SENTINEL_MALWAREBAZAAR_KEY" => Some(OsString::from("mb")),
            "SENTINEL_ABUSECH_KEY" => Some(OsString::from("shared")),
            _ => None,
        });
        assert_eq!(both.malwarebazaar.unwrap().expose_secret(), "mb");
        assert_eq!(both.abusech.unwrap().expose_secret(), "shared");
        let shared = Credentials::from_lookup(|name| {
            (name == "SENTINEL_ABUSECH_KEY").then(|| OsString::from("shared"))
        });
        assert_eq!(shared.malwarebazaar.unwrap().expose_secret(), "shared");
        assert!(Credentials::from_lookup(|_| None).malwarebazaar.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_values_become_an_invalid_empty_secret() {
        use std::os::unix::ffi::OsStringExt;
        let credentials = Credentials::from_lookup(|_| Some(OsString::from_vec(vec![0xff, 0xfe])));
        assert_eq!(credentials.abuseipdb.unwrap().expose_secret(), "");
        assert_eq!(credentials.virustotal.unwrap().expose_secret(), "");
    }
}
