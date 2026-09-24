//! Tests of the compiled `sentinel-osint` binary: exit codes, stream
//! separation and file output. None of them touches the network: invalid
//! input is rejected before any I/O, and hash investigations have no
//! applicable keyless source in v0.1. Provider keys are removed from the
//! environment, so keyed providers stay unavailable (no network).

#![allow(clippy::unwrap_used)]

use std::process::{Command, Output};

const SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

const MD5: &str = "d41d8cd98f00b204e9800998ecf8427e";

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sentinel-osint"))
        .args(args)
        .env_remove("SENTINEL_ABUSEIPDB_KEY")
        .env_remove("SENTINEL_VIRUSTOTAL_KEY")
        .env_remove("SENTINEL_ABUSECH_KEY")
        .env_remove("SENTINEL_MALWAREBAZAAR_KEY")
        .output()
        .unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn help_and_version() {
    let help = run(&["--help"]);
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("investigate"));

    let version = run(&["--version"]);
    assert!(version.status.success());
    assert!(String::from_utf8_lossy(&version.stdout).starts_with("sentinel-osint "));
}

#[test]
fn usage_errors_exit_with_2() {
    for args in [
        vec!["investigate"],
        vec!["investigate", "--domain", "example.com", "--ip", "8.8.8.8"],
        vec!["investigate", "--domain", "example.com", "--format", "xml"],
        vec!["investigate", "--domain", "example.com", "--timeout", "0"],
    ] {
        let output = run(&args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn invalid_and_non_public_targets_exit_with_2_before_any_io() {
    let cases = [
        (
            vec!["investigate", "--domain", "exa mple.com"],
            "invalid domain name",
        ),
        (
            vec!["investigate", "--domain", "https://example.com/"],
            "not a URL",
        ),
        (
            vec!["investigate", "--domain", "printer.local"],
            "special-use",
        ),
        (vec!["investigate", "--ip", "10.0.0.1"], "private"),
        (vec!["investigate", "--ip", "169.254.169.254"], "link-local"),
        (
            vec!["investigate", "--ip", "010.0.0.1"],
            "invalid IP address",
        ),
        (vec!["investigate", "--hash", "xyz"], "invalid file hash"),
    ];
    for (args, message) in cases {
        let output = run(&args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(output.stdout.is_empty(), "no report for invalid input");
        assert!(
            stderr(&output).contains(message),
            "{args:?}: {}",
            stderr(&output)
        );
    }
}

#[test]
fn error_messages_do_not_echo_hostile_input() {
    let output = run(&["investigate", "--domain", "\u{1b}]0;pwned\u{7}.com"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(!stderr(&output).contains('\u{1b}'));
    assert!(!stderr(&output).contains("pwned"));
}

#[test]
fn json_goes_to_stdout_as_a_single_document() {
    let output = run(&["investigate", "--hash", SHA256, "--format", "json"]);
    assert!(output.status.success(), "{}", stderr(&output));
    let doc: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(doc["investigation"]["target"]["type"], "file_hash");
    assert_eq!(doc["investigation"]["target"]["value"], SHA256);
}

#[test]
fn output_file_is_created_once() {
    let path = std::env::temp_dir().join(format!(
        "sentinel-osint-cli-test-{}.txt",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    let path_str = path.to_str().unwrap();

    let first = run(&["investigate", "--hash", SHA256, "--output", path_str]);
    assert!(first.status.success(), "{}", stderr(&first));
    assert!(
        first.stdout.is_empty(),
        "the report goes to the file, not stdout"
    );
    assert!(stderr(&first).contains("Report written to"));
    assert!(
        std::fs::read_to_string(&path)
            .unwrap()
            .contains("Type:      File hash")
    );

    let second = run(&["investigate", "--hash", SHA256, "--output", path_str]);
    assert_eq!(second.status.code(), Some(1));
    assert!(stderr(&second).contains("refusing to overwrite"));
    std::fs::remove_file(&path).unwrap();
}

/// Real Cymru DNS and RDAP against the live internet. Opt in with
/// `cargo test -p sentinel-cli -- --ignored`.
#[test]
#[ignore = "requires network access"]
fn live_ip_investigation() {
    let output = run(&["investigate", "--ip", "8.8.8.8", "--format", "json"]);
    assert!(output.status.success(), "{}", stderr(&output));
    let doc: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let sources: Vec<&str> = doc["investigation"]["sources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["source"].as_str().unwrap())
        .collect();
    assert!(
        sources.contains(&"cymru") && sources.contains(&"rdap"),
        "{sources:?}"
    );
}

/// Real DNS against the live internet. Opt in with
/// `cargo test -p sentinel-cli -- --ignored`.
#[test]
#[ignore = "requires network access"]
fn live_domain_investigation() {
    let output = run(&["investigate", "--domain", "example.com", "--format", "json"]);
    assert!(output.status.success(), "{}", stderr(&output));
    let doc: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    // Status order is not a contract: keyed providers without a key are
    // recorded as unavailable before DNS finishes. Look DNS up by name.
    let dns = doc["investigation"]["sources"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["source"] == "dns")
        .unwrap();
    assert_eq!(dns["status"], "succeeded", "{dns}");
    // CT ran (crt.sh can be slow or unavailable: any outcome is acceptable,
    // but a failure must be reported as a status, never hidden).
    let sources: Vec<&str> = doc["investigation"]["sources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["source"].as_str().unwrap())
        .collect();
    assert!(sources.contains(&"ct"), "{sources:?}");
    assert!(
        !doc["investigation"]["observations"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

/// Opt-in live VirusTotal lookup of the empty file's SHA-256:
/// `SENTINEL_VIRUSTOTAL_KEY=… cargo test -p sentinel-cli -- --ignored`.
/// Without the variable it is skipped (it passes after printing a notice);
/// it never asks for, invents or stores a key.
#[test]
#[ignore = "requires network access and SENTINEL_VIRUSTOTAL_KEY"]
#[allow(clippy::print_stderr)]
fn live_virustotal_lookup() {
    let Some(key) = std::env::var_os("SENTINEL_VIRUSTOTAL_KEY") else {
        eprintln!("skipped: SENTINEL_VIRUSTOTAL_KEY is not set (live VirusTotal test unavailable)");
        return;
    };
    let output = Command::new(env!("CARGO_BIN_EXE_sentinel-osint"))
        .args(["-vv", "investigate", "--hash", SHA256, "--format", "json"])
        .env_remove("SENTINEL_ABUSEIPDB_KEY")
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        stderr(&output)
    );
    assert!(
        !all.contains(key.to_str().unwrap()),
        "the key must never be printed"
    );
    let doc: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let status = doc["investigation"]["sources"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["source"] == "virustotal")
        .unwrap()
        .clone();
    // Found or not found are both successful lookups; failures are shown.
    assert_eq!(status["status"], "succeeded", "{status}");
}

/// Opt-in live URLhaus lookup of `example.com` (a lookup in URLhaus's
/// database; no listed URL is ever contacted):
/// `SENTINEL_ABUSECH_KEY=… cargo test -p sentinel-cli -- --ignored`.
/// Without the variable it is skipped (it passes after printing a notice).
#[test]
#[ignore = "requires network access and SENTINEL_ABUSECH_KEY"]
#[allow(clippy::print_stderr)]
fn live_urlhaus_lookup() {
    let Some(key) = std::env::var_os("SENTINEL_ABUSECH_KEY") else {
        eprintln!("skipped: SENTINEL_ABUSECH_KEY is not set (live URLhaus test unavailable)");
        return;
    };
    let output = Command::new(env!("CARGO_BIN_EXE_sentinel-osint"))
        .args([
            "-vv",
            "investigate",
            "--domain",
            "example.com",
            "--format",
            "json",
        ])
        .env_remove("SENTINEL_ABUSEIPDB_KEY")
        .env_remove("SENTINEL_VIRUSTOTAL_KEY")
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        stderr(&output)
    );
    assert!(
        !all.contains(key.to_str().unwrap()),
        "the key must never be printed"
    );
    let doc: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let status = doc["investigation"]["sources"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["source"] == "urlhaus")
        .unwrap()
        .clone();
    // Listed or no_results are both successful lookups; failures are shown.
    assert_eq!(status["status"], "succeeded", "{status}");
}

/// Opt-in live MalwareBazaar lookup (`get_info` only, never a download) of
/// the hash used in the official API documentation's example request:
/// `SENTINEL_MALWAREBAZAAR_KEY=… cargo test -p sentinel-cli -- --ignored`.
/// Without the variable it is skipped (it passes after printing a notice).
#[test]
#[ignore = "requires network access and SENTINEL_MALWAREBAZAAR_KEY"]
#[allow(clippy::print_stderr)]
fn live_malwarebazaar_lookup() {
    const DOCUMENTED_HASH: &str =
        "094fd325049b8a9cf6d3e5ef2a6d4cc6a567d7d49c35f8bb8dd9e3c6acf3d78d";
    let Some(key) = std::env::var_os("SENTINEL_MALWAREBAZAAR_KEY") else {
        eprintln!(
            "skipped: SENTINEL_MALWAREBAZAAR_KEY is not set (live MalwareBazaar test unavailable)"
        );
        return;
    };
    let output = Command::new(env!("CARGO_BIN_EXE_sentinel-osint"))
        .args([
            "-vv",
            "investigate",
            "--hash",
            DOCUMENTED_HASH,
            "--format",
            "json",
        ])
        .env_remove("SENTINEL_VIRUSTOTAL_KEY")
        .env_remove("SENTINEL_ABUSEIPDB_KEY")
        .env_remove("SENTINEL_ABUSECH_KEY")
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        stderr(&output)
    );
    assert!(
        !all.contains(key.to_str().unwrap()),
        "the key must never be printed"
    );
    let doc: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let status = doc["investigation"]["sources"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["source"] == "malwarebazaar")
        .unwrap()
        .clone();
    // Listed or hash_not_found are both successful lookups.
    assert_eq!(status["status"], "succeeded", "{status}");
}

const FAKE_KEY: &str = "cli-test-SECRET-key-never-printed";

fn run_with_key(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sentinel-osint"))
        .args(args)
        .env("SENTINEL_ABUSEIPDB_KEY", FAKE_KEY)
        .env("SENTINEL_VIRUSTOTAL_KEY", FAKE_KEY)
        .env("SENTINEL_ABUSECH_KEY", FAKE_KEY)
        .env("SENTINEL_MALWAREBAZAAR_KEY", FAKE_KEY)
        .output()
        .unwrap()
}

#[test]
fn the_api_key_is_never_printed() {
    // No target here reaches a provider (MD5 is supported by none, the IPs
    // are rejected first), so no real API is called with the fake key.
    for args in [
        vec!["-vvv", "investigate", "--hash", MD5],
        vec!["-vvv", "investigate", "--hash", MD5, "--format", "json"],
        vec!["-vvv", "investigate", "--ip", "10.0.0.1"],
        vec!["-vvv", "investigate", "--ip", "not-an-ip"],
    ] {
        let output = run_with_key(&args);
        let all = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            stderr(&output)
        );
        assert!(!all.contains(FAKE_KEY), "{args:?} leaked the key");
    }
}

#[test]
fn help_documents_the_optional_provider_key() {
    let help = run(&["investigate", "--help"]);
    let text = String::from_utf8_lossy(&help.stdout).into_owned();
    assert!(text.contains("SENTINEL_ABUSEIPDB_KEY"));
    assert!(text.contains("SENTINEL_VIRUSTOTAL_KEY"));
    assert!(text.contains("SENTINEL_ABUSECH_KEY"));
    assert!(text.contains("SENTINEL_MALWAREBAZAAR_KEY"));
}

#[test]
fn every_source_is_accounted_for_in_hash_investigations() {
    let output = run(&["investigate", "--hash", SHA256, "--format", "json"]);
    assert!(output.status.success());
    let doc: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let statuses: Vec<(String, String)> = doc["investigation"]["sources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            (
                s["source"].as_str().unwrap().to_owned(),
                s["status"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    for source in ["dns", "ct", "cymru", "rdap", "abuseipdb", "urlhaus"] {
        assert!(
            statuses.contains(&(source.to_owned(), "unsupported".to_owned())),
            "{source}: {statuses:?}"
        );
    }
    // SHA-256 is supported by VirusTotal: without a key it is unavailable,
    // never "no results".
    for keyed in ["virustotal", "malwarebazaar"] {
        assert!(
            statuses.contains(&(keyed.to_owned(), "unavailable".to_owned())),
            "{keyed}: {statuses:?}"
        );
    }
}

#[test]
fn correlate_flag_is_opt_in_and_offline() {
    let plain = run(&["investigate", "--hash", SHA256]);
    assert!(plain.status.success());
    assert!(!String::from_utf8_lossy(&plain.stdout).contains("Correlation ("));

    let table = run(&["investigate", "--hash", SHA256, "--correlate"]);
    assert!(table.status.success(), "{}", stderr(&table));
    let text = String::from_utf8_lossy(&table.stdout);
    assert!(text.contains("Correlation (0)"), "{text}");
    assert!(text.contains("No correlations in this investigation."));

    let json = run(&[
        "investigate",
        "--hash",
        SHA256,
        "--correlate",
        "--format",
        "json",
    ]);
    assert!(json.status.success());
    let doc: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(doc["schema_version"], "0.1");
    assert_eq!(
        doc["correlation"]["investigation"], doc["investigation"]["id"],
        "the report names the investigation it was derived from"
    );
    assert!(
        doc["correlation"]["correlations"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let help = run(&["investigate", "--help"]);
    assert!(String::from_utf8_lossy(&help.stdout).contains("--correlate"));
}

#[test]
fn malwarebazaar_states_for_hash_targets_without_network() {
    let status_of = |hash: &str| -> String {
        let output = run(&["investigate", "--hash", hash, "--format", "json"]);
        assert!(output.status.success());
        let doc: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        doc["investigation"]["sources"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["source"] == "malwarebazaar")
            .unwrap()["status"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    // SHA-256 and SHA-1 are supported but no key is set: unavailable, never "no results".
    assert_eq!(status_of(SHA256), "unavailable");
    assert_eq!(
        status_of("da39a3ee5e6b4b0d3255bfef95601890afd80709"),
        "unavailable"
    );
    // MD5 is not used for MalwareBazaar lookups.
    assert_eq!(status_of(MD5), "unsupported");
}
