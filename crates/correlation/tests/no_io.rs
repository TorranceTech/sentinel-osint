//! Architectural guarantees: the correlation crate cannot perform I/O.
//!
//! 1. Its dependencies are limited to crates without network, DNS,
//!    process or file I/O.
//! 2. Its source does not name any I/O API.
//!
//! (The end-to-end "no request after correlating" check lives in the CLI
//! tests, which have mock servers and a fake resolver.)

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

const ALLOWED_DEPENDENCIES: [&str; 3] = ["sentinel-core", "serde", "sha2"];

/// API names that would indicate I/O, processes, the environment, the
/// clock or randomness. (`std::net::IpAddr` is a plain value type and is
/// allowed; every socket and name-resolution API of `std::net` is listed.)
const FORBIDDEN: &[&str] = &[
    "TcpListener",
    "SocketAddr",
    "lookup_host",
    "std::fs",
    "std::process",
    "std::env",
    "std::io",
    "std::os",
    "std::thread",
    "TcpStream",
    "UdpSocket",
    "ToSocketAddrs",
    "Command::new",
    "tokio",
    "reqwest",
    "hickory",
    "sentinel_collectors",
    "HttpClient",
    "DnsResolver",
    "SystemTime",
    "Instant::now",
    "Utc::now",
    "rand::",
    "new_random",
];

fn manifest_dir() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn dependencies_are_limited_to_the_model_serialization_and_hashing() {
    let manifest = std::fs::read_to_string(manifest_dir().join("Cargo.toml")).unwrap();
    let section = manifest
        .split("[dependencies]")
        .nth(1)
        .expect("a [dependencies] section")
        .split("\n[")
        .next()
        .unwrap();
    let names: Vec<&str> = section
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.split(['.', '=', ' ']).next().unwrap())
        .collect();
    assert!(!names.is_empty());
    for name in &names {
        assert!(
            ALLOWED_DEPENDENCIES.contains(name),
            "unexpected dependency `{name}`: the correlation crate must stay I/O-free"
        );
    }
    assert!(
        !manifest.contains("[build-dependencies]"),
        "no build scripts"
    );
    assert!(
        !manifest_dir().join("build.rs").exists(),
        "no build scripts"
    );
}

fn rust_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn source_names_no_io_clock_or_randomness_api() {
    let mut files = Vec::new();
    rust_files(&manifest_dir().join("src"), &mut files);
    assert!(files.len() >= 5, "{files:?}");
    for file in files {
        // Unit tests may use test-only helpers (timing a large input).
        if file.ends_with("tests.rs") {
            continue;
        }
        let source = std::fs::read_to_string(&file).unwrap();
        for forbidden in FORBIDDEN {
            assert!(
                !source.contains(forbidden),
                "{} mentions `{forbidden}`; correlation must not perform I/O",
                file.display()
            );
        }
        assert!(
            !source.contains("async fn"),
            "{}: correlation is synchronous",
            file.display()
        );
        assert!(!source.contains("unsafe"), "{}", file.display());
    }
}
