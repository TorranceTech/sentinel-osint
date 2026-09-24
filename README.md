# Sentinel OSINT

[![CI](https://github.com/TorranceTech/sentinel-osint/actions/workflows/ci.yml/badge.svg)](https://github.com/TorranceTech/sentinel-osint/actions/workflows/ci.yml)
![Rust 2024](https://img.shields.io/badge/rust-2024%20edition-orange)
![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)

**Passive-first OSINT and threat-intelligence investigation tool, written in Rust.**

Give it one indicator (a domain name, an IP address or a file hash). It
collects public intelligence from legitimate sources, records every result as
evidence with provenance (source, time, confidence, response digest), derives
informational findings, and prints a report as a terminal table or as JSON.

It is built for defensive work: SOC triage, CTI enrichment, incident response,
security research and cybersecurity education.

```text
sentinel-osint investigate --domain example.com [--format table|json] [--correlate]
sentinel-osint investigate --ip 8.8.8.8
sentinel-osint investigate --hash <md5|sha1|sha256>
```

## Contents

1. [What it does (and does not do)](#what-it-does-and-does-not-do)
2. [Requirements](#requirements)
3. [Build](#build)
4. [Quick start](#quick-start)
5. [Command-line reference](#command-line-reference)
6. [Workflows](#workflows)
7. [Data sources](#data-sources)
8. [API keys (optional providers)](#api-keys-optional-providers)
9. [Reading the table report](#reading-the-table-report)
10. [JSON output](#json-output)
11. [Correlation (`--correlate`)](#correlation---correlate)
12. [Findings](#findings)
13. [Safety, privacy and OPSEC](#safety-privacy-and-opsec)
14. [Exit codes](#exit-codes)
15. [Running the tests](#running-the-tests)
16. [Troubleshooting](#troubleshooting)
17. [Scope of v0.1 and known limitations](#scope-of-v01-and-known-limitations)
18. [Project layout and documentation](#project-layout-and-documentation)
19. [Security and license](#security-and-license)

## What it does (and does not do)

**Sentinel OSINT does:**

- Look up an indicator in public, legitimate sources (DNS, Team Cymru, RDAP
  registries, Certificate Transparency via crt.sh) and, if you provide API
  keys, in threat-intelligence services (AbuseIPDB, VirusTotal, URLhaus,
  MalwareBazaar).
- Record every fact as an observation with its source, collection time,
  Sentinel's capture confidence, provenance and a SHA-256 digest of the raw
  response.
- Follow a small, bounded set of pivots: for a domain, the public IP addresses
  it resolves to are enriched with ASN, RDAP and (with a key) AbuseIPDB data.
- Produce informational findings that describe facts and attribute every
  third-party claim to the provider that made it.
- Optionally (`--correlate`) show explainable connections between the
  collected evidence, without making any new request.

**Sentinel OSINT does not:**

- Scan ports, probe services, brute-force subdomains, exploit anything, or
  authenticate against discovered infrastructure.
- Visit URLs, download files or malware samples, or contact hosts that appear
  in provider responses. URLs, hosts, IPs and hashes returned by a provider
  are data, never destinations.
- Upload or submit anything to any service.
- Decide that something is "malicious". There is no risk score, threat score
  or Sentinel verdict. Provider classifications are shown as the provider's
  own claims.

Only public indicators can be investigated: private, loopback, link-local,
multicast, reserved and other special-use addresses, and special-use domain
names (`.local`, `.internal`, `.onion`, `localhost`, …) are rejected before any
network activity.

## Requirements

- Rust toolchain with Cargo supporting the 2024 edition (Rust 1.85 or newer).
  v0.1.0 was built and tested with rustc/cargo 1.97.1. Install from
  <https://rustup.rs> if needed.
- A C compiler (gcc/clang, or MSVC on Windows). The TLS stack (rustls with the
  aws-lc-rs crypto provider) compiles native code. On Windows, CMake and NASM
  may also be required by `aws-lc-sys`.
- Network access for real investigations (DNS and HTTPS). The offline test
  suite needs no network once dependencies are downloaded.
- Optional: [`cargo-audit`](https://crates.io/crates/cargo-audit) to check
  dependencies for known vulnerabilities.

Linux is the tested platform. macOS and Windows are configured in CI but have
not been verified yet (limitation L2).

## Build

```bash
git clone https://github.com/TorranceTech/sentinel-osint.git
cd sentinel-osint
cargo build --release --locked
```

The binary is created at `target/release/sentinel-osint`
(`target\release\sentinel-osint.exe` on Windows). Run it from there, through
Cargo, or install it into `~/.cargo/bin`:

```bash
cargo run --release -p sentinel-cli -- investigate --domain example.com
cargo install --path crates/cli --locked

sentinel-osint --version   # sentinel-osint 0.1.0
```

## Quick start

No account or API key is needed for the basic sources.

```bash
# A domain: DNS records, SPF/DMARC/CAA analysis, CT certificates,
# and ASN/RDAP data for the addresses it resolves to.
sentinel-osint investigate --domain example.com

# An IP address: BGP origin (ASN) and RDAP registration data.
sentinel-osint investigate --ip 8.8.8.8

# The same, as JSON (for scripts, SIEMs, jq).
sentinel-osint investigate --ip 8.8.8.8 --format json

# Add the correlation section.
sentinel-osint investigate --domain example.com --correlate
```

A typical investigation takes a few seconds; Certificate Transparency
(crt.sh) is often the slowest source. The whole run is bounded by a deadline
(60 seconds by default).

## Command-line reference

```text
sentinel-osint [-v...] investigate
    (--domain DOMAIN | --ip IP | --hash HASH)
    [--format table|json]
    [--correlate]
    [--output FILE]
    [--timeout SECONDS]
```

| Option | Description |
|---|---|
| `-v`, `--verbose` | More log output on stderr; repeat for more (`-v` info, `-vv` debug, `-vvv` trace). Logs never contain API keys. |
| `-h`, `--help` / `-V`, `--version` | Help / version. |
| `--domain DOMAIN` | Domain to investigate. Internationalized names are normalized; defanged input is accepted. |
| `--ip IP` | Public IPv4 or IPv6 address. |
| `--hash HASH` | MD5 (32 hex), SHA-1 (40) or SHA-256 (64), case-insensitive. |
| `--format FORMAT` | `table` (default) or `json`. |
| `--correlate` | Add a Correlation section (table) or a `correlation` member (JSON). Off by default. |
| `-o`, `--output FILE` | Write the report to FILE (mode `0600` on Unix). An existing file is **never** overwritten. |
| `--timeout SECONDS` | Deadline for the whole investigation, 1–600 (default 60). |

Exactly one target is required.

**Defanged input.** Indicators copied from threat reports are refanged before
validation: `[.]`, `(.)`, `{.}`, `[dot]`, `(dot)`, `{dot}` (any case) become
`.`, `[:]` becomes `:`, `[://]` becomes `://`, `[@]` becomes `@`, and
`hxxp`/`hxxps` become `http`/`https`. Quote defanged values in your shell:

```bash
sentinel-osint investigate --domain "example[.]com"
```

**Output streams.** The report goes to stdout (or `--output FILE`); logs and
errors go to stderr, so the report can be piped or redirected safely.

## Workflows

### Investigate a domain

```bash
sentinel-osint investigate --domain example.com
```

Sources: DNS (A, AAAA, CNAME, MX, NS, SOA, TXT, CAA and `_dmarc.<domain>`
TXT), Certificate Transparency (crt.sh), and, for every public IP the domain
resolves to (up to 10 pivots): Team Cymru ASN, RDAP and, with a key,
AbuseIPDB. With keys, VirusTotal and URLhaus also look up the domain itself.

### Investigate an IP address

```bash
sentinel-osint investigate --ip 8.8.8.8
sentinel-osint investigate --ip 2001:4860:4860::8888
```

Sources: Team Cymru ASN and RDAP; with keys: AbuseIPDB, VirusTotal, URLhaus
(IPv4 only).

### Investigate a file hash

```bash
sentinel-osint investigate --hash <sha256>
```

Hash lookups use only keyed providers: VirusTotal (SHA-256) and MalwareBazaar
(SHA-256 and SHA-1). Without keys these sources show as `unavailable` and all
others as `unsupported` — that is expected. MD5 is accepted as input but no
v0.1 provider looks it up. Sentinel never downloads, uploads or executes
samples.

### JSON for automation

```bash
sentinel-osint investigate --domain example.com --format json > example.json
jq -r '.investigation.sources[] | "\(.source) \(.status)"' example.json
```

### Save a report, longer deadlines, debugging

```bash
sentinel-osint investigate --domain example.com --format json -o example.json
sentinel-osint --verbose investigate --domain example.com --timeout 120
sentinel-osint -vv investigate --domain example.com 2> debug.log
```

## Data sources

| Source ID | Service | Indicators | Key |
|---|---|---|---|
| `dns` | System DNS resolver | domain | — |
| `ct` | crt.sh (Certificate Transparency) | domain | — |
| `cymru` | Team Cymru IP-to-ASN (DNS) | IP (target and pivots) | — |
| `rdap` | RDAP via IANA bootstrap | IP (target and pivots) | — |
| `abuseipdb` | AbuseIPDB | IP (target and pivots) | `SENTINEL_ABUSEIPDB_KEY` |
| `virustotal` | VirusTotal API v3 | IP, domain, SHA-256 | `SENTINEL_VIRUSTOTAL_KEY` |
| `urlhaus` | abuse.ch URLhaus | domain, IPv4 | `SENTINEL_ABUSECH_KEY` |
| `malwarebazaar` | abuse.ch MalwareBazaar | SHA-256, SHA-1 | `SENTINEL_MALWAREBAZAAR_KEY` (or `SENTINEL_ABUSECH_KEY`) |

- DNS uses the system resolver configuration (not the hosts file). Only the
  fixed record types above are queried; no enumeration, no zone transfers, no
  lookups of discovered names.
- RDAP covers IP networks only (no domain RDAP in v0.1).
- VirusTotal, URLhaus and MalwareBazaar query only the investigation target,
  never pivots.
- Every request, including DNS collector queries, is charged to a budget of
  100 requests per investigation.

Endpoints, fields kept and discarded, rate limits and the documentation
consulted: [`docs/DATA-SOURCES.md`](docs/DATA-SOURCES.md).

## API keys (optional providers)

The four threat-intelligence providers are optional and enabled only when
their key is present in the environment. Without a key the source is still
listed with status `unavailable` and the reason, so a missing key is never
confused with "no results".

| Variable | Provider | Notes |
|---|---|---|
| `SENTINEL_ABUSEIPDB_KEY` | AbuseIPDB | free account at abuseipdb.com |
| `SENTINEL_VIRUSTOTAL_KEY` | VirusTotal | public API: 4 req/min, 500/day, non-commercial |
| `SENTINEL_ABUSECH_KEY` | URLhaus | abuse.ch Auth-Key from <https://auth.abuse.ch/> |
| `SENTINEL_MALWAREBAZAAR_KEY` | MalwareBazaar | falls back to `SENTINEL_ABUSECH_KEY` if unset |

```bash
export SENTINEL_VIRUSTOTAL_KEY='your-key'
SENTINEL_ABUSEIPDB_KEY='your-key' sentinel-osint investigate --ip 8.8.8.8   # one command only
```

```powershell
$env:SENTINEL_VIRUSTOTAL_KEY = 'your-key'
```

How keys are handled:

- Read only from environment variables in v0.1 (no config file yet).
- Must be non-empty printable ASCII without spaces, at most 256 characters.
  Invalid values are reported as "API key configuration is invalid" and never
  printed.
- If `SENTINEL_MALWAREBAZAAR_KEY` is set but empty or invalid, it is used
  as-is (and reported invalid); the fallback applies only when it is unset.
- Sent only in the provider's documented HTTP header, only over HTTPS, never
  in URLs, never across a cross-origin redirect. They never appear in reports,
  JSON, logs or error messages; a response that echoes a key is redacted.
- Never put keys in files inside the repository (`.env` and `config.toml` are
  git-ignored).
- You are responsible for each provider's terms of service. Sentinel sends at
  most one request per provider per target (AbuseIPDB: one per public IP,
  bounded by the pivot limit) and never retries. To stop a provider from being
  contacted, unset its key.

## Reading the table report

Abbreviated real output, no API keys set:

```text
Sentinel OSINT
Threat Intelligence Investigation

Target:    8.8.8.8
Type:      IPv4
Started:   2026-09-24 04:59:35 UTC
Duration:  0.4 s
ID:        4a673a09-ae41-4266-8012-8d4bdb7171f1

Infrastructure
────────────────────────────────────────────────────────────
8.8.8.8
  ASN           AS15169  GOOGLE - Google LLC, US
  BGP prefix    8.8.8.0/24
  Network       GOGL (NET-8-8-8-0-2)
  Range         8.8.8.0 – 8.8.8.255
  Organization  Google LLC
  ...

Findings (2)
────────────────────────────────────────────────────────────
  INFO    asn.origin
          BGP origin reported
          8.8.8.8 is announced by AS15169 (GOOGLE - Google LLC, US) in
          prefix 8.8.8.0/24, according to the source. A BGP origin
          identifies the network announcing the route; it does not
          establish ownership, control or intent.
  ...

Sources
────────────────────────────────────────────────────────────
  abuseipdb      unavailable API key not configured (set SENTINEL_ABUSEIPDB_KEY)
  virustotal     unavailable API key not configured (set SENTINEL_VIRUSTOTAL_KEY)
  urlhaus        unavailable API key not configured (set SENTINEL_ABUSECH_KEY)
  cymru          succeeded   2 observations   0.0 s
  rdap           succeeded   1 observation   0.4 s
  dns            unsupported no supported indicator in this investigation
  ct             unsupported no supported indicator in this investigation
  malwarebazaar  unsupported no supported indicator in this investigation

Evidence
────────────────────────────────────────────────────────────
  Observations    3 (3 with response digest)
  Relationships   2
  Details         --format json (IDs, provenance, timestamps, digests)
```

Sections, in order: header, DNS, Security Analysis (SPF/DMARC/CAA),
Certificate Transparency, Infrastructure, Threat Intelligence, Findings,
Correlation (only with `--correlate`), Sources, Evidence. Header, Findings,
Sources and Evidence always appear; the others only when there is data.

| Status | Meaning |
|---|---|
| `succeeded` | The source answered (it may still have found nothing; a provider's "no record" is a successful answer). |
| `partial` | Some of its queries failed; the rest is valid. |
| `unavailable` | Not run: API key missing or invalid. |
| `not run` | Not run: the request budget was exhausted. |
| `unsupported` | No indicator in this investigation is of a type it handles. |
| `failed` | HTTP error, invalid response, rate limit, … The reason is shown; a failure is never shown as "no data". |
| `timed out` | Cancelled by the per-source timeout or the investigation deadline. |

The table is plain text without colors or control sequences. All external
text is sanitized (control characters, ANSI escapes and bidi characters are
replaced) and long values are truncated with `…`. JSON contains full values.

## JSON output

```json
{
  "schema_version": "0.1",
  "investigation": {
    "id": "...",
    "target": { "type": "domain", "value": "example.com" },
    "tool": { "name": "sentinel-osint", "version": "0.1.0" },
    "started_at": "...Z",
    "finished_at": "...Z",
    "observations": [],
    "relationships": [],
    "findings": [],
    "sources": []
  }
}
```

With `--correlate` there is one more top-level member, `correlation`. Nothing
else is written to stdout.

- **observations** — one fact each: `id`, `indicator`, `source`,
  `collected_at` (UTC, RFC 3339), `data` (with a `kind` such as `dns_record`,
  `asn_origin`, `network_registration`, `ct_certificate`, `ip_reputation`,
  `provider_reputation`, `provider_listing`, `provider_no_record`),
  `confidence` (0–100), `provenance`, `raw_response_hash` (SHA-256).
- **relationships** — typed edges (`resolves_to`, `alias_of`,
  `has_mail_exchanger`, `has_nameserver`, `announced_by`, `registered_in`,
  `covers_name`, `covers_wildcard`), each citing its evidence by observation ID.
- **findings** — `code`, `severity`, `title`, `detail`, `confidence`,
  `evidence` (observation IDs).
- **sources** — one status per source (`succeeded`, `partial`, `unavailable`,
  `budget_exhausted`, `unsupported`, `failed`, `timed_out`).

`confidence` is Sentinel's confidence that it captured and parsed the data
correctly. It is **not** the provider's score and **not** a probability of
maliciousness. `schema_version` changes only for incompatible changes; new
fields may be added, so consumers should ignore unknown fields.

## Correlation (`--correlate`)

Correlation runs after all sources finish. It reads the finished
investigation only — no network, DNS or file access — and changes no data.

| Rule | What it shows |
|---|---|
| `domain_ip_infrastructure` | domain → IP (DNS) → origin AS (BGP) and registered network (RDAP), with conflicts (e.g. different ASNs, prefixes not containing the IP) and gaps. |
| `domain_certificate` | Certificates in CT that list the domain. |
| `ct_dns_names` | Related CT names that also appear in the collected DNS data (CT-only names are counted, never resolved). |
| `multiple_sources` | Several providers reported on the same indicator; each claim listed separately. |
| `source_disagreement` | Providers disagree; both sides shown, Sentinel does not decide who is right. |
| `shared_infrastructure` | Several indicators share an AS, network, IP or certificate (no implication of common ownership or intent). |

Every correlation shows its links, the evidence behind each link, conflicts,
gaps, the time window of its evidence and caveats. There are no scores.
Details: [`docs/CORRELATION.md`](docs/CORRELATION.md).

## Findings

Each finding has a stable code (e.g. `dns.dmarc.missing`,
`ti.virustotal.detections`), a severity, a title and an explanation citing
its evidence.

| Severity | Rule |
|---|---|
| `info` | A fact, including every infrastructure, CT, threat-intelligence and correlation finding. |
| `low` | An expected DNS security record is missing, discouraged or malformed. |
| `medium` | A DNS configuration defeats its own mechanism (e.g. SPF `+all`, multiple SPF or DMARC records). |

- Threat-intelligence findings (`ti.*`) repeat what a provider reports and say
  so explicitly. They are always `info`; a provider's score never raises a
  Sentinel severity.
- "No results" from a provider is not evidence that something is benign.
- BGP origin, RDAP registration, shared hosting and CT certificates describe
  infrastructure context, not ownership, control or intent.

All codes and conditions: [`docs/FINDINGS.md`](docs/FINDINGS.md).

## Safety, privacy and OPSEC

- Looking up an indicator can reveal your interest in it: DNS queries reach
  the owner's nameservers, and every enabled provider learns what you queried.
  Consider this before investigating indicators tied to an active incident.
- Sentinel only performs lookups. It never uploads files, submits URLs,
  downloads samples, or connects to the investigated host.
- All network access goes through one hardened HTTP client: HTTPS only,
  connections to private/loopback/link-local/metadata addresses refused (also
  after DNS resolution and on every redirect), at most 3 redirects,
  response-size limits, timeouts and a per-investigation request budget.
- Personal data returned by providers (reporter names, comments, file names,
  WHOIS contacts, e-mail addresses in certificates, …) is dropped or counted,
  not stored.
- Reports can contain sensitive incident data; `--output` creates files
  readable only by you.
- Use the tool only for authorized, defensive purposes — see
  [`docs/ETHICS.md`](docs/ETHICS.md).

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Investigation completed. Individual sources may have failed (see Sources); a failed source never aborts the run. |
| `1` | Fatal error: report file exists or cannot be written, system DNS configuration cannot be loaded, runtime cannot start. |
| `2` | Invalid usage or input, detected before any network activity (no/several targets, unknown option, `--timeout` out of range, invalid or non-public indicator). |

```text
$ sentinel-osint investigate --ip 10.0.0.1
error: 10.0.0.1 is a private (RFC 1918) address; only publicly routable
addresses can be investigated
```

## Running the tests

The suite runs offline: external services are replaced by local mock servers
and a fake DNS resolver.

```bash
cargo test --workspace --all-features --locked
```

Full quality gate:

```bash
cargo build --workspace --locked
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo audit --deny warnings
cargo build --release --locked
```

Live tests (real network, opt-in):

```bash
cargo test -p sentinel-cli -- --ignored
```

`live_ip_investigation` and `live_domain_investigation` need network but no
keys. The VirusTotal, URLhaus and MalwareBazaar live tests run only when their
key is set (otherwise they print `skipped: ...` and pass) and perform lookups
only.

After an intentional table layout change, regenerate the golden files and
review the diff: `UPDATE_GOLDEN=1 cargo test -p sentinel-report`.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `unavailable API key not configured (set ...)` | Optional provider; export the variable shown. |
| `unavailable API key configuration is invalid` | Variable is empty, not UTF-8, contains spaces or non-ASCII, or exceeds 256 characters. |
| `failed ... (HTTP 401)` / `(HTTP 403)` | Key rejected or plan does not allow the request. |
| `failed ... rate limit exceeded (HTTP 429)` | Provider quota reached; wait and retry. Sentinel does not retry. |
| `ct` failed or timed out | crt.sh is often slow or down (HTTP 502/429); retry later or raise `--timeout`. |
| `timed out   investigation deadline` | Use a larger `--timeout` (max 600). |
| `not run     request budget ... exhausted` | The 100-request budget was reached. |
| `error: refusing to overwrite existing file` | `--output` never overwrites; pick another name. |
| Build fails in `aws-lc-sys` | Install a C compiler (and CMake/NASM on Windows). |

Add `-v`, `-vv` or `-vvv` for more detail (logs go to stderr and never include
keys).

## Scope of v0.1 and known limitations

v0.1.0 is the feature-complete baseline. Intentionally **out of scope**: STIX
export, MITRE ATT&CK mapping, cross-investigation and multi-hop correlation,
provider score aggregation and verdict synthesis, automatic pivots from
third-party content, sample downloads, additional providers, persistence and
history, a configuration file, `--sources`, URL targets on the CLI, and domain
RDAP.

Selected known limitations (the full list, L1–L53, is in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)):

- No DNSSEC validation; only the system resolver is used.
- crt.sh is the only CT source; very large CT results (> 8 MiB) fail.
- HTTP 429 and `Retry-After` are reported, never retried.
- AbuseIPDB, VirusTotal, URLhaus and MalwareBazaar have been verified against
  official documentation and mock servers only, not with real keys.
- Correlation IDs are stable within one investigation, not across runs.
- Windows and macOS builds have not been verified in CI yet.

## Project layout and documentation

```text
crates/
├── core/         sentinel-core         domain model: indicators, observations,
│                                       evidence, relationships, findings (no I/O)
├── collectors/   sentinel-collectors   hardened HTTP client, DNS, engine, data sources
├── correlation/  sentinel-correlation  explainable correlation (no I/O)
├── report/       sentinel-report       table and JSON renderers
└── cli/          sentinel-cli          the sentinel-osint binary
```

| Document | Contents |
|---|---|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Design, data model, v0.1 scope, known limitations |
| [`docs/DATA-SOURCES.md`](docs/DATA-SOURCES.md) | Every source in detail, with the documentation used |
| [`docs/FINDINGS.md`](docs/FINDINGS.md) | All finding codes and severity rules |
| [`docs/CORRELATION.md`](docs/CORRELATION.md) | Correlation rules, conflicts, determinism |
| [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) | Threats to the tool and their mitigations |
| [`docs/ETHICS.md`](docs/ETHICS.md) | Acceptable use and capability levels |
| [`SECURITY.md`](SECURITY.md) | How to report a vulnerability |
| [`CLAUDE.md`](CLAUDE.md) | Engineering rules for contributors |

## Security and license

Please report vulnerabilities privately as described in
[`SECURITY.md`](SECURITY.md), not in public issues.

Dual-licensed under the [MIT License](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
