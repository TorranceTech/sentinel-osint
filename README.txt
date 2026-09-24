SENTINEL OSINT v0.1.0
=====================

Passive-first OSINT and threat-intelligence investigation tool, written in Rust.

Give it one indicator (a domain name, an IP address or a file hash). It
collects public intelligence from legitimate sources, records every result as
evidence with provenance (source, time, confidence, response digest), derives
informational findings, and prints a report as a terminal table or as JSON.

It is built for defensive work: SOC triage, CTI enrichment, incident response,
security research and cybersecurity education.


CONTENTS
--------

  1.  What Sentinel OSINT does (and does not do)
  2.  Requirements
  3.  Getting the code and building it
  4.  Quick start
  5.  Command-line reference
  6.  Workflows
  7.  Data sources
  8.  API keys (optional providers)
  9.  Reading the table report
  10. JSON output
  11. Correlation (--correlate)
  12. Findings and how to interpret them
  13. Safety, privacy and OPSEC
  14. Exit codes and errors
  15. Running the tests
  16. Troubleshooting
  17. Scope of v0.1 and known limitations
  18. Project layout and further documentation
  19. Security reporting and license


1. WHAT SENTINEL OSINT DOES (AND DOES NOT DO)
--------------------------------------------

Sentinel OSINT DOES:

  * Look up an indicator in public, legitimate sources (DNS, Team Cymru,
    RDAP registries, Certificate Transparency via crt.sh) and, if you
    provide API keys, in threat-intelligence services (AbuseIPDB,
    VirusTotal, URLhaus, MalwareBazaar).
  * Record every fact as an observation with its source, collection time,
    Sentinel's capture confidence, provenance and a SHA-256 digest of the
    raw response.
  * Follow a small, bounded set of pivots: for a domain, the public IP
    addresses it resolves to are enriched with ASN, RDAP and (with a key)
    AbuseIPDB data.
  * Produce informational findings that describe facts and attribute every
    third-party claim to the provider that made it.
  * Optionally (--correlate) show explainable connections between the
    collected evidence, without making any new request.

Sentinel OSINT does NOT:

  * Scan ports, probe services, brute-force subdomains, exploit anything,
    or authenticate against discovered infrastructure.
  * Visit URLs, download files or malware samples, or contact hosts that
    appear in provider responses. URLs, hosts, IPs and hashes returned by a
    provider are data, never destinations.
  * Upload or submit anything to any service.
  * Decide that something is "malicious". There is no risk score, threat
    score or Sentinel verdict. Provider classifications are shown as the
    provider's own claims.

Only public indicators can be investigated: private, loopback, link-local,
multicast, reserved and other special-use addresses, and special-use domain
names (.local, .internal, .onion, localhost, ...), are rejected before any
network activity.


2. REQUIREMENTS
---------------

  * Rust toolchain with Cargo, supporting the 2024 edition (Rust 1.85 or
    newer). v0.1.0 was built and tested with rustc/cargo 1.97.1.
    Install from https://rustup.rs if needed.
  * A C compiler (gcc/clang, or MSVC on Windows). The TLS stack (rustls
    with the aws-lc-rs crypto provider) compiles native code. On Windows,
    CMake and NASM may also be required by aws-lc-sys; see the aws-lc-rs
    documentation if the build fails there.
  * Network access for real investigations (DNS and HTTPS). Building and
    running the offline test suite does not need network access once the
    dependencies are downloaded.
  * Optional: cargo-audit (cargo install cargo-audit) to check dependencies
    for known vulnerabilities.

Supported platforms: Linux is the tested platform. macOS and Windows are
configured in CI but have not been run yet (limitation L2).


3. GETTING THE CODE AND BUILDING IT
-----------------------------------

The public repository URL has not been decided yet (TODO(repository-url)).
If you received the source as a git repository or archive:

    git clone <repository-url> sentinel-osint      # or unpack the archive
    cd sentinel-osint

Build a release binary (recommended for normal use):

    cargo build --release --locked

The binary is created at:

    target/release/sentinel-osint          (Linux, macOS)
    target\release\sentinel-osint.exe      (Windows)

You can run it directly from there, or through Cargo:

    cargo run --release -p sentinel-cli -- investigate --domain example.com

Optionally install it into ~/.cargo/bin (make sure that directory is on your
PATH):

    cargo install --path crates/cli --locked

Check that it works:

    ./target/release/sentinel-osint --version
    # sentinel-osint 0.1.0

The examples below write "sentinel-osint" for the binary; replace it with the
full path (./target/release/sentinel-osint) if you did not install it.


4. QUICK START
--------------

No account or API key is needed for the basic sources.

    # A domain: DNS records, SPF/DMARC/CAA analysis, CT certificates,
    # and ASN/RDAP data for the addresses it resolves to.
    sentinel-osint investigate --domain example.com

    # An IP address: BGP origin (ASN) and RDAP registration data.
    sentinel-osint investigate --ip 8.8.8.8

    # The same, as JSON (for scripts, SIEMs, jq).
    sentinel-osint investigate --ip 8.8.8.8 --format json

    # Add the correlation section.
    sentinel-osint investigate --domain example.com --correlate

A typical investigation takes a few seconds; Certificate Transparency
(crt.sh) is often the slowest source. The whole run is bounded by a deadline
(60 seconds by default).


5. COMMAND-LINE REFERENCE
-------------------------

    sentinel-osint [-v...] investigate
        (--domain DOMAIN | --ip IP | --hash HASH)
        [--format table|json]
        [--correlate]
        [--output FILE]
        [--timeout SECONDS]

Global options:

  -v, --verbose     More log output on stderr. Repeat for more detail:
                    (none) warnings only, -v info, -vv debug, -vvv trace.
                    Logs never contain API keys.
  -h, --help        Print help (also: sentinel-osint investigate --help).
  -V, --version     Print the version.

investigate options (exactly one target is required):

  --domain DOMAIN   Domain name to investigate. Internationalized names are
                    accepted and normalized. Defanged input is accepted
                    (see below).
  --ip IP           Public IPv4 or IPv6 address to investigate.
  --hash HASH       File hash to investigate: MD5 (32 hex characters),
                    SHA-1 (40) or SHA-256 (64). Case-insensitive.

  --format FORMAT   "table" (default): human-readable report.
                    "json": machine-readable document (section 10).

  --correlate       Add a Correlation section (table) or a "correlation"
                    member (JSON). Off by default; without it the output is
                    exactly the same as before this option existed.

  -o, --output FILE Write the report to FILE instead of stdout. The file is
                    created with permissions 0600 on Unix and an existing
                    file is NEVER overwritten (the command fails instead).
                    A confirmation line is printed on stderr.

  --timeout SECONDS Deadline for the whole investigation, 1 to 600 seconds
                    (default 60). Sources still running at the deadline are
                    cancelled and reported as "timed out".

Defanged input. Indicators copied from threat reports are refanged
automatically before validation: "[.]", "(.)", "{.}", "[dot]", "(dot)",
"{dot}" (any case) become ".", "[:]" becomes ":", "[://]" becomes "://",
"[@]" becomes "@", and "hxxp"/"hxxps" become "http"/"https". Examples:

    sentinel-osint investigate --domain "example[.]com"
    sentinel-osint investigate --ip "8.8.8[.]8"

Quote defanged values in your shell, because brackets and parentheses are
special characters in many shells.

Output streams: the report goes to stdout (or to --output FILE); logs and
error messages go to stderr. This lets you pipe or redirect the report
safely:

    sentinel-osint investigate --ip 8.8.8.8 --format json > report.json


6. WORKFLOWS
------------

6.1 Investigate a domain

    sentinel-osint investigate --domain example.com

  Sources used: DNS (A, AAAA, CNAME, MX, NS, SOA, TXT, CAA and
  _dmarc.<domain> TXT), Certificate Transparency (crt.sh), and, for every
  public IP address the domain resolves to (up to 10 pivots): Team Cymru
  ASN, RDAP and, with a key, AbuseIPDB. With keys, VirusTotal and URLhaus
  also look up the domain itself.

  The report contains the DNS records, a Security Analysis of SPF, DMARC
  and CAA, the certificates seen in CT, the infrastructure behind each
  address, provider claims (if keys are set), findings, source statuses and
  an evidence summary.

6.2 Investigate an IP address

    sentinel-osint investigate --ip 8.8.8.8
    sentinel-osint investigate --ip 2001:4860:4860::8888

  Sources used: Team Cymru ASN and RDAP, and with keys: AbuseIPDB,
  VirusTotal, URLhaus (IPv4 only).

6.3 Investigate a file hash

    sentinel-osint investigate --hash <sha256>
    sentinel-osint investigate --hash <sha1>

  Hash lookups use only keyed providers: VirusTotal (SHA-256 only) and
  MalwareBazaar (SHA-256 and SHA-1). Without keys the report shows these
  sources as "unavailable" and every other source as "unsupported" -- that
  is expected. MD5 hashes are accepted as input but no v0.1 provider looks
  them up, so every source is reported as unavailable or unsupported.
  Sentinel never downloads, uploads or executes samples.

6.4 Produce JSON for automation

    sentinel-osint investigate --domain example.com --format json > example.json

    # Example with jq: list every source and its status
    jq -r '.investigation.sources[] | "\(.source) \(.status)"' example.json

6.5 Save a report to a file

    sentinel-osint investigate --domain example.com --output example.txt
    sentinel-osint investigate --domain example.com --format json -o example.json

  The command refuses to overwrite an existing file; choose a new name or
  delete the old file yourself. Treat saved reports as sensitive (see
  section 13).

6.6 Explainable correlation

    sentinel-osint investigate --domain example.com --correlate
    sentinel-osint investigate --domain example.com --correlate --format json

  See section 11.

6.7 Use the optional threat-intelligence providers

    export SENTINEL_VIRUSTOTAL_KEY='...'     # your own key
    sentinel-osint investigate --domain example.com

  See section 8 for all variables.

6.8 Longer deadlines and troubleshooting output

    sentinel-osint --verbose investigate --domain example.com --timeout 120
    sentinel-osint -vv investigate --domain example.com 2> debug.log


7. DATA SOURCES
---------------

  Source ID       Service                          Indicators              Key
  --------------- -------------------------------- ----------------------- ---------------------------
  dns             System DNS resolver              domain                  no
  ct              crt.sh (Certificate Transparency) domain                 no
  cymru           Team Cymru IP-to-ASN (DNS)       IP (target and pivots)  no
  rdap            RDAP via IANA bootstrap          IP (target and pivots)  no
  abuseipdb       AbuseIPDB                        IP (target and pivots)  SENTINEL_ABUSEIPDB_KEY
  virustotal      VirusTotal API v3                IP, domain, SHA-256     SENTINEL_VIRUSTOTAL_KEY
  urlhaus         abuse.ch URLhaus                 domain, IPv4            SENTINEL_ABUSECH_KEY
  malwarebazaar   abuse.ch MalwareBazaar           SHA-256, SHA-1          SENTINEL_MALWAREBAZAAR_KEY
                                                                           (or SENTINEL_ABUSECH_KEY)

Notes:

  * DNS uses your system resolver configuration (the hosts file is not
    used). Only the fixed set of record types listed above is queried; no
    enumeration, no zone transfers, no lookups of discovered names.
  * RDAP covers IP networks only (no domain RDAP in v0.1).
  * VirusTotal, URLhaus and MalwareBazaar query only the investigation
    target, never pivots. VirusTotal URL lookups exist in the library but
    the CLI has no URL target in v0.1.
  * Every request, including DNS collector queries, is charged to a request
    budget of 100 per investigation.

The full description of each source (endpoints, fields kept and discarded,
rate limits, documentation consulted) is in docs/DATA-SOURCES.md.


8. API KEYS (OPTIONAL PROVIDERS)
--------------------------------

The four threat-intelligence providers are optional. Each is enabled only
when its API key is present in the environment. Without a key, the source is
still listed in the report with the status "unavailable" and the reason, so
a missing key is never confused with "no results".

  Variable                      Provider           Notes
  ----------------------------- ------------------ ---------------------------------
  SENTINEL_ABUSEIPDB_KEY        AbuseIPDB          free account at abuseipdb.com
  SENTINEL_VIRUSTOTAL_KEY       VirusTotal         public API: 4 requests/minute,
                                                   500/day, non-commercial use only
  SENTINEL_ABUSECH_KEY          URLhaus            abuse.ch Auth-Key from
                                                   https://auth.abuse.ch/
  SENTINEL_MALWAREBAZAAR_KEY    MalwareBazaar      if unset, SENTINEL_ABUSECH_KEY is
                                                   used (same abuse.ch Auth-Key)

Setting keys (Linux/macOS shells):

    export SENTINEL_VIRUSTOTAL_KEY='your-key'
    export SENTINEL_ABUSECH_KEY='your-abuse.ch-auth-key'

For a single command only:

    SENTINEL_ABUSEIPDB_KEY='your-key' sentinel-osint investigate --ip 8.8.8.8

Windows PowerShell:

    $env:SENTINEL_VIRUSTOTAL_KEY = 'your-key'

Handling of keys:

  * Keys are read only from environment variables in v0.1 (there is no
    config file yet).
  * A key must be non-empty printable ASCII without spaces (at most 256
    characters). An invalid value is reported as "API key configuration is
    invalid"; it is never printed.
  * If SENTINEL_MALWAREBAZAAR_KEY is set but empty or invalid, it is used
    as-is (and reported as invalid); the SENTINEL_ABUSECH_KEY fallback only
    applies when SENTINEL_MALWAREBAZAAR_KEY is not set at all.
  * Keys are sent only in the provider's documented HTTP header, only over
    HTTPS, never in URLs, and never across a redirect to another origin.
    They never appear in reports, JSON, logs (at any -v level) or error
    messages. A response that echoes a key is redacted before storage.
  * Never put keys in files inside the repository. .env files and
    config.toml are listed in .gitignore.
  * You are responsible for each provider's terms of service and rate
    limits. Sentinel sends at most one request per provider per target
    (AbuseIPDB: one per public IP, bounded by the pivot limit) and never
    retries.

To stop a provider from being contacted, unset its key (a --sources option
does not exist in v0.1):

    unset SENTINEL_VIRUSTOTAL_KEY


9. READING THE TABLE REPORT
---------------------------

Example (abbreviated, real output, no API keys set):

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

Sections, in this order: header, DNS, Security Analysis (SPF/DMARC/CAA),
Certificate Transparency, Infrastructure, Threat Intelligence, Findings,
Correlation (only with --correlate), Sources, Evidence. The header,
Findings, Sources and Evidence always appear ("No findings." when there are
none); the other sections appear only when there is data for them.

Source statuses:

  succeeded     The source answered. (It may still have found nothing; e.g.
                a provider's "no record" is a successful answer.)
  partial       Some of its queries failed; the rest is valid.
  unavailable   Not run: API key missing or invalid.
  not run       Not run: the request budget was exhausted.
  unsupported   No indicator in this investigation is of a type it handles.
  failed        The source failed (HTTP error, invalid response, rate limit,
                ...). The reason is shown. A failure is never shown as
                "no data".
  timed out     Cancelled by the per-source timeout or the investigation
                deadline.

The table report is plain text with no colors or terminal control sequences.
All text that comes from external sources is sanitized (control characters,
ANSI escapes and bidi characters are replaced) and long values are
truncated with "…". The JSON output contains the full values.


10. JSON OUTPUT
---------------

    sentinel-osint investigate --domain example.com --format json

The document is:

    {
      "schema_version": "0.1",
      "investigation": {
        "id": "...",
        "target": { "type": "domain", "value": "example.com" },
        "tool": { "name": "sentinel-osint", "version": "0.1.0" },
        "started_at": "...Z",
        "finished_at": "...Z",
        "observations": [ ... ],
        "relationships": [ ... ],
        "findings": [ ... ],
        "sources": [ ... ]
      }
    }

With --correlate there is one more top-level member, "correlation" (section
11). Nothing else is written to stdout, so the output can be piped straight
into jq or a SIEM.

  * observations: one fact each, with "id", "indicator", "source",
    "collected_at" (UTC, RFC 3339), "data" (with a "kind" such as
    dns_record, asn_origin, network_registration, ct_certificate,
    ip_reputation, provider_reputation, provider_listing,
    provider_no_record), "confidence" (0-100), "provenance" and
    "raw_response_hash" (SHA-256).
  * relationships: typed edges between entities (resolves_to, alias_of,
    has_mail_exchanger, has_nameserver, announced_by, registered_in,
    covers_name, covers_wildcard), each citing its evidence by observation
    ID.
  * findings: "code", "severity", "title", "detail", "confidence",
    "evidence" (observation IDs).
  * sources: one status per source run ("status" is succeeded, partial,
    unavailable, budget_exhausted, unsupported, failed or timed_out).

"confidence" is Sentinel's confidence that it captured and parsed the data
correctly. It is NOT the provider's score and NOT a probability of
maliciousness.

schema_version changes only for incompatible changes; new fields may be
added, so consumers should ignore unknown fields.


11. CORRELATION (--correlate)
-----------------------------

Correlation runs after all sources have finished. It reads the finished
investigation only: it makes no network, DNS or file access and changes no
data. It shows how existing observations connect:

  domain_ip_infrastructure  domain -> IP (DNS) -> origin AS (BGP) and
                            registered network (RDAP), with conflicts
                            (e.g. different ASNs reported, prefixes that do
                            not contain the IP) and gaps (missing links and
                            the source status that explains them).
  domain_certificate        certificates in CT that list the domain.
  ct_dns_names              related names seen in CT that also appear in the
                            DNS data already collected (CT-only names are
                            counted, never resolved).
  multiple_sources          several providers reported on the same
                            indicator; each claim is listed separately.
  source_disagreement       providers disagree (e.g. one reports detections,
                            another has no record). Both sides are shown;
                            Sentinel does not decide who is right.
  shared_infrastructure     several indicators share an AS, network, IP or
                            certificate (this does not imply common
                            ownership or intent).

Every correlation shows its links, the evidence behind each link (source,
collection time, capture confidence, digest), conflicts, gaps, the time
window of its evidence and its caveats. There are no scores. In JSON,
correlations reference observations by ID; each also has a "correlation.*"
finding (always "info").

Details: docs/CORRELATION.md.


12. FINDINGS AND HOW TO INTERPRET THEM
--------------------------------------

Each finding has a stable code (for example dns.dmarc.missing,
ti.virustotal.detections) that automation can rely on, a severity, a title
and an explanation that cites its evidence.

Severities follow fixed rules:

  info     A fact (including every infrastructure, CT, threat-intelligence
           and correlation finding).
  low      An expected DNS security record is missing, discouraged or
           malformed.
  medium   A DNS configuration defeats its own mechanism (e.g. SPF "+all",
           multiple SPF or DMARC records).

Important:

  * Threat-intelligence findings (ti.*) repeat what a provider reports and
    say so explicitly ("VirusTotal reports ...", "URLhaus lists ...",
    "MalwareBazaar reports ..."). They are always "info". A provider's
    score never raises a Sentinel severity.
  * "No results" from a provider (no reports, no detections, no record) is
    not evidence that something is benign; the findings say so.
  * BGP origin, RDAP registration, shared hosting and CT certificates
    describe infrastructure context, not ownership, control or intent.

The complete list of codes and their conditions: docs/FINDINGS.md.


13. SAFETY, PRIVACY AND OPSEC
-----------------------------

  * Looking up an indicator can reveal your interest in it: DNS queries
    eventually reach the indicator owner's nameservers, and every provider
    you enable learns what you queried (IPs, domains, hashes). Consider
    this before investigating indicators tied to an active incident.
  * Sentinel only performs lookups. It never uploads files, submits URLs
    for scanning, downloads samples, or connects to the investigated host.
  * All network access goes through one hardened HTTP client: HTTPS only,
    connections to private/loopback/link-local/metadata addresses refused
    (also after DNS resolution and on every redirect), at most 3 redirects,
    response-size limits, timeouts, and a per-investigation request budget.
  * Personal data returned by providers (reporter names, comments, file
    names, WHOIS contacts, e-mail addresses in certificates, ...) is dropped
    or counted, not stored.
  * Reports can contain sensitive incident data. Store them with care;
    --output creates files readable only by you (0600 on Unix).
  * Use the tool only for authorized, defensive purposes. See
    docs/ETHICS.md.


14. EXIT CODES AND ERRORS
-------------------------

  0   The investigation completed. Individual sources may have failed; see
      the Sources section (a failed source never aborts the investigation).
  1   Fatal error: the report file already exists or cannot be written,
      the system DNS configuration cannot be loaded, the runtime cannot
      start.
  2   Invalid usage or input, detected before any network activity: no or
      several targets, an unknown option or format, --timeout out of range,
      an invalid indicator, or a non-public target.

Examples:

    $ sentinel-osint investigate --ip 10.0.0.1
    error: 10.0.0.1 is a private (RFC 1918) address; only publicly routable
    addresses can be investigated
    (exit code 2)

    $ sentinel-osint investigate --domain example.com --timeout 0
    error: invalid value '0' for '--timeout <SECONDS>': 0 is not in 1..=600
    (exit code 2)


15. RUNNING THE TESTS
---------------------

The test suite runs offline: external services are replaced by local mock
servers and a fake DNS resolver.

    cargo test --workspace --all-features --locked

v0.1.0 result: 506 tests passed, 0 failed, 5 ignored (the 5 ignored tests
are the live tests below).

Full quality gate used for the release:

    cargo build --workspace --locked
    cargo fmt --all --check
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
    cargo test --workspace --all-features --locked
    cargo audit --deny warnings
    cargo build --release --locked

Live tests (real network, opt-in):

    cargo test -p sentinel-cli -- --ignored

  * live_ip_investigation and live_domain_investigation need network access
    but no keys.
  * live_virustotal_lookup, live_urlhaus_lookup and
    live_malwarebazaar_lookup run only when SENTINEL_VIRUSTOTAL_KEY,
    SENTINEL_ABUSECH_KEY or SENTINEL_MALWAREBAZAAR_KEY is set; otherwise
    they print "skipped: ..." and pass. They perform lookups only (the
    MalwareBazaar test uses the hash from the official API documentation
    and never downloads anything).

After an intentional change to the table layout, regenerate the golden
files and review the diff:

    UPDATE_GOLDEN=1 cargo test -p sentinel-report


16. TROUBLESHOOTING
-------------------

  "unavailable API key not configured (set ...)"
      The provider is optional; export the variable shown (section 8).

  "unavailable API key configuration is invalid"
      The variable is set but empty, not valid UTF-8, contains spaces or
      non-ASCII characters, or is longer than 256 characters.

  "failed ... (HTTP 401)" / "(HTTP 403)"
      The provider rejected the key or the account/plan does not allow the
      request.

  "failed ... rate limit exceeded (HTTP 429)" / "quota"
      Provider quota reached (VirusTotal's public API allows 4 requests per
      minute). Wait and run again; Sentinel does not retry.

  ct "failed" or "timed out"
      crt.sh is often slow or temporarily unavailable (HTTP 502/429). Try
      again later or raise --timeout.

  "timed out   investigation deadline"
      The global deadline was reached; use a larger --timeout (max 600).

  "not run     request budget of N requests exhausted"
      The investigation reached its request budget (100).

  "error: refusing to overwrite existing file ..."
      --output never overwrites files; pick another name (exit code 1).

  Build fails in aws-lc-sys
      Install a C compiler (and CMake/NASM on Windows).

  Need more detail
      Add -v, -vv or -vvv (logs go to stderr and never include keys).


17. SCOPE OF v0.1 AND KNOWN LIMITATIONS
---------------------------------------

v0.1.0 is the feature-complete baseline. The following are intentionally
OUT OF SCOPE for v0.1 and are not implemented:

  * STIX export (--format stix does not exist)
  * MITRE ATT&CK mapping
  * cross-investigation correlation and transitive (multi-hop) correlation
  * provider score aggregation and provider verdict synthesis
  * automatic pivots from third-party content (URLs, hosts, IPs, hashes,
    files, CT names)
  * MalwareBazaar/URLhaus payload (sample) downloads
  * additional provider integrations
  * persistence, history and storage
  * a configuration file (keys come from environment variables only)
  * --sources (choosing sources per run; unset a key instead)
  * URL targets on the command line
  * domain RDAP

Selected known limitations (the full numbered list, L1-L53, is in
docs/ARCHITECTURE.md):

  * No DNSSEC validation; only the system resolver is used.
  * crt.sh is the only CT source; very large CT results (> 8 MiB) fail.
  * HTTP 429 and Retry-After are reported, never retried.
  * Live behavior of AbuseIPDB, VirusTotal, URLhaus and MalwareBazaar has
    been verified against official documentation and mock servers only; no
    live test has run with real keys. MalwareBazaar's get_info response
    envelope is not documented by the provider (L49).
  * Correlation IDs are stable for one investigation, not across runs.
  * Windows and macOS builds have not been verified in CI yet.


18. PROJECT LAYOUT AND FURTHER DOCUMENTATION
--------------------------------------------

  crates/core/          sentinel-core         domain model: indicators,
                                              observations, evidence,
                                              relationships, findings (no I/O)
  crates/collectors/    sentinel-collectors   hardened HTTP client, DNS,
                                              engine, all data sources
  crates/correlation/   sentinel-correlation  explainable correlation (no I/O)
  crates/report/        sentinel-report       table and JSON renderers
  crates/cli/           sentinel-cli          the sentinel-osint binary

  docs/ARCHITECTURE.md  design, data model, v0.1 scope, known limitations
  docs/DATA-SOURCES.md  every source in detail, with the documentation used
  docs/FINDINGS.md      all finding codes and severity rules
  docs/CORRELATION.md   correlation rules, conflicts, determinism
  docs/THREAT-MODEL.md  threats to the tool and their mitigations
  docs/ETHICS.md        acceptable use and capability levels
  SECURITY.md           how to report a vulnerability
  CLAUDE.md             engineering rules for contributors


19. SECURITY REPORTING AND LICENSE
----------------------------------

Please report vulnerabilities privately as described in SECURITY.md, not in
public issues.

Sentinel OSINT is dual-licensed under the MIT License (LICENSE-MIT) or the
Apache License, Version 2.0 (LICENSE-APACHE), at your option.
