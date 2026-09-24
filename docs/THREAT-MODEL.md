# Threat Model

This is the threat model of **Sentinel OSINT itself**: how the tool, its user,
and its data could be harmed. A tool that ingests adversary-controlled data from
the internet has to be engineered as a security product.

## System overview and trust boundaries

```
 [Analyst] ──CLI args──▶ [sentinel-osint] ──HTTPS/DNS──▶ [External sources]
     ▲                        │   ▲                         (untrusted)
     │                        │   └── environment (API keys)
     └──── table/JSON ◀───────┘       (+ optional correlation: pure, no I/O)
```

| Boundary | Trust |
|---|---|
| CLI arguments | Semi-trusted (the operator), but validated strictly |
| Environment (v0.1 has no config file) | Trusted, but contains secrets |
| Correlation output | Derived from untrusted data; computed without I/O, references evidence by ID |
| DNS answers, RDAP, CT logs, API responses | **Untrusted.** May be adversary-controlled |
| Generated reports | Contain untrusted data; consumed by terminals, SIEMs, TIPs, humans |

## Assets

| Asset | Why it matters |
|---|---|
| API keys | Abuse, quota theft, account suspension |
| Investigation targets | Revealing what an analyst is investigating can alert an adversary or leak incident details |
| Investigation output | May contain sensitive incident data (TLP) |
| Analyst host | Code execution or SSRF would compromise the analyst |
| Report consumers | Terminals and downstream tools can be attacked through output |
| Supply chain | Dependencies run with the analyst's privileges |

## Threats and mitigations

### T1: Malicious or malformed source responses
An adversary controls DNS TXT records, RDAP fields, and certificate SANs for
their own infrastructure, and a compromised or buggy API can return anything.
- Strongly typed deserialization with `serde`; unknown or invalid fields are
  rejected or ignored, never `eval`'d or executed.
- Response-size caps on every HTTP read; caps on list lengths (32 DNS records
  per query, 2 KiB per TXT record, bounded SPF terms/DMARC tags/CAA values;
  CT limits in step 5).
- Parsers of external formats (SPF, DMARC, CAA) are total: they never panic
  (property-tested with arbitrary input) and record problems as findings.
- No `unwrap` on external data. Parser tests cover malformed, oversized, and
  hostile input.
- Content is never interpreted as instructions by code or by AI agents
  working on the repo (see `CLAUDE.md`).

### T2: Terminal and report injection
A TXT record or certificate name can contain ANSI escape sequences, control
characters, or bidi overrides that rewrite the analyst's terminal or disguise
output.
- The table renderer replaces C0/C1 control characters (which neutralizes
  ANSI escape sequences) and bidi/invisible format characters in every
  external string, and bounds value length. Tested with hostile TXT/MX/CAA
  content and a mutation test.
- JSON is produced only by `serde_json` (correct escaping). STIX is out of
  scope for v0.1.
- **Log injection.** Log fields carry only validated or encoded values
  (normalized indicators, percent-encoded sanitized URLs, fixed error
  texts). Free text in source statuses is passed through
  `sentinel_core::text::sanitize_single_line` when the status is created.
- Future HTML reports must HTML-escape everything (Phase 2 requirement).

### T3: SSRF, DNS rebinding and redirects
Implemented in `crates/collectors/src/http/`. The rules live in
`policy.rs` and are enforced at three points:

1. **Before sending**: HTTPS only, no `user:pass@`, and IP-literal hosts
   must be globally routable (`sentinel_core::net::classify`, which also
   catches IPv4-mapped/NAT64/6to4 embeddings and WHATWG notations such as
   `0x7f.1` or `2130706433`).
2. **On every redirect hop**: the same check, at most 3 redirects. Requests
   carrying a secret header follow **same-origin redirects only** (see T4).
3. **At DNS resolution**: a custom resolver resolves each name once, drops
   every non-public address and hands only the remaining addresses to the
   connector. The address that was checked is the address that is used, so
   a DNS-rebinding answer cannot slip in between check and connect. Names
   that resolve only to non-public addresses (e.g. `localhost`) are refused.

Additional measures:
- The user's indicator is only placed into URL-encoded parameters of fixed
  source endpoints. Sentinel never connects to a host taken from the
  indicator or from response content (except validated redirects).
- RDAP server URLs come only from the IANA bootstrap registry and must be HTTPS.
- Proxies are disabled (`no_proxy`), because a proxy would resolve names
  itself and bypass the resolver check. System proxy support is not compiled in.
- The `Referer` header is disabled so URLs are not leaked to redirect targets.
- Tests talk to plain-HTTP mock servers on loopback through
  `HttpClient::for_tests`, which allows **exactly** the listed mock socket
  addresses and exists only under `cfg(test)`. A redirect to the same
  loopback IP on another port is still refused.

### T4: API key leakage
- Keys are held as `secrecy::SecretString` (redacted `Debug`, zeroized on drop).
- Keys are sent only in headers (`HttpRequest::secret_header`), never in
  URLs. The header value is marked *sensitive*, so it is hidden from
  `Debug` output and excluded from HTTP/2 header compression.
- **Cross-origin redirects.** reqwest strips `Authorization` and `Cookie`
  on cross-host redirects, but **not** custom API-key headers such as
  `x-apikey`, `Key` or `Auth-Key`. Requests with a secret header therefore use
  a separate client that refuses any redirect to another origin
  (`PolicyViolation::CrossOriginRedirect`). A test verifies that the other
  origin receives nothing.
- `HttpError`, `PolicyViolation` and `CollectorError` messages are fixed
  texts or validated values. They never include URLs, header values or
  response content.
- Logged endpoints and `Provenance` endpoints go through `sanitize_url`
  (userinfo and fragment removed, secret-like query values redacted).
- `.gitignore` covers `.env`, `config.toml`, and output directories.
- A config file (and a warning when it is readable by others) is planned
  after v0.1 (L25); v0.1 reads keys from the environment only.

### T5: Operational security (OPSEC) disclosure
Querying an indicator discloses it:
- **DNS lookups** of an adversary's domain eventually reach the adversary's
  authoritative nameservers through the recursive resolver. This is inherent
  to DNS and documented for the analyst.
- **Third-party APIs** (VirusTotal, AbuseIPDB, abuse.ch) learn the queried
  indicator.
- Mitigations: the report lists every source contacted, keyed APIs only run
  when configured (unsetting a key excludes that provider; `--sources` is
  not available in v0.1, L12), and Sentinel
  **never uploads files or submits samples**. It performs lookups only.

### T6: Resource exhaustion, decompression bombs, uncontrolled concurrency
| Resource | Limit (defaults) |
|---|---|
| Investigation time | global deadline (60 s); unfinished sources are cancelled and recorded as `timed_out` |
| Time per source run | 45 s |
| Time per HTTP request | connect 5 s, total 20 s (including body); a source may override per request up to 60 s (crt.sh: 40 s) |
| Response size | 5 MiB default, 64 MiB hard ceiling. Checked against `Content-Length` **and** while streaming |
| Decompression | none: reqwest is built without gzip/brotli/deflate/zstd, so compressed bodies are never inflated and the size cap applies to raw bytes |
| Concurrent source runs | 4 (engine semaphore) |
| Concurrent HTTP requests | 8 (client semaphore); idle pool 2 per host, 30 s idle timeout |
| Network requests per investigation | 100 (shared request budget) |
| Pivots | depth 1, 10 distinct entities; at most 1,000 candidates examined per source response |
| Retries | none (`retry::never()`); rate limits are reported, not hammered |

- Pivots are deduplicated, which prevents `domain → IP → domain → …`
  cycles, and every pivot must pass `ensure_investigable`, so private
  addresses returned by DNS are never sent to third parties.
- The tool must not become a traffic amplifier against any source.

### T7: Invalid or dangerous input
- Domains are IDNA-normalized and validated (label length, charset, total length).
- IPs must be globally routable. Private and reserved addresses are rejected
  because external sources cannot describe them and sending internal addresses
  to third parties leaks internal information.
- Hashes are validated as hex of the correct length (MD5/SHA-1/SHA-256).

### T8: Sensitive data at rest
- Raw responses are hashed, not stored, by default.
- Output files are created with mode `0600`.
- No telemetry and no automatic uploads.

### T9: Supply chain
- `Cargo.lock` committed; `cargo audit` in CI; minimal dependencies with
  `default-features = false` where practical; rustls instead of OpenSSL.
- `#![forbid(unsafe_code)]` via workspace lints.

### T10: Malicious RDAP JSON and bootstrap data (step 4)
RDAP responses and the IANA bootstrap are fetched from third parties and may
be hostile (compromised registry, MITM on a misconfigured path, or a
registry's own buggy output).
- Responses are capped (RDAP 1 MiB, bootstrap 512 KiB) and parsed with a
  recursion limit, so deep nesting fails cleanly instead of exhausting the stack.
- Only a fixed set of fields is extracted, each checked for type, value and
  size. Arrays are bounded (16 CIDRs and status values, 32 events, 64
  entities, entity depth ≤ 4). Invalid fields are dropped and recorded as
  issues; the observation's confidence drops to 70.
- Remarks, notices and links are never read. Instructions inside them (or
  anywhere else) are data, and nothing acts on them.
- Hostile strings (escape sequences, CR/LF, bidi characters) are stored
  faithfully as evidence and sanitized when rendered (T2). Tests cover this.

### T11: SSRF through RDAP bootstrap and redirects (step 4)
- Bootstrap entries are accepted only with `https` base URLs without
  credentials, query or fragment. The chosen service is then contacted
  through the shared HTTP client, so the full network policy (T3) applies:
  public addresses only, resolver filtering, validated redirects (≤ 3).
- A bootstrap pointing at `https://10.1.2.3/` and registry redirects to
  HTTP, private, loopback, link-local and `localhost` targets are tested
  and refused.
- RDAP requests carry no secrets, so cross-registry redirects are allowed
  (under the policy). The same-origin rule of T4 remains for keyed APIs.

### T12: Querying third parties about non-public addresses (step 4)
- Private and reserved IPs from DNS stay data. The engine does not pivot to
  them, **and** each collector refuses them again (`RefusedTarget`). Tests
  assert that no Cymru query and no RDAP request is ever made for them.
  Mutation tests disable each layer separately.

### T13: Contact-data overcollection (step 4)
- The tool is not a people-search system. RDAP entities of kind
  `individual` are skipped entirely. From other entities only the
  registrant organization name and an abuse mailbox are kept. Addresses,
  phone numbers, technical/administrative contacts and personal names are
  never stored. A test asserts these values do not appear in the output.

### T14: Source inconsistency and over-attribution (step 4)
- A reported BGP prefix that does not contain the IP (`asn.prefix_mismatch`)
  and a registered range that does not contain it (`rdap.range_mismatch`)
  are reported as inconsistencies instead of being trusted.
- Findings state facts with explicit caveats: a BGP origin "does not
  establish ownership, control or intent", and registration data "does not
  establish who operates a specific host". No infrastructure finding
  claims maliciousness.

### T15: Malicious CT data and certificate names (step 5)
Anyone can obtain a certificate with arbitrary names under a domain they
control, and aggregator output mixes in unrelated names.
- **Domain-boundary confusion:** names are related only by label boundary
  (`is_subdomain_of`). `example.com.evil.test`, `evil-example.com` and
  `m.testexample.com` (a real crt.sh result) are `unrelated`.
- **Hostile names:** control characters (CR/LF, ESC), bidi characters,
  invalid IDNA, malformed wildcards (`*.*.x`, `*x`, `a.*.x`) make a name
  `invalid`. It is kept (bounded) as evidence, excluded from
  relationships, and sanitized when rendered.
- **Malicious JSON:** 8 MiB response cap, recursion-limited parser,
  bounded arrays (5,000 entries, 200 names each), fixed-field extraction,
  wrong types recorded as issues.
- **Personal data:** email identities in certificates are counted, never stored.

### T16: Failures masquerading as empty results (step 5)
- Only a successful `200` with an empty array produces
  `ct.no_certificates`. Timeouts, `429`, `5xx`, invalid JSON and oversized
  answers are source failures. A mutation test turns a failure into an
  empty result and verifies the tests catch it.

### T17: Pivot explosion from CT (step 5)
- CT names never become engine pivots. The collector makes exactly one
  request, and an integration test with 300 names asserts no additional DNS,
  ASN or RDAP requests. Certificates, names per certificate and
  relationships are bounded, and truncation is reported.

### T18: Stale historical data (step 5)
- CT keeps historical and expired certificates. Findings report counts and
  validity spans and state explicitly that CT does not show that a name
  resolves or that a host is online. Expiry is reported as a fact, not
  as compromise.

### T19: API key leakage from a keyed provider (step 6)
- The key is read once from the environment into a `SecretString`, sent
  only in the `Key` header (never the documented query-string form), and
  marked sensitive (hidden from `Debug`).
- `AbuseIpDbCollector`'s `Debug` shows only `configured`/`missing`/`invalid`.
  Errors, source statuses, provenance, observations, findings, JSON and
  table never contain it.
- **Credential-bearing redirects:** the request uses the same-origin-only
  client (T4); a cross-origin redirect is refused and the other origin
  receives nothing (tested).
- **Echo attacks:** if a response contains the key (a misbehaving or
  malicious endpoint), it is redacted before storage and flagged.
- Tests assert the key's absence from a TRACE-level log capture, error
  `Display`/`Debug`, statuses, JSON and `Debug` of the investigation, and
  from the compiled binary's stdout/stderr with `-vvv`. Remaining
  exposure: the default panic hook (L3); no code path formats the key.

### T20: Provider failure masquerading as an empty result (step 6)
- 401, 403, 404, 422, 429 and 5xx, timeouts, invalid JSON and oversized
  bodies are `failed`/`timed_out`. A missing or invalid key is
  `unavailable`, an exhausted budget is `budget_exhausted`. Only a
  successful response with `totalReports = 0` yields
  `ti.abuseipdb.no_reports`. Mutation tests convert failures into empty
  results and verify the tests catch it.

### T21: Malicious or manipulated provider data (step 6)
- 256 KiB cap, recursion-limited parsing, fixed-field extraction with
  type and range checks (score ≤ 100, counts ≤ 10⁹, distinct users ≤
  reports, dates 1990–9999 with an explicit offset). Unknown fields and
  `reports` arrays are ignored. Hostile text is kept as evidence and
  sanitized for the terminal.
- A manipulated score cannot raise a Sentinel severity: TI findings are
  always `info`, and there is no aggregate score to poison.

### T22: Rate limiting and quota exhaustion (step 6)
- One request per public IP per investigation, bounded by the pivot limit
  and the shared request budget. No retries. `429` is reported, not retried.

### T23: Privacy and data minimization (step 6)
- `verbose` is never requested, so reporter comments, reporter IDs and
  reporter countries are never received or stored. Only the queried public
  IP is disclosed to AbuseIPDB (never domains, CT names or private IPs).

### T24: VirusTotal key leakage and misuse (step 7A)
- The same controls as T19, through the now shared key module
  (`sources/api_key.rs`): key only in the `x-apikey` header via
  `secret_header` (same-origin redirects only), state-only `Debug`,
  echoed keys redacted from stored fields, error messages are fixed texts
  (a `401` body quoting the key is never stored). Tests cover logs at
  TRACE level, errors, statuses, JSON, `Debug`, the binary with `-vvv`, a
  cross-origin redirect and a redirect to `http`.

### T25: Provider failure or absence masquerading as a clean result (step 7A)
- `401`/`403`/`429`/`5xx`, an undocumented `404`, timeouts, invalid JSON
  and oversized bodies are `failed`/`timed_out` with distinct messages; a
  missing or invalid key is `unavailable`. A documented `NotFoundError` is
  a separate observation (`provider_no_record`) and finding
  (`ti.virustotal.not_found`), never "no detections".
  `ti.virustotal.no_detections` requires all five counters and at least
  one engine result. Mutation tests convert each case into an empty or
  clean result and verify the tests catch it.

### T26: Misattributed or manipulated provider data (step 7A)
- A response whose `data.type` or `data.id` does not match the query is
  rejected (never stored under the queried indicator). 8 MiB cap,
  recursion-limited parsing, fixed-field extraction with ranges (engine
  counts ≤ 10,000, votes ≤ 10⁹, community score within ±10⁹, dates
  1990–9999), bounded tags. Hostile tags are kept as evidence and
  sanitized for the terminal; they never reach finding text.
- Engine counts cannot raise a Sentinel severity or confidence.

### T27: Disclosure and personal data (step 7A)
- Only the validated, public target is sent (never pivots, CT names or
  VirusTotal content). URLs are sent whole, so tokens in a URL are
  disclosed to VirusTotal: documented for users.
- WHOIS, certificates, HTTP headers/cookies, page metadata, file names,
  per-engine results and all relationship data (comments, votes by user)
  are dropped before storage.

### T28: Pivot explosion and quota exhaustion via VirusTotal (step 7A)
- `TargetOnly`: one request per investigation, charged to the request
  budget. DNS records, certificate names, URLs or IPs inside VirusTotal
  responses never become pivots (integration test with such content).

### T29: Provider content as a network destination (step 7B)
URLhaus answers contain live malware URLs, hosts, IPs and sample download
links.
- None of them is ever contacted, resolved or downloaded: the collector
  sends exactly one request to the fixed API endpoint and returns no
  pivots or relationships (`TargetOnly`). Tests put a reachable mock
  "malware host" in the answer and assert it receives nothing, that no DNS
  query or provider lookup uses response content, and that the request
  count is exactly one.
- Listed URLs and links are not stored, so a later component cannot
  follow them by accident (L37).

### T30: Failure or absence masquerading as a clean result (step 7B)
- Only `200` + `query_status = ok|no_results` are answers. Every other
  status (undocumented by URLhaus), `invalid_*`, `http_post_expected`,
  undocumented statuses, empty or malformed bodies, timeouts and
  oversized bodies are failures; a missing key is `unavailable`.
  `no_results` is a recorded absence that states it is not evidence of
  benign use.

### T31: Manipulated or misattributed URLhaus data (step 7B)
- An answer for another URL or host is rejected. Classifications are
  kept only as short tokens (letters, digits, `_ - . / +` and spaces,
  ≤ 64 characters, or a JSON boolean rendered as `true`/`false`; since step 9
  this rule is shared with MalwareBazaar in `sources/abusech.rs`), so
  provider text cannot inject content into finding details; tags are
  bounded and sanitized for the terminal. 2 MiB cap, recursion-limited
  parsing, duplicate entries counted once.

### T32: Personal data from URLhaus (step 7B)
- `reporter` handles and payload file names are dropped before evidence
  is created; the Auth-Key goes only in its header (never in the form
  body, URL or logs), with the T19/T24 controls.

### T33: Correlation performing I/O or following pivots (step 8)
- `correlate` is a synchronous function of the investigation alone. The
  `sentinel-correlation` crate depends only on `sentinel-core`, `serde` and
  `sha2`; a test enforces the dependency list and scans the source for
  socket, DNS, process, file, environment, clock and RNG APIs. An
  end-to-end CLI test counts resolver lookups with and without
  `--correlate` (equal). Correlations can only reference entities already
  in the investigation, so they cannot create pivots.

### T34: Correlation manufacturing certainty (step 8)
- No score, weighting, voting or combined confidence exists. Agreement is
  listed per provider; disagreement is a conflict with both sides' evidence
  and an explicit "not resolved" caveat. Finding confidence is the
  weakest evidence's capture confidence. Mutation tests turn disagreement
  into a malicious finding and mix confidence with provider counts; the
  tests catch both.

### T35: Misleading composition of unrelated evidence (step 8)
- Temporal: every correlation states its collection window and, when the
  times differ, that the observations may not describe the same state.
- Attribution: shared ASNs, networks, IPs and certificates carry the
  caveat that sharing does not imply common ownership or intent; routing
  and registration are described as context, not ownership.
- Gaps name the missing link and the source status that explains it, so
  absence of evidence is never shown as evidence of absence.

### T36: Hostile or degenerate input to correlation (step 8)
- Provider text in claim summaries and all rendered text are sanitized;
  duplicate observation IDs are indexed once and reported; duplicate
  relationships are merged; cyclic relationships cannot loop (no graph
  walks); large inputs are bounded (L47) and indexed (no quadratic scans).

### T37: Malware-sample data as a trigger for downloads or lookups (step 9)
- MalwareBazaar answers describe live malware and contain download-capable
  data (hashes, URLs, vendor links). The collector sends one `get_info`
  request for the target hash and nothing else: no `get_file`, upload or
  comment call exists in the code, no pivots or relationships are created,
  and other hashes, URLs, hosts and IPs are not stored. Tests put a
  reachable mock host, another hash, URLs and an IP in the answer and
  assert zero further requests, DNS lookups or provider queries.

### T38: Misattributed or manipulated sample data (step 9)
- The answer must contain exactly one sample carrying the queried hash
  (hex compared case-insensitively, nothing else normalized); otherwise it
  is rejected. Undocumented envelopes and statuses fail explicitly.
  Classifications are stored only as bounded tokens and never enter
  finding text as free text; findings are always `info`.

### T39: Personal data in sample metadata (step 9)
- File names, reporter handles, uploader countries, comment authors, YARA
  authors and code-signing subject names are dropped before evidence is
  created. The Auth-Key is sent only in its header (never the form body),
  with the T19/T24 controls and the same leak tests.

## Out of scope

- A compromised analyst host or a malicious operator.
- Correctness of the data provided by third-party sources. The tool records
  provenance so analysts can judge it.
- Privacy guarantees of third-party APIs.
