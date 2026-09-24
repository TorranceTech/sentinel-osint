# Data Sources

Every collector in Sentinel OSINT is listed here, with its capability level
(see `docs/ETHICS.md`), the indicator types it handles, and what it discloses.
A source must be documented here before it is implemented.

## Summary

| Source ID | Source | Indicators | Level | API key | Protocol |
|---|---|---|---|---|---|
| `dns` | System / configured recursive resolver | Domain | 1 | No | DNS |
| `rdap` | RDAP servers via IANA bootstrap | IP (domain: roadmap) | 1 | No | HTTPS |
| `ct` | crt.sh (Certificate Transparency aggregator) | Domain | 1 | No | HTTPS |
| `cymru` | Team Cymru IP-to-ASN (DNS interface) | IP (incl. pivoted IPs) | 1 | No | DNS |
| `abuseipdb` | AbuseIPDB | IP | 2 | `SENTINEL_ABUSEIPDB_KEY` | HTTPS |
| `virustotal` | VirusTotal API v3 | IP, domain, URL, SHA-256 (target only) | 2 | `SENTINEL_VIRUSTOTAL_KEY` | HTTPS |
| `urlhaus` | abuse.ch URLhaus | URL, domain, IPv4 (target only) | 2 | `SENTINEL_ABUSECH_KEY` | HTTPS |
| `malwarebazaar` | abuse.ch MalwareBazaar | SHA-256, SHA-1 (target only) | 2 | `SENTINEL_MALWAREBAZAAR_KEY` (else `SENTINEL_ABUSECH_KEY`) | HTTPS |

## Details

### `dns`: DNS records (implemented, step 3)
- **Query plan (fixed):** A, AAAA, CNAME, MX, NS, SOA, TXT, CAA at the
  target, and TXT at `_dmarc.<target>`. That is 9 queries, each charged to
  the request budget. There is no enumeration, no wordlist, no zone
  transfer, no `ANY`, no lookups of discovered names (MX/NS/CNAME targets
  are recorded, not queried) and no connection to any discovered host.
- **Resolver:** the system configuration via `hickory-resolver`. The hosts
  file is disabled (local configuration is not public DNS). Names are sent
  fully qualified, so search domains are never appended. 3 s per attempt,
  2 attempts, 8 s per query overall.
- **Observations:** one per record (`dns_record`), or one `dns_no_records`
  (NODATA/NXDOMAIN) as evidence of absence. Failed queries produce no
  observation. The source is reported as `partial` with the reason.
- **Digest:** `raw_response_hash` is the SHA-256 of the answer set in a
  canonical presentation form (`name ttl IN TYPE rdata`, one line per
  record), computed before collection limits. hickory does not expose the
  raw wire message, so the digest is over the decoded answer.
- **Relationships:** `resolves_to` (A/AAAA), `alias_of` (CNAME),
  `has_mail_exchanger` (MX), `has_nameserver` (NS). Resolved public IPs are
  offered as pivots for IP collectors.
- **Limits:** 32 records per query, 2,048 bytes per TXT record (truncated),
  1,024 bytes per other record (dropped); exceeding them yields
  `dns.records.limit_exceeded`.
- **Findings:** SPF, DMARC, CAA, non-public addresses, null MX. See
  `docs/FINDINGS.md`.
- **Disclosure:** the recursive resolver, and ultimately the domain's
  authoritative nameservers, see the queries.

### `rdap`: Registration data (RDAP) (implemented for IPs, step 4)
- **Bootstrap:** IANA `https://data.iana.org/rdap/ipv4.json` / `ipv6.json`
  (RFC 9224), fetched through the hardened HTTP client, validated and
  cached per process. The most specific covering HTTPS service is used.
- **Query:** `GET <service>/ip/<address>`, `Accept: application/rdap+json`.
  Redirects between registries are followed under the network policy.
- **Collects (ip network, RFC 9083 §5.4):** handle, name, type, IP version,
  start/end address, `cidr0` CIDRs, parent handle, country, status,
  registration and last-changed dates, registrant **organization** name,
  and the abuse mailbox of a non-individual abuse contact.
- **Not collected:** individuals (any entity of kind `individual`),
  postal addresses, phone numbers, technical/administrative contacts,
  remarks, notices, links.
- **Confidence:** 95 (authoritative registry); 70 when fields were invalid.
- **Attribution limits:** registration data describes the allocation holder
  of record. It does not establish who operates a specific host (customers,
  cloud tenants and reassignments are often not visible).
- **Not implemented:** domain RDAP (roadmap).

### `ct`: Certificate Transparency via crt.sh (implemented, step 5)
- **Provider:** crt.sh (Sectigo), a public **aggregator** that ingests many
  CT logs. It is not a CT log itself. Sentinel does not verify log
  inclusion proofs or SCTs.
- **Endpoint:** `GET https://crt.sh/?q=<domain>&output=json&deduplicate=Y`
  (query built with the URL encoder from the validated, IDNA-normalized
  domain). One request per investigation, charged to the request budget.
- **Observed behavior (2026-09-23, example.com):** a JSON array of objects
  with `id` (crt.sh entry ID), `issuer_ca_id`, `issuer_name`,
  `common_name`, `name_value` (identities separated by `\n`),
  `not_before`/`not_after` (**no timezone**; interpreted as UTC),
  `serial_number` and `result_count`. No certificate fingerprint and no raw
  certificate are returned. `q=example.com` and `q=%.example.com` returned
  the same 77 entries; `deduplicate=Y` reduced them to 42 by collapsing
  precertificate/certificate pairs (same issuer and serial).
- **Data characteristics:** historical certificates are included (33 of 42
  were expired); wildcard names are returned; `name_value` also contains
  **non-DNS identities** (email addresses, free text) and **names outside
  the domain** (e.g. `m.testexample.com` in a search for `example.com`).
  Upstream filtering is therefore not trusted. Every name is classified
  locally (see `docs/ARCHITECTURE.md`).
- **Freshness:** crt.sh ingests logs with some delay. Very recent
  certificates may be missing, and its coverage of logs may change.
- **Rate limits and availability:** no rate limit is documented by the
  service. It is best-effort: measured latency ranged from 0.6 s to more
  than 20 s, and `502` responses were observed. Sentinel sends a single
  request with a 40 s timeout and no retries. `429`/`5xx` are reported as
  source failures, **never** as "no certificates".
- **Collected:** crt.sh entry ID, serial, issuer DN, subject CN, validity
  dates and the classified names (raw + normalized + wildcard + relation).
  Email identities are counted, never stored.
- **Limits:** 8 MiB response (larger results fail explicitly), 5,000 array
  entries parsed, 200 name lines per entry, 200 certificates kept (most
  recent first), 100 names per certificate, 500 `covers_*` relationships.
  Every cut is reported by `ct.results_truncated`.
- **Confidence:** 80 (aggregator view, proofs not verified); 60 for records
  with invalid fields.
- **Passive only:** names from certificates are **candidates**. They are never
  resolved, probed, connected to, permuted or passed to other collectors.
- **Disclosure:** crt.sh learns the queried domain.

### `cymru`: IP → ASN (implemented, step 4)
- **Mechanism:** DNS TXT queries through the system resolver, charged to
  the request budget: `<reversed IPv4>.origin.asn.cymru.com` or
  `<32 reversed nibbles>.origin6.asn.cymru.com` → `ASNs | prefix | CC |
  registry | allocation date`; then `AS<n>.asn.cymru.com` → `ASN | CC |
  registry | date | AS name` for up to 4 distinct origin ASes.
- **Collects:** origin AS numbers (several = MOAS), BGP prefix, country,
  registry, allocation date, AS name, plus the verbatim answer (≤ 512
  characters). Country, registry and dates are kept only when the source
  states them in a valid form.
- **Confidence:** 85 (aggregated BGP view over non-DNSSEC DNS); 50 when
  fields were invalid.
- **Attribution limits:** the origin AS announces the route. It is not
  proof of ownership, control or intent, and anycast or DDoS-protection
  networks announce addresses they do not operate.
- **Disclosure:** the resolver and Team Cymru's DNS servers see the queried
  IP (in reversed form).
- **Why this source:** no API key, DNS-based, widely used in IR.

### `abuseipdb`: IP reputation (implemented, step 6)
- **Documentation used:** official APIv2 documentation,
  <https://docs.abuseipdb.com/>, retrieved **2026-09-23** (page SHA-256
  `78fc75f7e846f6265b9b3297234f13197ce25cd942f20b3686c7acb36519b3df`).
  Nothing below is from memory.
- **Endpoint:** `GET https://api.abuseipdb.com/api/v2/check?ipAddress=<ip>&maxAgeInDays=90`
  (URL-encoded; documented range 1–365, default 30). `verbose` is **not** set.
- **Authentication:** API key in the `Key` header (the documented,
  recommended form; the query-string form is never used). `Accept:
  application/json` is required (otherwise the API returns HTML). Env var:
  `SENTINEL_ABUSEIPDB_KEY`. HTTPS only (the API redirects HTTP to HTTPS;
  Sentinel never sends HTTP).
- **Rate limits (documented):** `check` allows 1,000/day (Standard),
  3,000 (Webmaster), 5,000 (Supporter), 10,000 (Basic), 50,000 (Premium).
  Exceeding it returns `429` with `Retry-After` and `X-RateLimit-*`
  headers. Sentinel sends at most one request per public IP per
  investigation (bounded by the pivot limit, 10 by default).
- **Errors:** documented as HTTP status plus a JSON:API `errors` array.
  Sentinel relies on the status code and never echoes `detail`.
- **Response semantics (as documented):**
  - `abuseConfidenceScore`: "our calculated evaluation on how abusive the
    IP is based on the users that reported it", a percentage. AbuseIPDB
    documents "75%-100% is the recommended range for denial of service".
    Stored as metric `abuse_confidence_score` (max 100).
  - `totalReports`: "a sum of the reports within maxAgeInDays".
    Metric `total_reports`.
  - `numDistinctUsers`: present in the documented response; not further
    defined in prose. Metric `num_distinct_users`.
  - `lastReportedAt`: RFC 3339 with offset; `null` when there are none.
    Timestamps without an offset are rejected (issue), never reinterpreted.
  - `isWhitelisted`: may be `null`; AbuseIPDB says it "generally should not
    be used as a basis for action".
  - `countryCode`, `usageType`, `isp`, `domain`: **sourced from IPinfo**
    per the documentation. Stored with `context_source`.
  - `isTor`, `hostnames`: present in the documented response; not further
    defined. Stored as reported (bounded).
- **Not collected:** per-report data (comments, reporter IDs and
  countries, categories). It is only available with `verbose`, which is
  never requested (data minimization; limitation L22).
- **Confidence:** 90 for a clean response, 60 with issues. This is
  Sentinel's capture confidence, unrelated to the provider's score.
- **Attribution limits:** reports are claims by AbuseIPDB users; the score
  is AbuseIPDB's evaluation. Shared, NAT, CDN and cloud addresses collect
  reports from unrelated users. No report count or score establishes intent.
- **Live test:** not performed. No API key was available (limitation L23).

### `virustotal`: Multi-engine reputation lookups (implemented, step 7A)
- **Documentation used:** official API v3 reference at
  <https://docs.virustotal.com/reference/overview>, retrieved **2026-09-23**
  (Markdown versions, `<page>.md`; the `docs/` page was served by
  `virustotal.readme.io`, the same documentation site):

  | Page | SHA-256 of the retrieved Markdown |
  |---|---|
  | `reference/authentication` | `427e25bd16f31e0ba9594583ddc33b5bacbca5229fa8fcdc279ec24b90a982b9` |
  | `reference/public-vs-premium-api` | `38ec0a0e7f0242eccaeffd60b807c98f43621a360ddd6f6e89427e63b32f4781` |
  | `reference/errors` | `b2962876e925cb0396cab55fa339f4d2e567a2ef74b4599fb39a3e030ae7be31` |
  | `reference/ip-info` | `f7faa9b74effbc126c8ce6362ebbacff1d18a9732a9dfc8f6b047b86bdb0cbda` |
  | `reference/domain-info` | `64d7f3dac939e053db9456d1500d976855fd16ac70a6370c2bf01353130d98fd` |
  | `reference/url-info` | `afa199a7b0c2a463feaacd14e8c4fca611e461115c55ae68a1225f51aaf97d79` |
  | `reference/file-info` | `3a220e00596aa0d5cd63737ca5ee8aedfcfa2129e3966e30999f2ed90a44d308` |
  | `reference/url` | `7de191f5ddd1639f2be04486f78c181849db9b4d5dab5dcecc8b53a352190082` |
  | `reference/ip-object` | `f9d6861923242e5aa161561c81294c4784e57947da1f95cf0bf63aff63df4e54` |
  | `reference/domains-object` | `bb1aaa504bd6d1bb1d51ae3abf5b686c475c90b7e351d5fdadeee67fa8ba7996` |
  | `reference/url-object` | `4115be0eba83194d5811747477d0add2da596c48323efdac13641a8f7f470c70` |
  | `reference/files` | `98d6cecf3ccc9c17733209c6b6426f185397781f9a6ecb58598435c860024494` |
  | `reference/analyses-object` | `24f88bbf8a4e7b8dd9bcb7e24a4e5511bddecba38ad8cbabb90b80af32c508d5` |
  | `docs/consumption-quotas-handled` | `674ea5a9401f57f2267a8ae0e9334b14a074acab4d01e33eef694c236fb70723` |

  Nothing below is
  from memory; where the documentation is silent, this says so.
- **Endpoints (lookups only, `GET`, base `https://www.virustotal.com/api/v3`):**
  `/ip_addresses/{ip}`, `/domains/{domain}` (ASCII/punycode form),
  `/urls/{id}` and `/files/{sha256}`. The URL `id` is the URL in unpadded
  URL-safe base64, one of the two documented identifier forms
  (VirusTotal canonicalizes it server-side; the other form, a SHA-256 of
  VirusTotal's canonical URL, cannot be computed reliably by a client).
  The indicator fills exactly one percent-encoded path segment; no query
  string is used. Upload, scan/re-analysis, comments, votes and
  relationship endpoints are never called.
- **Indicators:** public IPv4/IPv6, domain, URL, SHA-256. MD5 and SHA-1 are
  also accepted by `/files/{id}` but are not used in this version (the
  collector reports them as `unsupported`; L27). The CLI has no URL target
  in v0.1, so URL lookups are exercised by the collector and engine, not
  the binary (L28).
- **Authentication:** API key in the `x-apikey` header (the only
  documented form). Env var `SENTINEL_VIRUSTOTAL_KEY`. `Accept:
  application/json` is sent (the API documents JSON responses). HTTPS
  only ("Always use HTTPS instead of HTTP").
- **Rate limits (documented):** Public API 500 requests/day and 4/minute;
  it "must not be used in commercial products or services". Premium limits
  are per licence. Quota exhaustion is `429` (`QuotaExceededError`,
  `TooManyRequestsError`); daily quotas reset at 00:00 UTC. The
  documentation does not describe `Retry-After` or rate-limit headers, so
  none are read. The collector is `TargetOnly`: **one request per
  investigation**, never for pivots.
- **Status handling:**

  | Status | Documented meaning | Sentinel |
  |---|---|---|
  | 200 | object returned | parsed; observation + findings |
  | 404 with `error.code = "NotFoundError"` | resource not found | `provider_no_record` observation + `ti.virustotal.not_found`; source `succeeded` |
  | 404 with any other body | — | `failed`: "unexpected not-found response" |
  | 400 | `BadRequestError`, `InvalidArgumentError`, `NotAvailableYet`, … | `failed`: request rejected as invalid |
  | 401 | `AuthenticationRequiredError`, `WrongCredentialsError`, `UserNotActiveError` | `failed`: API key rejected |
  | 403 | `ForbiddenError` | `failed`: not permitted for this key |
  | 429 | quota / too many requests | `failed`: quota or rate limit exceeded (no retry) |
  | 5xx | `TransientError` (503), `DeadlineExceededError` (504) | `failed`: server error (no retry) |
  | other | — | `failed`: unexpected HTTP status |

  The provider's `message` is never stored or echoed (fixed texts only).
- **Redirects:** not documented for these endpoints and not needed. The
  shared authenticated client follows at most 3 same-origin HTTPS
  redirects; a redirect to another origin or to `http` is refused and the
  other origin receives nothing.
- **Fields used** (`data.attributes`): `last_analysis_stats` (`malicious`,
  `suspicious`, `undetected`, `harmless`, `timeout`; files also
  `confirmed-timeout`, `failure`, `type-unsupported`), `last_analysis_date`,
  `reputation` (a signed community score; negative values are documented as
  indicating maliciousness *by community vote*), `total_votes` (`harmless`,
  `malicious`), `tags` (≤ 32, ≤ 64 chars each). `data.type` and `data.id`
  are checked against the query: a response about another object or
  object type is rejected as a failure (for URLs, only the identifier's
  shape can be checked).
- **Deliberately not stored** (personal data, pivot sources, or not
  needed): `whois` (registrant names, e-mails, phone numbers, postal
  addresses), `last_https_certificate` (subject fields can name people),
  `last_dns_records`, `last_analysis_results` (per-engine verdicts),
  `categories`, `popularity_ranks`, `registrar`, `jarm`, `as_owner`/`asn`/
  `network`/`country` (collected by Cymru/RDAP instead), URL
  `html_meta`/`title`/`last_http_response_headers`/`…_cookies`/`trackers`/
  `outgoing_links`/`redirection_chain`/`last_final_url` (tokens, session
  data, e-mail addresses in URLs), file `names`/`meaningful_name` (paths
  with user names), `sandbox_verdicts`, `crowdsourced_ai_results`,
  `threat_verdict`/`threat_severity` (a provider verdict label; L29),
  `links`, and every relationship (comments, votes, resolutions, …). They
  are parsed as part of the body and dropped; only the digest covers them.
- **Timestamps:** documented as integer UTC Unix timestamps; converted to
  UTC. Non-integers and years outside 1990–9999 are issues, never guessed.
  `collected_at` is Sentinel's clock, not a provider date.
- **Size limit:** 8 MiB response cap (object reports carry WHOIS,
  certificates and per-engine results; file reports can be large). Larger
  answers are `failed` (L30). Parsing is recursion-limited; unknown fields
  are ignored.
- **Evidence:** `provider_reputation` (`provider`, `metrics` named
  `last_analysis_stats.<name>` / `total_votes.<name>`, `community_score`,
  `last_analysis_at`, `tags`, `issues`) or `provider_no_record`. The
  observation's indicator is the queried indicator.
- **Confidence:** 90 for a clean response, 60 with issues; never derived
  from engine counts or votes.
- **Attribution limits:** engine results are third-party classifications
  that include false positives; votes and the community score reflect
  VirusTotal users; shared/CDN addresses and popular domains collect
  unrelated detections. A missing record is not evidence of benign use.
- **Disclosure:** the queried IP, domain, URL (including its path and query
  string) or SHA-256 is sent to VirusTotal under the user's account.
  Lookups do not submit anything for analysis, but URLs can contain
  tokens or personal data: only look up URLs you are allowed to share.
- **Live test:** not performed; `SENTINEL_VIRUSTOTAL_KEY` was not set.
  An opt-in, ignored test (`live_virustotal_lookup`) runs when it is (L31).

### `urlhaus`: abuse.ch malware-URL database (implemented, step 7B)
- **Documentation used**, retrieved **2026-09-23** (SHA-256 of the
  retrieved page):

  | Page | SHA-256 |
  |---|---|
  | <https://urlhaus-api.abuse.ch/> (API reference) | `43b6fd0f099a34a48b9fed5fec854ede08494a17755944aea40845e26b88207c` |
  | <https://urlhaus.abuse.ch/api/> (community API, submission policy) | `d66248b4d9b35b8253e82d7aa0fc51eca660605f3898324f585c8d52c271f7dd` |
  | <https://urlhaus.abuse.ch/about/> | `5c9c2906dd3d2fa13d067c98324b8fa62e633e362f67ea5754e9c2416183c0fb` |
  | <https://abuse.ch/terms-of-use/> (fair use) | `fcb6fc3c99d312a739a6119682f194c331cc4e78fed998edfc729ec2627542e5` |
  | <https://auth.abuse.ch/> (Auth-Key portal, rate-limit notice) | `356167b3bb876881378f5951a4fc0943a681312e32e3db9958742d448ba5885c` |
  | `abusech/URLhaus` `lookup_url.py` (official sample script) | `3ded0aea198ec338d02a194f9fda2f9364feaed4df2a4e700937ad7c3c469895` |

  Where the documentation is silent, this section says **undocumented**.
- **Endpoints (lookups only):**
  - `POST https://urlhaus-api.abuse.ch/v1/url/`, form field `url` (URL targets);
  - `POST https://urlhaus-api.abuse.ch/v1/host/`, form field `host`
    ("IPv4 address, hostname or domain name"; domains and IPv4 targets).
  Body `application/x-www-form-urlencoded`; the indicator is the only
  field. Never used: `urlid`, `payload`, `tag`, `signature`, the `recent`
  feeds, `download` (malware samples) and submissions.
- **Indicators:** public URL, domain, IPv4. **IPv6: undocumented** for the
  host endpoint, so not sent (`unsupported`, L35). Hashes are not looked up
  here (L38).
- **Authentication:** `Auth-Key` header, **required** ("you must include
  the HTTP header Auth-Key"). Env var `SENTINEL_ABUSECH_KEY` (one key for
  abuse.ch platforms). Held and sent through the shared key module and
  `secret_header` (same-origin redirects only). `Accept: application/json`
  is sent.
- **Rate limits:** no numeric limit is documented. The terms of use set
  "Query Volume Limits" for not-for-profit use (commercial use may need a
  subscription) and forbid high-volume automated harvesting; the Auth-Key
  portal announces temporary limits "for up to 72 hours" for unusually
  high volumes. Sentinel sends **one request per investigation**
  (`TargetOnly`) and never retries.
- **HTTP status codes: undocumented.** Outcomes are reported in the body's
  `query_status`. Sentinel treats only `200` as an answer; every other
  status is a failure with a fixed text based on standard HTTP meaning
  (400 invalid, 401 unauthorized, 403 forbidden, 404 unexpected, 429 rate
  limit, 5xx server error), never "no results" (L36).
- **`query_status`:** `ok` → listing; `no_results` → recorded absence
  (`provider_no_record`, `ti.urlhaus.no_results`); `invalid_url` /
  `invalid_host` / `http_post_expected` / any undocumented value / missing
  → failure. An empty or non-JSON body is a failure. The documented host
  example spells the key `query_staus`; both spellings are accepted (L39).
- **"Not found":** `no_results` only means URLhaus has no entry. URLhaus
  only tracks malware distribution URLs, so it is not evidence of benign
  use. A `404` is **not** "not found" (failure).
- **Timestamps:** `date_added` and host `firstseen` are documented as
  "human readable timestamp in UTC" (`YYYY-MM-DD HH:MM:SS UTC`); they are
  parsed as UTC, with or without the suffix. `last_online`'s time zone is
  undocumented, so only an explicit ` UTC` suffix is accepted (L40). Other
  forms and years outside 1990–9999 are issues.
- **Fields used:** entry `id`; `url_status`, `threat`, `larted`,
  `blacklists.spamhaus_dbl`, `blacklists.surbl` (classifications stored
  under URLhaus's names, only as short tokens); `date_added`,
  `last_online`, `firstseen`; `url_count`, `takedown_time_seconds`;
  `tags`; payload `signature`s (malware family names). Sentinel also
  counts the returned lists: `returned_urls`, `returned_urls.online`,
  `returned_urls.latest_date_added`, `returned_payloads` (duplicates
  counted once).
- **Identity check:** the response's `url` (URL lookups, compared after
  normalization) or `host` (host lookups) must equal the query, otherwise
  the answer is rejected as a failure.
- **Personal data, deliberately not stored:** `reporter` (a person's
  Twitter handle), payload `filename`s (can contain victim or user names).
- **Pivot-capable data, deliberately not stored:** listed `url`s,
  `urlhaus_reference` links, `urlhaus_download` links, payload hashes
  (`response_md5`/`response_sha256`) and fuzzy hashes, the `virustotal`
  sub-object and its links (L37).
- **Pivots:** none. `TargetOnly`; no pivots, entities or relationships
  are created from URLhaus content. **No URL, host, IP or link from a
  response is ever contacted, resolved or downloaded** (tested with a
  reachable mock "malware host").
- **Size limit:** 2 MiB (lookups return at most 100 URLs or payloads per
  the documentation). Recursion-limited parsing, bounded tags (32 × 64
  chars) and signatures (10).
- **HTTPS:** the API is HTTPS; `http` and redirects to `http` or to
  another origin are refused by the shared client.
- **Evidence:** `provider_listing` (`provider`, `entry_id`, `attributes`,
  `metrics`, `dates`, `tags`, `issues`) or `provider_no_record`. Confidence
  90 (60 with issues), never derived from the classification.
- **URL matching:** URLhaus stores URLs "as you see them on the wire";
  Sentinel sends the WHATWG-normalized URL. A URL listed in a different
  textual form may answer `no_results` (L42).
- **Disclosure:** the queried URL (with path and query), domain or IPv4 is
  sent to abuse.ch under the user's Auth-Key.
- **Live test:** not performed; `SENTINEL_ABUSECH_KEY` was not set. The
  ignored `live_urlhaus_lookup` test (a lookup of `example.com`) runs when
  it is (L41).

### `malwarebazaar`: abuse.ch malware-sample database (implemented, step 9)
- **Documentation used**, retrieved **2026-09-23** (SHA-256 of the
  retrieved page):

  | Page | SHA-256 |
  |---|---|
  | <https://bazaar.abuse.ch/api/> (Community API reference) | `678aa7cbab66ee86ac557b962504c4351e81c8b6a88b306ad2dd2964ebc6ad1e` |
  | <https://bazaar.abuse.ch/faq/> (download limit, terms) | `36b971dba5cc5193cc7bf32db97262752c3f9d4ba12a22b06d57803f1e88be67` |
  | <https://bazaar.abuse.ch/about/> | `96062d25b7e133628bcfa301fd13bf6119acef4afb88d9b30930c7e09c4ba700` |
  | `abusech/MalwareBazaar` `README.md` (official repository) | `713a66db4cfb27af70967418ba1e4e137ffcd64ca5cedf5d2ca176ce45de5b69` |
  | <https://abuse.ch/terms-of-use/> (fair use; see `urlhaus`) | `fcb6fc3c99d312a739a6119682f194c331cc4e78fed998edfc729ec2627542e5` |

  Where the documentation is silent, this section says **not documented**.
- **Endpoint (lookup only):** `POST https://mb-api.abuse.ch/api/v1/`, form
  fields `query=get_info` and `hash=<hash>` (`application/x-www-form-
  urlencoded`). The hash is the only indicator-derived value. Never used:
  upload, download (`get_file`), recent additions, tag/signature/imphash/
  TLSH/… queries, `update`, `add_comment`, batches.
- **Indicators:** SHA-256 and SHA-1 (documented: "SHA256, MD5 or SHA1
  hash"; the core already models them). MD5 is not used (`unsupported`,
  L50). The target only (`TargetOnly`).
- **Authentication:** `Auth-Key` header, **required**, obtained from the
  abuse.ch authentication portal (the same portal as URLhaus). Env var
  `SENTINEL_MALWAREBAZAAR_KEY`; if unset, `SENTINEL_ABUSECH_KEY`. Held and
  sent through the shared key module and `secret_header` (same-origin
  redirects only). `Accept: application/json` is sent.
- **Documented `query_status` values for `get_info`:** `http_post_expected`,
  `hash_not_found`, `illegal_hash`, `no_hash_provided`. Documented
  elsewhere on the page: `no_api_key`, `user_blacklisted` (upload) and `ok`
  (other queries). Sentinel: `ok` → listing; `hash_not_found` → recorded
  absence (`provider_no_record`, `ti.malwarebazaar.not_found`); every
  other value, and a missing one, → failure.
- **Response envelope: not documented for `get_info`.** The page's only
  JSON example (recent additions) is `{"query_status": "ok", "data": [ …
  ]}`. Sentinel requires that shape with **exactly one** sample whose
  `sha256_hash` (or `sha1_hash` for SHA-1 queries) equals the query
  (hex, case-insensitive; no other normalization). Anything else is a
  failure, never "no results" (L49).
- **HTTP status codes: not documented.** Only `200` is an answer; every
  other status is a failure with a fixed text based on standard HTTP
  meaning (400/401/403/404/429/5xx), never "no results".
- **Rate limits:** no numeric limit for queries is documented. The FAQ
  documents 2,000 **file downloads** per IP per day (not applicable:
  Sentinel never downloads). Fair-use terms and the portal's temporary
  restrictions for high volumes apply (see `urlhaus`). One request per
  investigation; no retries.
- **Fields kept:** `signature` ("malware family, if available"),
  `file_type`, `file_type_mime`, `delivery_method` (bounded tokens, under
  MalwareBazaar's names); `first_seen`, `last_seen` (documented "(UTC)",
  format `YYYY-MM-DD HH:MM:SS`); `file_size`; `tags` (≤ 32 × 64 chars).
- **Deliberately not stored:** `file_name` (can contain personal or victim
  names) and `reporter` (a person's Twitter handle), `origin_country`
  (uploader location), `comments` (handles, display names, free text),
  `yara_rules` (authors, references), `vendor_intel` (third-party
  verdicts and links), `code_sign` (subject names), `ole_information`,
  `file_information`, `archive_pw`, `anonymous`, `intelligence`, every
  other hash (MD5, SHA-1/SHA-256, SHA3-384, imphash, TLSH, telfhash,
  gimphash, ssdeep, icon dhash) and every URL.
- **Pivots:** none. No URL, host, IP, file name, hash or link from a
  response is contacted, resolved or looked up (tested with a reachable
  mock host and a fake resolver).
- **Size limit:** 4 MiB (one sample, but vendor/YARA/OLE data can be
  large; L51). Recursion-limited parsing.
- **Evidence:** `provider_listing` or `provider_no_record` (no new type);
  confidence 90, or 60 with issues, never derived from the classification.
  The correlation layer consumes these observations through its existing
  provider rules.
- **Disclosure:** the queried hash is sent to abuse.ch under the user's key.
- **Live test:** not performed; neither `SENTINEL_MALWAREBAZAAR_KEY` nor
  `SENTINEL_ABUSECH_KEY` was set. The ignored `live_malwarebazaar_lookup`
  test (the documentation's example hash, `get_info` only) runs when it is
  (L52).

## Confidence guidelines

| Case | Confidence |
|---|---|
| DNS answer via a non-validating resolver | 90 |
| Aggregated public data (CT via crt.sh: 80; Cymru ASN: 85) | 80–85 |
| Authoritative registry data (RDAP) | 95 |
| Any source with invalid fields in its answer | Reduced (Cymru 50, CT 60, RDAP 70, AbuseIPDB 60, VirusTotal 60, URLhaus 60, MalwareBazaar 60) |
| Reputation provider responses (capture confidence, not the provider's score) | 90 (AbuseIPDB, VirusTotal, URLhaus, MalwareBazaar) |
| Third-party reputation verdicts | Derived from the source's own score/consensus; documented per collector |
| Derived findings | Inherit the minimum confidence of their evidence |

## Terms of service

Users are responsible for complying with each source's terms of service and
rate limits. Sentinel identifies itself with a `User-Agent` of
`sentinel-osint/<version> (+<repository URL>)`.
