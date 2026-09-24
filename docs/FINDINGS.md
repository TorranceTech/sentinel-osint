# Finding Codes

Findings are **conclusions derived from observations**. Each has a stable
`code` that automation keys on (SIEM rules, dashboards, later MITRE ATT&CK
mapping). Titles and details are human-readable and may change; codes do not.

## Stability rules

- A code, once released, keeps its meaning. It is never reused for a
  different condition.
- Renaming or removing a code is a breaking change of the JSON output
  (`schema_version` changes).
- Codes are `lowercase.dot.separated`: `<area>.<subject>.<condition>`.

## Severity rules

Severity is **not a risk score**. It follows fixed rules, so the same
observation always yields the same severity:

| Severity | Rule |
|---|---|
| `info` | A fact about the configuration, with no RFC violation. Policies such as `p=none` or `~all` are facts, not verdicts. |
| `low` | An expected security record is absent, a construct is deprecated or discouraged by its RFC, or a record has syntax errors. |
| `medium` | The configuration defeats the mechanism: the RFC says receivers return a permanent error or ignore it, or it authorizes every host. |
| `high` | Not used in v0.1. |

**Infrastructure, CT and threat-intelligence findings (`asn.*`, `rdap.*`,
`ct.*`, `ti.*`) are always `info`.** A provider's score never sets a
Sentinel severity. They
describe what registries and routing data report, and the quality of that
data. They say nothing about the risk or intent of the IP's operator. No
finding claims that an IP, network or organization is malicious.

All DNS findings have confidence 90, because answers come from a recursive
resolver without DNSSEC validation. They cite the observations they are
based on in `evidence`.

**Unknown is not absent.** If a query failed, no finding is derived from it.
The source is reported as `partial` instead.

## DNS: general

| Code | Severity | Condition |
|---|---|---|
| `dns.domain.nxdomain` | info | The target does not exist (NXDOMAIN). No other DNS findings are produced. |
| `dns.records.limit_exceeded` | info | An answer exceeded collection limits (32 records per query, 2,048 bytes per TXT record, 1,024 bytes per other record) and was truncated. |
| `dns.address.non_public` | low | An A/AAAA record points to a non-public address (private, loopback, link-local, …). Such addresses are never pivoted to. |
| `dns.mx.null` | info | A single null MX record (RFC 7505): the domain accepts no email. |

## SPF (RFC 7208)

Only the target's own record is analyzed. `include:` and `redirect=` targets
are listed, not resolved.

| Code | Severity | Condition |
|---|---|---|
| `dns.spf.missing` | low | No TXT record starting with `v=spf1`. |
| `dns.spf.multiple_records` | medium | More than one SPF record (§4.5: permanent error). No further SPF analysis. |
| `dns.spf.hardfail` | info | The first `all` mechanism is `-all`. |
| `dns.spf.softfail` | info | The first `all` mechanism is `~all`. |
| `dns.spf.neutral_all` | low | The first `all` mechanism is `?all`. |
| `dns.spf.permissive_all` | medium | The first `all` mechanism is `+all` or a bare `all`: every host is authorized. |
| `dns.spf.redirect` | info | No `all`; the policy is delegated with `redirect=`. |
| `dns.spf.no_all` | low | Neither `all` nor `redirect=`: unlisted hosts get the default neutral result (§4.7). |
| `dns.spf.includes` | info | The record uses `include:` (the domains are listed). |
| `dns.spf.too_many_lookups` | medium | The record itself has more than 10 DNS-querying terms (§4.6.4: permanent error). Nested includes are not counted. |
| `dns.spf.ptr_mechanism` | low | The record uses `ptr` (§5.5: SHOULD NOT). |
| `dns.spf.malformed` | low | Terms that are not valid SPF (§4.6: permanent error), or too many terms to analyze. |

## DMARC (RFC 7489)

Only `_dmarc.<target>` is queried. For subdomains, receivers fall back to the
organizational domain's record, which is not checked.

| Code | Severity | Condition |
|---|---|---|
| `dns.dmarc.missing` | low | No TXT record starting with `v=DMARC1` at `_dmarc.<target>`. |
| `dns.dmarc.multiple_records` | medium | More than one DMARC record (§6.6.3: DMARC is not applied). |
| `dns.dmarc.malformed` | low | Syntax problems: missing or invalid `p`, invalid `sp`/`pct`/`adkim`/`aspf`, duplicate tags, tags without a value. |
| `dns.dmarc.policy_none` | info | `p=none`. |
| `dns.dmarc.policy_quarantine` | info | `p=quarantine`. |
| `dns.dmarc.policy_reject` | info | `p=reject`. |
| `dns.dmarc.subdomain_policy_none` | info | `sp=none`. |
| `dns.dmarc.subdomain_policy_quarantine` | info | `sp=quarantine`. |
| `dns.dmarc.subdomain_policy_reject` | info | `sp=reject`. |
| `dns.dmarc.pct_partial` | info | `pct` below 100. |
| `dns.dmarc.aggregate_reporting` | info | `rua` is present (destinations listed). |
| `dns.dmarc.no_aggregate_reporting` | info | `rua` is absent. |
| `dns.dmarc.failure_reporting` | info | `ruf` is present (destinations listed). |
| `dns.dmarc.strict_alignment` | info | `adkim=s` and/or `aspf=s`. |

## CAA (RFC 8659)

Only the target name is queried. CAA inherited from parent domains (tree
climbing, §3) is not evaluated.

| Code | Severity | Condition |
|---|---|---|
| `dns.caa.missing` | info | No CAA records at the target. |
| `dns.caa.issue` | info | `issue` restricts issuance to the listed CAs. |
| `dns.caa.issue_forbidden` | info | Only `issue ";"`: no CA may issue. |
| `dns.caa.issuewild` | info | `issuewild` restricts wildcard issuance to the listed CAs. |
| `dns.caa.issuewild_forbidden` | info | Only `issuewild ";"`: no CA may issue wildcards. |
| `dns.caa.no_issue_restriction` | info | CAA records exist, but none has `issue`/`issuewild`. |
| `dns.caa.iodef` | info | Violation reporting destinations (`iodef`). |
| `dns.caa.unknown_critical_tag` | low | An unknown tag has the critical flag (§4.1: CAs must not issue). |
| `dns.caa.malformed` | low | An `issue`/`issuewild` issuer is not a valid domain name. |
| `dns.caa.duplicate_records` | info | Identical records published more than once. |

## ASN (Team Cymru)

| Code | Severity | Condition |
|---|---|---|
| `asn.origin` | info | The source reports origin AS(es) for the IP, with name and prefix when available. The detail states that a BGP origin is not ownership, control or intent. |
| `asn.multiple_origins` | info | More than one origin AS (MOAS), common for anycast/CDNs. |
| `asn.not_announced` | info | The source has no origin for the IP (NXDOMAIN/NODATA). |
| `asn.prefix_mismatch` | info | The reported prefix does not contain the IP (source inconsistency). |
| `asn.response_malformed` | info | Fields of the answer were invalid and left empty (issues listed). |

## RDAP

| Code | Severity | Condition |
|---|---|---|
| `rdap.network` | info | Registration data is available (network, range, CIDR, type, country, registrant organization). The detail states that it does not establish who operates a specific host. |
| `rdap.range_mismatch` | info | The registered range does not contain the queried IP (source inconsistency). |
| `rdap.incomplete` | info | Fields were invalid, truncated or of the wrong type (issues listed). |

Source failures (timeouts, HTTP errors, malformed documents) are not
findings. They appear as source statuses (`failed`, `partial`, `timed_out`).

## Certificate Transparency (`ct`)

CT data shows what certificates were logged. It does not show that a name
resolves, that a host is online or reachable, that a certificate is
deployed, or who controls a name. Findings say so; none claims
maliciousness or compromise.

| Code | Severity | Condition |
|---|---|---|
| `ct.certificates_observed` | info | Certificates naming the domain or its subdomains were reported (count, log entries, validity span). |
| `ct.no_certificates` | info | The source answered successfully with an empty list. **Not** used for failed requests. |
| `ct.additional_names_observed` | info | Subdomain names (non-wildcard) appear in certificates (distinct names listed). |
| `ct.wildcard_names_observed` | info | Wildcard names under the domain appear in certificates. |
| `ct.unrelated_names_observed` | info | Certificates also list names outside the domain (multi-domain certificates, look-alikes). They are not treated as related. |
| `ct.expired_certificates` | info | Certificates whose `not_after` is before the collection time. Expiry is not compromise. |
| `ct.not_yet_valid_certificates` | info | Certificates whose `not_before` is after the collection time. |
| `ct.invalid_records` | info | Records with invalid fields or names (issues listed); invalid names never become relationships. |
| `ct.results_truncated` | info | A collection limit was applied (what and how much is listed). |

## Threat intelligence: AbuseIPDB (`ti.abuseipdb.*`)

Every statement is attributed to AbuseIPDB. None of these findings says
that an IP is malicious, an attacker, compromised or part of a botnet.
Provider failures and missing credentials are **source states**
(`failed`, `unavailable`, `budget_exhausted`, `timed_out`), never findings,
so they cannot be mistaken for "no reports".

| Code | Severity | Condition |
|---|---|---|
| `ti.abuseipdb.observed` | info | AbuseIPDB returned reputation data (score, reports, last report, window). |
| `ti.abuseipdb.no_reports` | info | `totalReports` is 0 in the window. The detail states that absence of reports is not evidence of benign use. Not produced when the count is unknown. |
| `ti.abuseipdb.abuse_reports` | info | `totalReports` > 0 (reports are third-party claims, unverified by Sentinel). |
| `ti.abuseipdb.high_abuse_confidence` | info | `abuseConfidenceScore` ≥ 75, the lower bound of the range AbuseIPDB documents as recommended for blocking. The threshold is AbuseIPDB's, not Sentinel's. |
| `ti.abuseipdb.allowlisted` | info | `isWhitelisted` is true (AbuseIPDB: not a basis for action). |
| `ti.abuseipdb.tor` | info | `isTor` is true. |
| `ti.abuseipdb.response_incomplete` | info | Fields were missing, invalid or truncated, or the response echoed the API key (redacted). |

## Threat intelligence: VirusTotal (`ti.virustotal.*`)

Every statement is attributed to VirusTotal: engine results are
third-party classifications, votes are VirusTotal users' votes. None of
these findings says that an indicator is malicious, dangerous, an attacker
or compromised, and engine counts never change a severity or Sentinel's
confidence. Failures, missing or rejected keys, quota errors and timeouts
are source states, never findings.

| Code | Severity | Condition |
|---|---|---|
| `ti.virustotal.observed` | info | VirusTotal returned an object report (last-analysis counts and date, community score, votes). |
| `ti.virustotal.detections` | info | `last_analysis_stats.malicious` + `suspicious` > 0: "VirusTotal reports detections for this indicator", with the counts. The detail states that engine results can be false positives and were not verified by Sentinel. |
| `ti.virustotal.no_detections` | info | All five documented counters are known, at least one engine result exists, and none is malicious or suspicious. The detail states that absence of detections is not evidence of benign use. Not produced when counts are missing or all zero (never analyzed). |
| `ti.virustotal.not_found` | info | `404` with VirusTotal's documented `NotFoundError`: VirusTotal has no record. The detail states that Sentinel submits nothing and that absence from the dataset is not evidence of benign use. Any other `404` is a failure. |
| `ti.virustotal.response_incomplete` | info | Fields were missing, invalid or truncated, or the response echoed the API key (redacted). |

## Threat intelligence: MalwareBazaar (`ti.malwarebazaar.*`)

Every statement is attributed to MalwareBazaar and keeps its field names
(`signature`, `file_type`, …). None says that a file is malicious or
malware as Sentinel's own judgment; details state that Sentinel did not
download or execute the sample. Failures, a missing key, undocumented
statuses and malformed answers are source states, never findings.

| Code | Severity | Condition |
|---|---|---|
| `ti.malwarebazaar.sample_listed` | info | `get_info` returned the queried sample: "MalwareBazaar reports <hash> as a sample in its malware database", with `signature`, `file_type`, `delivery_method`, `first_seen`, `last_seen`. |
| `ti.malwarebazaar.not_found` | info | `query_status = hash_not_found`. The detail states that absence is not evidence that the file is benign. |
| `ti.malwarebazaar.response_incomplete` | info | Fields were missing, invalid, not short tokens or truncated, or the response echoed the key (redacted). |

## Correlation (`correlation.*`, with `--correlate`)

Derived from a finished investigation by `sentinel-correlation` (see
`docs/CORRELATION.md`). Always `info`. Each finding cites every
observation of its correlation; its confidence is the **lowest capture
confidence** of that evidence (evidence quality, never likelihood of
maliciousness). No finding combines provider verdicts, and none claims an
actor, campaign, ownership, compromise or maliciousness.

| Code | Severity | Condition |
|---|---|---|
| `correlation.domain_ip_infrastructure` | info | A `resolves_to` edge and an `announced_by` and/or `registered_in` edge for the same IP; conflicts (differing ASN/network observations, prefixes or ranges not containing the IP, non-overlapping routing and registration) and gaps (with source statuses) are part of it. |
| `correlation.domain_certificate` | info | CT certificates list the investigated domain (`covers_name` / `covers_wildcard`). |
| `correlation.ct_dns_names` | info | Related CT names that also appear in DNS data already collected; CT-only names are counted as a gap, never resolved. |
| `correlation.multiple_sources` | info | Two or more providers have claims about the same indicator; each claim is listed in the provider's terms. |
| `correlation.source_disagreement` | info | One provider flags an indicator while another does not flag it or has no record, or one provider answered differently in different observations. Both sides are cited; nothing is resolved. |
| `correlation.shared_infrastructure` | info | Two or more indicators connect to the same AS, network, IP or certificate. The detail's caveat: sharing does not imply a common owner, operator or intent. |

## Threat intelligence: URLhaus (`ti.urlhaus.*`)

Every statement is attributed to URLhaus and keeps URLhaus's field names
and values (`threat: malware_download`, `url_status: online`). None says
that an indicator is malicious, compromised or dangerous; details state
that Sentinel did not access listed URLs. Failures, a missing key,
undocumented statuses and malformed answers are source states, never
findings.

| Code | Severity | Condition |
|---|---|---|
| `ti.urlhaus.url_listed` | info | URL lookup, `query_status = ok`: "URLhaus reports <url> in its malware URL database", with `threat`, `url_status`, `date_added` and payload signatures. |
| `ti.urlhaus.url_online` | info | `url_status = online` (URLhaus: "currently serving a payload"). |
| `ti.urlhaus.host_listed` | info | Host lookup, `query_status = ok`: URLhaus's `url_count`, how many returned entries it reports online, first seen, latest entry. The detail notes that listed hosts can be compromised legitimate or shared hosts. |
| `ti.urlhaus.blocklist_status` | info | `blacklists.spamhaus_dbl` or `blacklists.surbl` is anything other than `not listed`, as reported by URLhaus. |
| `ti.urlhaus.no_results` | info | `query_status = no_results`. The detail states that absence is not evidence of benign use. |
| `ti.urlhaus.response_incomplete` | info | Fields were missing, invalid, not short tokens, duplicated or truncated, or the response echoed the key (redacted). |
