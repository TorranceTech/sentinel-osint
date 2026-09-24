# Correlation

Status: **implemented (step 8)** in the `sentinel-correlation` crate.

Sentinel collects independent evidence from independent sources. The
correlation layer shows **verifiable connections between that evidence**:
which observations, from which sources, collected when, support which
chain of facts, and where sources disagree. It never turns evidence into
a verdict, a score or a conclusion about intent.

## Philosophy

- **Evidence stays independent.** Two sources agreeing does not make a
  fact "more true" in a way Sentinel could quantify, and does not make an
  indicator malicious. Each source's claim is listed with its own
  provenance; nothing is summed, averaged or weighted.
- **Explain, don't score.** Every correlation answers: what was observed,
  which observations support it, which sources they came from, when they
  were collected, which relation connects them, how confident Sentinel is
  in each *capture*, what conflicts, and what is missing. There is no
  `threat_score`, `risk_score`, `malicious` flag or combined confidence.
- **Conflicts are kept.** When sources disagree, the disagreement is the
  result. Sentinel does not pick a winner.
- **Absence is not evidence of absence.** A missing ASN or registration,
  or a provider's "no record", is reported as such, with the source status
  that explains it (failed, timed out, unavailable, not run).

## Definitions (design questions 1–3)

| Term | Meaning | Where |
|---|---|---|
| **Observation** | One fact reported by one source, with provenance, time, confidence and digest. | `sentinel-core` |
| **Relationship** | A typed edge between two entities (`resolves_to`, `announced_by`, `registered_in`, `covers_name`, …) justified by at least one observation. Produced by collectors. It is one hop and one kind of fact. | `sentinel-core` |
| **Correlation** | A derived, explainable *composition* of existing observations and relationships: a chain (domain → IP → ASN/network), a grouping (indicators sharing an AS, a network, an IP or a certificate), or a comparison of provider claims about one indicator (agreement or disagreement). It creates no new facts, only references existing ones. | `sentinel-correlation` |
| **Finding** | A human-readable, stable-coded conclusion (`correlation.*`), `info` severity, citing the observations of exactly one correlation. | derived from a correlation |

## Rules

1. **Input is a finished `Investigation`; output is a `CorrelationReport`.**
   `correlate(&Investigation) -> CorrelationReport` is a pure, synchronous
   function. It receives no HTTP client, resolver, clock, RNG or context.
2. **No I/O (question 10).** The crate's direct dependencies are only
   `sentinel-core`, `serde` and `sha2`, none of which performs network,
   DNS, process or file I/O. Tests assert that dependency list, scan the
   crate's source for socket, file, process, environment, clock and
   randomness APIs (`TcpStream`, `std::fs`, `std::process`, `std::env`,
   `tokio`, `reqwest`, `hickory`, `Utc::now`, `new_random`, …; the value
   type `std::net::IpAddr` is allowed), and run an end-to-end
   investigation against mock servers and a fake resolver to show that
   correlating adds zero requests and zero DNS queries.
3. **References, not copies (question 4).** A correlation holds
   observation IDs and the (cloned) typed relationships it composes. The
   provenance chain is resolved through the investigation:
   `correlation → observation ID → source, collected_at, provenance,
   raw_response_hash, confidence`. A correlation cannot be constructed with
   no evidence or with an ID that is not in the investigation
   (`CorrelationError::MissingEvidence`, `UnknownObservation`).
4. **No new entities.** Every subject of a correlation must already
   appear in the investigation (target, observation subject or relationship
   endpoint); `Draft::build` rejects unknown subjects. Links are the
   investigation's own relationships (cloned); tests assert that every link
   is an existing edge. Correlation never creates indicators, so it cannot create
   pivots. CT names become part of a correlation only when the CT collector
   classified them as related *and* DNS data for them already exists.
5. **No double counting (question 6).** Providers are counted by
   `SourceId`, never by observation. Relationships are deduplicated by edge
   (the investigation already merges them). Evidence lists are sets.
   Duplicate observation IDs are indexed once (first kept) and reported as
   a limitation. A provider with several observations about one indicator
   is one provider; if those observations disagree, that is a conflict.
6. **Two sources are not truth (question 5).** Agreement is reported as
   "each provider made its own classification", listed per provider, with
   no aggregate and no severity change. Sentinel's `confidence` keeps its
   meaning (capture quality); a correlation finding carries the *minimum*
   confidence of its evidence, which is a statement about evidence
   quality, never about maliciousness.
7. **Conflicts (question 7)** are first-class: `conflicts[]` with a fixed
   description and the evidence on each side.
8. **Absence (question 8)** is `gaps[]`: which expected link is missing and
   the non-successful source statuses for that indicator.
9. **Time.** Every correlation carries `observed.first` and
   `observed.last` (the collection times of its evidence). When they
   differ, a limitation states that the observations were not made at the
   same moment and may not describe the same state. Validity periods are
   never invented.
10. **Determinism (question 9).** Inputs are indexed in ordered maps,
    outputs are sorted, and correlation IDs are
    `corr-` + the first 16 bytes (hex) of SHA-256 over the kind, the
    subjects and the sorted evidence IDs. No clock, no randomness. The same
    investigation always yields byte-identical JSON.

## Correlations (step 8)

| Kind / finding code | When | Content |
|---|---|---|
| `domain_ip_infrastructure` | A `resolves_to` edge (domain → IP) and at least one `announced_by` or `registered_in` edge for that IP. | The chain links with evidence; conflicts (different observations reporting different origin ASNs or registered networks; a BGP prefix or registered range that does not contain the IP; a routing prefix and a registered network that do not overlap); gaps (missing ASN or registration, with source statuses); MOAS noted as a limitation. |
| `domain_certificate` | The target is a domain and certificates list it (`covers_name` / `covers_wildcard`). | The certificate links (bounded); the target's DNS address records as supporting evidence when present. |
| `ct_dns_names` | Names the CT collector classified as related (not the target itself) that also appear in DNS data already collected. | CT links and DNS links for those names; a gap counts CT-only names, which were not resolved by design. |
| `multiple_sources` | Two or more providers (distinct sources) have reputation observations about the same indicator. | One claim per provider observation: provider, observation, provider-worded summary, provider stance, collection time. |
| `source_disagreement` | For one indicator, at least one provider observation flags it and another does not flag it or has no record; or one provider answered differently in different observations. | The claims on both sides and a conflict listing them. Never resolved. |
| `shared_infrastructure` | Two or more distinct indicators connect to the same AS (`announced_by`), network (`registered_in`), IP (`resolves_to`), or certificate (`covers_name`). | The shared entity, the indicators, the edges. A limitation states that shared hosting, CDNs, anycast and multi-domain certificates do not imply a common owner, operator or intent. |

**Provider stance** is a coarse, documented, provider-attributed reading of
each claim, used only to detect disagreement:

| Observation | `flags` | `does_not_flag` | `no_record` | `unclear` |
|---|---|---|---|---|
| `ip_reputation` (AbuseIPDB) | `total_reports` > 0 | `total_reports` = 0 | — | count missing |
| `provider_reputation` (VirusTotal) | `malicious` + `suspicious` > 0 | all five counters known, at least one engine result, none flagged | — | otherwise |
| `provider_listing` (URLhaus, MalwareBazaar) | always (the indicator is listed in the provider's malware database) | — | — | — |
| `provider_no_record` | — | — | always | — |

A stance is the provider's, not Sentinel's: `flags` means "this provider
reports something", not "malicious".

## Deliberately not implemented

These are intentionally out of scope for v0.1 (see `docs/ARCHITECTURE.md`,
"v0.1 scope"):

- No STIX export of correlations.
- No score, ranking, weighting, voting or combined confidence.
- No actor, campaign, ownership or compromise attribution; no MITRE ATT&CK
  mapping (a later, separate step).
- No transitive graph walks (e.g. alias chains) and no historical
  reasoning across investigations.
- No correlation of CT names without DNS data, and no new lookups to
  "complete" a chain.
- Discovered URLhaus URLs and payload hashes are not modeled (L37), so
  they are not correlated.

## Examples

```
correlation.domain_ip_infrastructure
  example.com --resolves_to--> 93.184.215.14   [dns 2026-09-23 17:40:12Z, digest 3f1c…]
  93.184.215.14 --announced_by--> AS15133       [cymru 17:40:13Z]
  93.184.215.14 --registered_in--> 93.184.215.0/24 [rdap 17:40:14Z]
  observed 17:40:12Z – 17:40:14Z (not simultaneous)

correlation.source_disagreement  45.33.32.156
  abuseipdb   flags          total_reports=41, abuse_confidence_score=95/100
  virustotal  no_record      no record
  → conflict kept; Sentinel does not decide which provider is right
```

## Limitations

See `docs/ARCHITECTURE.md` (L43 onward).
