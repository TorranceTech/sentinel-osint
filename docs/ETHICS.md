# Ethics and Responsible Use

Sentinel OSINT exists to improve **defensive** security: understanding
infrastructure, enriching indicators of compromise, and supporting incident
response and threat intelligence with verifiable evidence.

## Principles

- **Passive-first.** Prefer public data and the least interaction with any system.
- **Lawful and authorized.** Use it for security operations, research, and
  education within applicable law and source terms of service.
- **Data minimization.** Collect only what the investigation needs; avoid
  personal data.
- **Evidence and reproducibility.** Every result is traceable to its source and time.
- **Infrastructure, not people.** The tool investigates indicators and
  infrastructure, not private individuals.

## Capability levels

Every capability is classified before implementation:

| Level | Name | Description | Project status |
|---|---|---|---|
| 1 | Passive | Retrieval of public information: DNS, RDAP, CT logs, public APIs | ✅ In scope |
| 2 | Enrichment | Correlating existing intelligence: reputation, ASN relationships, STIX | ✅ In scope |
| 3 | Active, non-intrusive | Interacting with target infrastructure without exploitation or authentication | ⚠️ Only with a documented justification in this file |
| 4 | Security testing | Interacting with a target's security controls (scanning, probing) | ❌ Out of scope |
| 5 | Offensive | Credential attacks, exploitation, persistence, evasion, malware, unauthorized access | ❌ Out of scope |

**Default scope: Levels 1–2.** No Level 3 capability exists in v0.1.

## Intended uses

- ✅ SOC alert triage and IOC enrichment
- ✅ Threat intelligence research and reporting (STIX 2.1)
- ✅ Incident response: scoping attacker infrastructure
- ✅ Assessing your own organization's external footprint (DNS, email
  authentication, certificates)
- ✅ Cybersecurity education and training

## Not intended for, and not implemented

- ❌ Credential theft, credential stuffing, or password attacks
- ❌ Phishing or phishing infrastructure
- ❌ Account compromise or account takeover
- ❌ Exploitation, malware deployment, or persistence
- ❌ Evasion of security controls
- ❌ Unauthorized access
- ❌ Subdomain brute forcing or active scanning
- ❌ Doxxing, stalking, harassment, or profiling of private individuals

## Personal data

- RDAP personal contact entities (natural persons) are not extracted.
- Username and email intelligence is **not** part of v0.1. If it is added
  (roadmap Phase 5), it must first be reviewed against this document with
  explicit limits: no correlation of private individuals across platforms by
  default, no scraping of private content, and clear confidence and
  false-positive handling.

## Level 3 justifications

_None._ Any future Level 3 capability must be added here with its purpose,
exact interaction, opt-in mechanism, and risks before it is implemented.

## OPSEC notice for analysts

Looking up an indicator can disclose your interest in it to resolvers,
authoritative nameservers, and third-party APIs. See `docs/THREAT-MODEL.md`
(T5). In v0.1, keyed providers are contacted only when their API key is set,
so unsetting a key excludes that provider (`--sources` is not available yet,
L12).
