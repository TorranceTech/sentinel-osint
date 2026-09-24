# Security Policy

## Supported versions

Sentinel OSINT is in early development. Only the latest release on the `main`
branch receives security fixes.

## Reporting a vulnerability

Please **do not open a public issue** for security vulnerabilities.

Report privately through GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
("Security" tab → "Report a vulnerability").

Please include:
- affected version/commit
- a description of the issue and its impact
- steps to reproduce or a proof of concept (a crafted DNS/API response is ideal)

You can expect an acknowledgment within 7 days. Fixes are coordinated with
the reporter, and reporters are credited unless they prefer otherwise.

## In scope

Vulnerabilities in Sentinel OSINT itself, for example:
- SSRF or connections to unintended hosts
- API key leakage (logs, output, errors, files)
- Terminal or report injection through crafted external data
- Crashes, hangs, or resource exhaustion caused by malicious responses
- Insecure file handling of reports or configuration

See `docs/THREAT-MODEL.md` for the full threat model.

## Out of scope

- Vulnerabilities in third-party data sources or their APIs
- Findings that require a compromised host or a malicious operator
- Misuse of the tool contrary to `docs/ETHICS.md` (that is a misuse, not a
  vulnerability)

## Security practices

- `unsafe` code is forbidden in the workspace.
- CI runs `cargo fmt`, `cargo clippy -D warnings`, `cargo test`, and `cargo audit`.
- Secrets are never committed. API keys are read from environment variables
  (a config file is not part of v0.1).
