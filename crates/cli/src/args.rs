//! Command-line arguments.

use std::path::PathBuf;

use clap::{ArgGroup, Args, Parser, Subcommand, ValueEnum};

/// Passive-first OSINT and threat intelligence investigations.
#[derive(Debug, Parser)]
#[command(name = "sentinel-osint", version, about, long_about = None)]
pub(crate) struct Cli {
    /// More log output on stderr (-v info, -vv debug, -vvv trace).
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    pub(crate) verbose: u8,

    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Investigate an indicator using passive, public sources.
    ///
    /// Optional providers: set `SENTINEL_ABUSEIPDB_KEY` to enable AbuseIPDB IP
    /// reputation, `SENTINEL_VIRUSTOTAL_KEY` to enable VirusTotal lookups
    /// (IP, domain, SHA-256), `SENTINEL_ABUSECH_KEY` to enable URLhaus
    /// lookups (domain, IPv4) and `SENTINEL_MALWAREBAZAAR_KEY` (or
    /// `SENTINEL_ABUSECH_KEY`) to enable MalwareBazaar hash lookups
    /// (SHA-256, SHA-1). Without a key, the source is reported as
    /// unavailable.
    Investigate(InvestigateArgs),
}

/// Arguments of `investigate`.
#[derive(Debug, Clone, Args)]
#[command(group(ArgGroup::new("target").required(true).args(["domain", "ip", "hash"])))]
pub(crate) struct InvestigateArgs {
    /// Domain name to investigate (defanged input such as example[.]com is accepted).
    #[arg(long, value_name = "DOMAIN")]
    pub(crate) domain: Option<String>,

    /// Public IPv4 or IPv6 address to investigate.
    #[arg(long, value_name = "IP")]
    pub(crate) ip: Option<String>,

    /// File hash to investigate (MD5, SHA-1 or SHA-256).
    #[arg(long, value_name = "HASH")]
    pub(crate) hash: Option<String>,

    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Table)]
    pub(crate) format: Format,

    /// Write the report to FILE (created with mode 0600; never overwritten)
    /// instead of stdout.
    #[arg(short, long, value_name = "FILE")]
    pub(crate) output: Option<PathBuf>,

    /// Deadline for the whole investigation, in seconds.
    #[arg(long, value_name = "SECONDS", default_value_t = 60,
          value_parser = clap::value_parser!(u64).range(1..=600))]
    pub(crate) timeout: u64,

    /// Add a Correlation section: explainable connections between the
    /// collected evidence (no extra lookups, no scores).
    #[arg(long)]
    pub(crate) correlate: bool,
}

/// Output formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum Format {
    /// Human-readable report.
    Table,
    /// Machine-readable JSON document.
    Json,
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("sentinel-osint").chain(args.iter().copied()))
    }

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn requires_exactly_one_target() {
        assert!(parse(&["investigate"]).is_err());
        assert!(parse(&["investigate", "--domain", "example.com", "--ip", "8.8.8.8"]).is_err());
        let cli = parse(&["investigate", "--domain", "example.com"]).unwrap();
        let Command::Investigate(args) = cli.command;
        assert_eq!(args.domain.as_deref(), Some("example.com"));
        assert_eq!(args.format, Format::Table);
        assert_eq!(args.timeout, 60);
    }

    #[test]
    fn validates_format_and_timeout() {
        assert!(parse(&["investigate", "--ip", "8.8.8.8", "--format", "xml"]).is_err());
        assert!(parse(&["investigate", "--ip", "8.8.8.8", "--timeout", "0"]).is_err());
        assert!(parse(&["investigate", "--ip", "8.8.8.8", "--timeout", "601"]).is_err());
        let cli = parse(&[
            "-vv",
            "investigate",
            "--hash",
            "abc",
            "--format",
            "json",
            "-o",
            "out.json",
        ])
        .unwrap();
        assert_eq!(cli.verbose, 2);
        let Command::Investigate(args) = cli.command;
        assert_eq!(args.format, Format::Json);
        assert_eq!(args.output, Some(PathBuf::from("out.json")));
    }
}
