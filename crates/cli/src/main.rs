//! `sentinel-osint`: passive-first OSINT and threat intelligence investigations.
//!
//! Reports go to stdout (or `--output`); logs and errors go to stderr.
//!
//! Exit codes: `0` investigation completed (sources may have failed; see the
//! report), `1` fatal error, `2` invalid usage or input.

// The CLI is the one place that writes to the terminal.
#![allow(clippy::print_stderr)]

mod app;
mod args;
mod config;
mod output;

use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use sentinel_collectors::{DnsResolver, HickoryResolver};
use tracing::Level;

use crate::app::AppError;
use crate::args::{Cli, Command};

const EXIT_FATAL: u8 = 1;
const EXIT_USAGE: u8 = 2;

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_logging(cli.verbose);

    let Command::Investigate(args) = cli.command;

    // Validate before touching the network or the system configuration.
    let target = match app::parse_target(&args) {
        Ok(target) => target,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::from(EXIT_USAGE);
        }
    };

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("error: could not start the async runtime: {error}");
            return ExitCode::from(EXIT_FATAL);
        }
    };

    // Read once; the values are secrets and are never printed.
    let credentials = config::Credentials::from_env();
    let result = runtime.block_on(async {
        let resolver: Arc<dyn DnsResolver> =
            Arc::new(HickoryResolver::from_system().map_err(|e| AppError::Fatal(e.into()))?);
        app::investigate(
            &args,
            target,
            app::default_collectors(&resolver, credentials),
        )
        .await
    });

    let report = match result {
        Ok(report) => report,
        Err(AppError::InvalidInput(error)) => {
            eprintln!("error: {error}");
            return ExitCode::from(EXIT_USAGE);
        }
        Err(AppError::Fatal(error)) => {
            eprintln!("error: {error:#}");
            return ExitCode::from(EXIT_FATAL);
        }
    };

    match output::write_report(&report, args.output.as_deref()) {
        Ok(()) => {
            if let Some(path) = &args.output {
                eprintln!("Report written to {}", path.display());
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::from(EXIT_FATAL)
        }
    }
}

/// Plain-text logs on stderr. Warnings by default; `-v` for more.
fn init_logging(verbosity: u8) {
    let level = match verbosity {
        0 => Level::WARN,
        1 => Level::INFO,
        2 => Level::DEBUG,
        _ => Level::TRACE,
    };
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(level)
        .with_target(false)
        .init();
}
