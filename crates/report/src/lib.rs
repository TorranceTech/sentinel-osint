//! # sentinel-report
//!
//! Renders an [`Investigation`](sentinel_core::Investigation):
//!
//! - [`table`]: a human-readable report for the terminal. Every value that
//!   may contain external data is sanitized (control characters, ANSI escape
//!   sequences and bidi overrides are replaced) and length-bounded.
//! - [`json`]: the stable, machine-readable document for automation, SIEMs
//!   and later STIX export, versioned by [`json::SCHEMA_VERSION`].
//!
//! Both also render an optional
//! [`CorrelationReport`](sentinel_correlation::CorrelationReport)
//! (`table::render_correlated`, `json::render_correlated`).
//!
//! Renderers do no I/O. They return strings, and the caller decides where
//! those go.

mod correlation;
pub mod json;
pub mod table;
