//! JSON output.
//!
//! The document is:
//!
//! ```json
//! { "schema_version": "0.1", "investigation": { ... } }
//! ```
//!
//! `investigation` is the serialized [`Investigation`] (its shape is pinned
//! by `sentinel-core`'s JSON contract tests). The output contains nothing
//! else: no banners, no log lines, no progress text. Strings are escaped by
//! `serde_json`, so hostile content cannot break the document structure.
//!
//! With correlation enabled, a third member `correlation` holds the
//! [`CorrelationReport`]. Adding it is compatible, so `schema_version` is
//! unchanged.
//!
//! `schema_version` changes when the shape changes incompatibly (renamed or
//! removed fields, changed types). Adding fields is not a breaking change,
//! so consumers should ignore unknown fields.

use sentinel_core::Investigation;
use sentinel_correlation::CorrelationReport;
use serde::Serialize;

/// Version of the JSON document format.
pub const SCHEMA_VERSION: &str = "0.1";

#[derive(Serialize)]
struct Document<'a> {
    schema_version: &'static str,
    investigation: &'a Investigation,
    #[serde(skip_serializing_if = "Option::is_none")]
    correlation: Option<&'a CorrelationReport>,
}

/// Renders the investigation as a pretty-printed JSON document, ending with
/// a newline.
///
/// # Errors
/// Only if serialization fails, which the model's types do not do in practice.
pub fn render(investigation: &Investigation) -> Result<String, serde_json::Error> {
    render_document(investigation, None)
}

/// Renders the investigation and its correlation report. The report is an
/// additional top-level `correlation` member; it references observations
/// of `investigation` by ID instead of copying them.
///
/// # Errors
/// Only if serialization fails, which the model's types do not do in practice.
pub fn render_correlated(
    investigation: &Investigation,
    report: &CorrelationReport,
) -> Result<String, serde_json::Error> {
    render_document(investigation, Some(report))
}

fn render_document(
    investigation: &Investigation,
    correlation: Option<&CorrelationReport>,
) -> Result<String, serde_json::Error> {
    let mut output = serde_json::to_string_pretty(&Document {
        schema_version: SCHEMA_VERSION,
        investigation,
        correlation,
    })?;
    output.push('\n');
    Ok(output)
}
