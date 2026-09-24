//! The `Correlation` section of the table report.
//!
//! Every correlation is shown with its links, the evidence behind each link
//! (source, collection time, capture confidence, digest), provider claims,
//! conflicts, gaps, the collection window and its caveats. Never a number
//! standing alone. External text is sanitized.

use std::fmt::Write as _;

use sentinel_core::text::sanitize_single_line;
use sentinel_core::{Investigation, Observation, ObservationId};
use sentinel_correlation::{Correlation, CorrelationReport};

use crate::table::{safe, section as heading};

/// Evidence entries listed per link before "(+N more)".
const EVIDENCE_PER_LINK: usize = 3;
/// Links listed per correlation before "(+N more)".
const LINKS_SHOWN: usize = 10;
const LABEL: usize = 10;
const INDENT: usize = 4;
const WIDTH: usize = 78;
const MAX_TEXT: usize = 1_000;
/// Collection times with milliseconds: evidence is often collected within
/// the same second.
const TIME: &str = "%Y-%m-%d %H:%M:%S%.3f UTC";

pub(crate) fn section_title(report: &CorrelationReport) -> String {
    format!("Correlation ({})", report.correlations.len())
}

pub(crate) fn section(out: &mut String, investigation: &Investigation, report: &CorrelationReport) {
    heading(out, &section_title(report));
    wrapped(
        out,
        "",
        "Derived from the observations above without new lookups. Relations, claims and disagreements are shown with their evidence; nothing is scored or ranked.",
        2,
    );
    if report.correlations.is_empty() {
        let _ = writeln!(out, "\n  No correlations in this investigation.");
    }
    for (i, correlation) in report.correlations.iter().enumerate() {
        let _ = writeln!(out);
        entry(out, investigation, i + 1, correlation);
    }
    for limitation in &report.limitations {
        let _ = writeln!(out);
        wrapped(out, "Note", limitation, 2);
    }
}

fn entry(out: &mut String, investigation: &Investigation, n: usize, c: &Correlation) {
    let _ = writeln!(out, "  [{n}] {} · {}", c.kind().finding_code(), c.id());
    wrapped(out, "", c.summary(), INDENT);
    for link in c.links().iter().take(LINKS_SHOWN) {
        let text = format!("{} --{}--> {}", link.source(), link.kind(), link.target());
        wrapped(out, "Link", &text, INDENT);
        evidence_lines(out, investigation, link.evidence());
    }
    if c.links().len() > LINKS_SHOWN {
        wrapped(
            out,
            "",
            &format!(
                "(+{} more links; see --format json)",
                c.links().len() - LINKS_SHOWN
            ),
            INDENT,
        );
    }
    for claim in c.claims() {
        let text = format!(
            "{} · {} · {}",
            claim.provider,
            claim.stance.as_str(),
            claim.summary
        );
        wrapped(out, "Claim", &text, INDENT);
        evidence_lines(out, investigation, &[claim.observation]);
    }
    if !c.supporting().is_empty() {
        wrapped(out, "Context", "supporting observations:", INDENT);
        evidence_lines(out, investigation, c.supporting());
    }
    for conflict in c.conflicts() {
        wrapped(out, "Conflict", &conflict.description, INDENT);
        evidence_lines(out, investigation, &conflict.evidence);
    }
    for gap in c.gaps() {
        wrapped(out, "Gap", gap, INDENT);
    }
    let observed = c.observed();
    let window = if observed.first == observed.last {
        observed.first.format(TIME).to_string()
    } else {
        format!(
            "{} – {}",
            observed.first.format(TIME),
            observed.last.format(TIME)
        )
    };
    wrapped(out, "Observed", &window, INDENT);
    wrapped(
        out,
        "Evidence",
        &format!(
            "{} observation(s); lowest capture confidence {} (evidence quality, not likelihood of maliciousness)",
            c.evidence().len(),
            c.evidence_confidence().value()
        ),
        INDENT,
    );
    for limitation in c.limitations() {
        wrapped(out, "Note", limitation, INDENT);
    }
}

/// `source · time · confidence · digest` for each cited observation.
/// Listed in collection order (then source), which reads as a timeline.
fn evidence_lines(out: &mut String, investigation: &Investigation, ids: &[ObservationId]) {
    let mut ordered: Vec<(Option<&Observation>, ObservationId)> = ids
        .iter()
        .map(|id| (investigation.observation(*id), *id))
        .collect();
    ordered.sort_by_key(|(o, id)| {
        (
            o.is_none(),
            o.map(|o| (o.collected_at(), o.source().clone())),
            *id,
        )
    });
    for (observation, id) in ordered.iter().take(EVIDENCE_PER_LINK) {
        let text = match observation {
            Some(o) => format!(
                "{} · {} · confidence {} · {}",
                o.source(),
                o.collected_at().format(TIME),
                o.confidence().value(),
                o.raw_response_hash().map_or_else(
                    || "no digest".to_owned(),
                    |d| format!("sha256 {}…", &d.to_string()[..12])
                )
            ),
            None => format!("{id} (not in this investigation)"),
        };
        wrapped(out, "", &format!("↳ {text}"), INDENT + LABEL);
    }
    if ids.len() > EVIDENCE_PER_LINK {
        wrapped(
            out,
            "",
            &format!("↳ (+{} more observations)", ids.len() - EVIDENCE_PER_LINK),
            INDENT + LABEL,
        );
    }
}

/// Writes `label` then `text`, wrapped, sanitized, continuation lines
/// aligned after the label.
fn wrapped(out: &mut String, label: &str, text: &str, indent: usize) {
    let text = sanitize_single_line(text, MAX_TEXT);
    let first = if label.is_empty() {
        " ".repeat(indent)
    } else {
        format!("{}{:<LABEL$}", " ".repeat(indent), safe(label))
    };
    let rest = " ".repeat(if label.is_empty() {
        indent
    } else {
        indent + LABEL
    });
    let mut line = first.clone();
    let mut empty = true;
    for word in text.split_whitespace() {
        if !empty && line.chars().count() + 1 + word.chars().count() > WIDTH {
            let _ = writeln!(out, "{}", line.trim_end());
            line.clone_from(&rest);
            empty = true;
        }
        if !empty {
            line.push(' ');
        }
        line.push_str(word);
        empty = false;
    }
    let _ = writeln!(out, "{}", line.trim_end());
}
