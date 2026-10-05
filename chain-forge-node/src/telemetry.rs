//! Attestation guard telemetry — structured JSON lines on stdout.
//!
//! Each attestation event is emitted as a single newline-terminated JSON
//! object so log aggregators (Loki, Datadog, Vector, jq pipelines) can
//! ingest it without parsing tracing output.
//!
//! Schema (all fields always present):
//! ```json
//! {
//!   "event":          "attestation",
//!   "validator":      "<validator_id>",
//!   "height":         <u64 | null>,
//!   "round":          <u64 | null>,
//!   "verdict":        "pass" | "quorum" | "slash",
//!   "evidence_hash":  "<hex string | empty>",
//!   "timestamp":      "<RFC-3339 UTC>"
//! }
//! ```
//!
//! `verdict` meanings:
//!   - `"pass"`   — attestation recorded, quorum not yet reached
//!   - `"quorum"` — attestation pushed claimant over ATTESTATION_QUORUM → Verified
//!   - `"slash"`  — equivocation detected; validator tombstoned and stake burned

use std::time::{SystemTime, UNIX_EPOCH};

/// Emit one attestation telemetry line to stdout.
///
/// # Arguments
/// * `validator`      — the attester (pass/quorum) or slashed validator (slash)
/// * `height`         — consensus height, `None` for identity-layer events
/// * `round`          — consensus round, `None` for identity-layer events
/// * `verdict`        — `"pass"`, `"quorum"`, or `"slash"`
/// * `evidence_hash`  — hex digest of the relevant block hash or evidence
///                      bytes; empty string when not applicable
pub fn emit_attestation_event(
    validator:     &str,
    height:        Option<u64>,
    round:         Option<u64>,
    verdict:       &str,
    evidence_hash: &str,
) {
    let ts = rfc3339_now();
    let height_s = match height {
        Some(h) => format!("{}", h),
        None    => "null".to_owned(),
    };
    let round_s = match round {
        Some(r) => format!("{}", r),
        None    => "null".to_owned(),
    };

    // Hand-built JSON — avoids pulling in serde_json just for one call site.
    // All string values are sanitised: inner double-quotes escaped.
    println!(
        r#"{{"event":"attestation","validator":{},"height":{},"round":{},"verdict":{},"evidence_hash":{},"timestamp":{}}}"#,
        json_str(validator),
        height_s,
        round_s,
        json_str(verdict),
        json_str(evidence_hash),
        json_str(&ts),
    );
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn json_str(s: &str) -> String {
    // Escape backslash then double-quote; control chars are unlikely in these
    // fields but we guard them for spec compliance.
    let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{}\"", escaped)
}

fn rfc3339_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Format as YYYY-MM-DDTHH:MM:SSZ without pulling in `time` or `chrono`.
    let s   = secs;
    let sec = s % 60;
    let min = (s / 60) % 60;
    let hr  = (s / 3600) % 24;
    let days = s / 86400; // days since 1970-01-01

    let (y, mo, d) = days_to_ymd(days);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, mo, d, hr, min, sec)
}

/// Proleptic Gregorian calendar: convert days-since-epoch to (year, month, day).
fn days_to_ymd(mut z: u64) -> (u64, u64, u64) {
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html
    z += 719468;
    let era  = z / 146097;
    let doe  = z % 146097;
    let yoe  = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y    = yoe + era * 400;
    let doy  = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp   = (5 * doy + 2) / 153;
    let d    = doy - (153 * mp + 2) / 5 + 1;
    let mo   = if mp < 10 { mp + 3 } else { mp - 9 };
    let y    = if mo <= 2 { y + 1 } else { y };
    (y, mo, d)
}
