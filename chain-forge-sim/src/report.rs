//! The report this crate actually produces. The scope banner at the top
//! of render() is not decoration -- it travels with the report wherever
//! it's shared, specifically so this can't get separated from its output
//! and mistaken for pilot evidence later.

use crate::context::TxLogEntry;
use crate::persona::CheckResult;

pub struct EpochReport {
    pub epoch:  u64,
    pub tx_log: Vec<TxLogEntry>,
    /// (persona_id, check_result) pairs from this epoch's expectation checks.
    pub checks: Vec<(String, CheckResult)>,
    /// (persona_id, error message) for any run_epoch() that returned Err.
    pub persona_errors: Vec<(String, String)>,
}

impl EpochReport {
    pub fn new(epoch: u64) -> Self {
        Self { epoch, tx_log: Vec::new(), checks: Vec::new(), persona_errors: Vec::new() }
    }

    pub fn failed_checks(&self) -> impl Iterator<Item = &(String, CheckResult)> {
        self.checks.iter().filter(|(_, c)| !c.passed)
    }
}

pub struct SimReport {
    pub persona_ids: Vec<String>,
    pub epochs:      Vec<EpochReport>,
}

impl SimReport {
    pub fn new(persona_ids: Vec<String>) -> Self {
        Self { persona_ids, epochs: Vec::new() }
    }

    pub fn total_checks(&self) -> usize {
        self.epochs.iter().map(|e| e.checks.len()).sum()
    }

    pub fn total_failures(&self) -> usize {
        self.epochs.iter().map(|e| e.failed_checks().count()).sum()
    }

    pub fn total_persona_errors(&self) -> usize {
        self.epochs.iter().map(|e| e.persona_errors.len()).sum()
    }

    pub fn render(&self) -> String {
        let mut out = String::new();

        out.push_str("================================================================\n");
        out.push_str("chain-forge-sim -- MECHANICAL INTEGRATION TEST REPORT\n");
        out.push_str("================================================================\n");
        out.push_str("SCOPE: This is a scripted software integration test. It is NOT\n");
        out.push_str("evidence of sybil resistance and must not be cited as pilot\n");
        out.push_str("results in the whitepaper or any external communication. Every\n");
        out.push_str("persona -- including the fault-injection ones -- can only take\n");
        out.push_str("actions its own author anticipated. Real adversarial testing\n");
        out.push_str("requires real, independent humans (see Identity Pilot Design,\n");
        out.push_str("Section 2, \"What the Pilot Is Not\").\n");
        out.push_str("This report belongs in an internal engineering log.\n");
        out.push_str("================================================================\n\n");

        out.push_str(&format!("Personas: {}\n", self.persona_ids.join(", ")));
        out.push_str(&format!("Epochs run: {}\n", self.epochs.len()));
        out.push_str(&format!(
            "Checks: {} total, {} failed, {} persona errors\n\n",
            self.total_checks(), self.total_failures(), self.total_persona_errors()
        ));

        for epoch in &self.epochs {
            out.push_str(&format!("--- Epoch {} ---\n", epoch.epoch));

            let confirmed = epoch.tx_log.iter()
                .filter(|e| matches!(e.outcome, crate::context::TxOutcome::Confirmed { success: true, .. }))
                .count();
            let failed = epoch.tx_log.iter()
                .filter(|e| matches!(e.outcome, crate::context::TxOutcome::Confirmed { success: false, .. }))
                .count();
            let rejected = epoch.tx_log.iter()
                .filter(|e| matches!(e.outcome, crate::context::TxOutcome::RejectedAtSubmission { .. }))
                .count();
            let queued = epoch.tx_log.iter()
                .filter(|e| matches!(e.outcome, crate::context::TxOutcome::Queued))
                .count();

            out.push_str(&format!(
                "  transactions: {} confirmed-ok, {} confirmed-failed, {} rejected-at-submission, {} still queued\n",
                confirmed, failed, rejected, queued
            ));

            for entry in &epoch.tx_log {
                let outcome_str = match &entry.outcome {
                    crate::context::TxOutcome::Confirmed { success: true, .. } => "ok".to_string(),
                    crate::context::TxOutcome::Confirmed { success: false, error, .. } =>
                        format!("failed ({})", error.clone().unwrap_or_default()),
                    crate::context::TxOutcome::RejectedAtSubmission { message } =>
                        format!("rejected ({message})"),
                    crate::context::TxOutcome::Queued => "queued (no confirmation yet)".to_string(),
                };
                out.push_str(&format!("    [{}] {} -- {}\n", entry.persona_id, entry.kind, outcome_str));
            }

            for (persona_id, check) in &epoch.checks {
                let mark = if check.passed { "PASS" } else { "FAIL" };
                out.push_str(&format!("  [{mark}] {persona_id}: {}", check.description));
                if let Some(detail) = &check.detail {
                    out.push_str(&format!(" -- {detail}"));
                }
                out.push('\n');
            }

            for (persona_id, err) in &epoch.persona_errors {
                out.push_str(&format!("  [ERROR] {persona_id}: {err}\n"));
            }

            out.push('\n');
        }

        out.push_str("================================================================\n");
        if self.total_failures() == 0 && self.total_persona_errors() == 0 {
            out.push_str("RESULT: all checks passed. See SCOPE note above before using\n");
            out.push_str("this anywhere -- passing here means the mechanical loop works,\n");
            out.push_str("nothing more.\n");
        } else {
            out.push_str(&format!(
                "RESULT: {} check(s) failed, {} persona error(s). Investigate before\n\
                 relying on this build for a real pilot.\n",
                self.total_failures(), self.total_persona_errors()
            ));
        }
        out.push_str("================================================================\n");

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_includes_scope_banner() {
        let report = SimReport::new(vec!["alice".into()]);
        let text = report.render();
        assert!(text.contains("NOT"));
        assert!(text.contains("sybil resistance"));
        assert!(text.contains("internal engineering log"));
    }

    #[test]
    fn render_summarises_pass_fail_counts() {
        let mut report = SimReport::new(vec!["alice".into()]);
        let mut epoch = EpochReport::new(0);
        epoch.checks.push(("alice".into(), CheckResult::pass("registered")));
        epoch.checks.push(("alice".into(), CheckResult::fail("verified", "still Provisional")));
        report.epochs.push(epoch);

        assert_eq!(report.total_checks(), 2);
        assert_eq!(report.total_failures(), 1);

        let text = report.render();
        assert!(text.contains("1 check(s) failed"));
    }

    #[test]
    fn empty_report_renders_all_pass() {
        let report = SimReport::new(vec![]);
        let text = report.render();
        assert!(text.contains("all checks passed"));
    }
}
