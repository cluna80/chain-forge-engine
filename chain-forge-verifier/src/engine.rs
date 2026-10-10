//! `VerificationEngine` — the core verification state machine.
//!
//! ## Responsibilities
//!
//! * Accept an independent verification record from a verifier miner
//!   (`submit_verification`).
//! * After each successful insert, count the number of `'reproduced'`
//!   verifications for the associated result.
//! * If the count meets or exceeds the objective's `verification_quorum`,
//!   atomically transition the task from `'submitted'` to `'accepted'` and
//!   mark the result `'accepted'` as well.
//!
//! ## Consensus separation
//!
//! `'accepted'` is the highest status this service writes.  The on-chain
//! `DiscoveryReceipt` and `MicrotaskRegistry` (in `chain-forge-pocd`) remain
//! the sole authorities for reward eligibility.  This engine only records
//! that independent scientific reproduction has occurred.
//!
//! ## Self-verification
//!
//! A miner that submitted a result (`miner_id` on the `experiment_results`
//! row) is unconditionally barred from verifying it.  The check occurs at
//! three layers (DB constraint, `insert_verification`, and `VerificationEngine`
//! here) so it is never silently skipped.
//!
//! ## Quorum rules
//!
//! * Only `outcome = 'reproduced'` votes count toward the quorum.
//! * `'diverged'` and `'inconclusive'` outcomes are recorded for provenance
//!   but do not advance the quorum counter.
//! * A verifier may submit at most one verification per result.  Duplicates
//!   return `VerifierError::DuplicateVerification`.

use std::sync::Arc;

use tracing::{debug, info};
use uuid::Uuid;

use chain_forge_research_db::{
    ResearchDb,
    models::NewVerificationRecord,
};

use crate::error::{VerifierError, VerifierResult};

/// Valid verification outcomes.
const VALID_OUTCOMES: &[&str] = &["reproduced", "diverged", "inconclusive"];

/// The verification engine.  Clone-cheap (holds an `Arc` internally).
#[derive(Clone)]
pub struct VerificationEngine {
    pub(crate) db: Arc<dyn ResearchDb>,
}

impl VerificationEngine {
    /// Create a new engine with the given database handle.
    pub fn new(db: Arc<dyn ResearchDb>) -> Self {
        Self { db }
    }

    // ── public API ────────────────────────────────────────────────────────────

    /// Submit an independent verification for a previously submitted result.
    ///
    /// ## Returns
    ///
    /// `Ok(true)` — the verification record was inserted AND the quorum was
    /// met; the task has been transitioned to `'accepted'`.
    ///
    /// `Ok(false)` — the verification record was inserted but the quorum has
    /// not been reached yet.
    ///
    /// ## Errors
    ///
    /// * `SelfVerification` — `verifier_id` matches the original submitter.
    /// * `DuplicateVerification` — this verifier has already submitted for
    ///   this result.
    /// * `InvalidOutcome` — unrecognised outcome string.
    /// * `TaskNotSubmitted` — the task is not in `submitted` status.
    /// * `AlreadyAccepted` — the task has already been accepted.
    /// * `Db(…)` — propagated database error.
    pub async fn submit_verification(
        &self,
        task_id:              &str,
        result_id:            Uuid,
        verifier_id:          &str,
        outcome:              &str,
        verifier_content_hash: &str,
        notes:                Option<String>,
        verifier_receipt_id:  Option<String>,
    ) -> VerifierResult<bool> {
        // ── validate outcome ────────────────────────────────────────────────
        if !VALID_OUTCOMES.contains(&outcome) {
            return Err(VerifierError::InvalidOutcome(outcome.to_string()));
        }

        // ── fetch task ──────────────────────────────────────────────────────
        let task = self
            .db
            .get_task(task_id)
            .await?
            .ok_or_else(|| VerifierError::TaskNotFound {
                task_id: task_id.to_string(),
            })?;

        match task.status.as_str() {
            "accepted" => return Err(VerifierError::AlreadyAccepted {
                task_id: task_id.to_string(),
            }),
            "submitted" => { /* proceed */ }
            other => return Err(VerifierError::TaskNotSubmitted {
                task_id: task_id.to_string(),
                status:  other.to_string(),
            }),
        }

        // ── fetch result and check self-verification ────────────────────────
        let result = self
            .db
            .get_result(result_id)
            .await?
            .ok_or(VerifierError::ResultNotFound(result_id))?;

        if result.miner_id == verifier_id {
            return Err(VerifierError::SelfVerification(verifier_id.to_string()));
        }

        // ── check for duplicate from this verifier ──────────────────────────
        let existing = self
            .db
            .list_verifications_for_result(result_id)
            .await?;
        if existing.iter().any(|v| v.verifier_id == verifier_id) {
            return Err(VerifierError::DuplicateVerification {
                verifier_id: verifier_id.to_string(),
                result_id,
            });
        }

        // ── insert the verification record ──────────────────────────────────
        self.db
            .insert_verification(NewVerificationRecord {
                result_id,
                task_id:              task_id.to_string(),
                verifier_id:          verifier_id.to_string(),
                outcome:              outcome.to_string(),
                verifier_content_hash: verifier_content_hash.to_string(),
                notes,
                verifier_receipt_id,
            })
            .await?;

        debug!(
            task_id,
            result_id = %result_id,
            verifier_id,
            outcome,
            "verification record inserted"
        );

        // ── check quorum ────────────────────────────────────────────────────
        // Only 'reproduced' verifications count toward the quorum.
        let reproduced = self
            .db
            .count_reproduced_verifications(result_id)
            .await?;

        let objective_id = &task.objective_id;
        let quorum = self
            .db
            .get_verification_quorum(objective_id)
            .await? as u64;

        if reproduced >= quorum {
            // Quorum met — transition task and result to 'accepted'.
            self.db.accept_task(task_id, result_id).await?;

            info!(
                task_id,
                result_id = %result_id,
                reproduced,
                quorum,
                "verification quorum met — task accepted"
            );

            return Ok(true);
        }

        debug!(
            task_id,
            result_id = %result_id,
            reproduced,
            quorum,
            "verification recorded — quorum not yet met"
        );

        Ok(false)
    }

    /// List tasks for an objective that are in `'submitted'` status and
    /// therefore awaiting independent verification.
    pub async fn list_submitted_tasks(
        &self,
        objective_id: &str,
    ) -> VerifierResult<Vec<chain_forge_research_db::models::TaskRow>> {
        Ok(self.db.list_submitted_tasks(objective_id).await?)
    }
}
