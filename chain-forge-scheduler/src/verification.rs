//! Change Set M — Independent Verification Engine
//!
//! ## Purpose
//!
//! Bridges the gap between a miner submitting a result (`'submitted'` status)
//! and that result becoming eligible for reward settlement (`'accepted'` status).
//!
//! ## Protocol
//!
//! 1. A verifier calls `POST /scheduler/tasks/{task_id}/verify` and supplies:
//!    - `result_id`   — the UUID of the result being reproduced or rejected
//!    - `verifier_id` — the verifier's identity (must differ from the original miner)
//!    - `outcome`     — `"reproduced"` | `"rejected"` | `"inconclusive"`
//!    - `verifier_content_hash` — the hash the verifier independently computed
//!      (must match the original for `"reproduced"`)
//!    - optional `verifier_receipt_id` — PoCD `DiscoveryReceipt.receipt_id` if
//!      the verifier used the PoCD protocol to produce their own proof
//!    - optional `notes`
//!
//! 2. `VerificationEngine::record_verification()` validates and stores the record.
//!    Self-verification is rejected at the DB layer (returns `SelfVerification`).
//!
//! 3. After each successful `"reproduced"` record, the engine checks whether
//!    the `count(reproduced) >= verification_quorum` for the result's objective.
//!
//! 4. When quorum is met → `ResearchDb::accept_task_canonical()` is called
//!    atomically, promoting this result to canonical and marking all competing
//!    results for the same task as `'superseded'`.
//!
//! ## Relationship to DiscoveryReceipt
//!
//! Verifiers are expected to run the same PoCD mining protocol as miners and
//! produce their own `DiscoveryReceipt` (via `chain-forge-pocd`).  The receipt
//! ID is carried in `verifier_receipt_id`; this crate treats it as an opaque
//! string — it does NOT duplicate the PoCD registry or re-implement seal
//! verification.  The scheduler trusts that verifiers use the PoCD protocol
//! and stores their receipt ID for auditability and downstream use by
//! settlement operators.
//!
//! ## Scientific integrity
//!
//! No result is automatically classified as a cryptographic breakthrough.
//! No experimental result is automatically classified as a cryptographic
//! anomaly or scientific discovery.  This engine records what verifiers
//! observed; scientific interpretation is left to human researchers and
//! the chain's governance processes.

use std::sync::Arc;

use uuid::Uuid;
use tracing::{info, warn};

use chain_forge_research_db::{
    ResearchDb, ResearchDbError,
    models::NewVerificationRecord,
};

use crate::error::SchedulerError;

// ── Public request / response types ──────────────────────────────────────────

/// Request body for `POST /scheduler/tasks/{task_id}/verify`.
#[derive(Debug, serde::Deserialize)]
pub struct VerifyRequest {
    /// UUID of the result being independently verified.
    pub result_id: Uuid,

    /// Verifier's identity string.  Must not match the original miner's ID;
    /// the DB layer returns `ResearchDbError::SelfVerification` if it does.
    pub verifier_id: String,

    /// Verification outcome.
    ///
    /// - `"reproduced"` — the verifier independently computed the same hash.
    ///   Counts toward the quorum.
    /// - `"rejected"` — the verifier's result differed.  Does NOT count toward
    ///   quorum; may trigger further investigation in a future change set.
    /// - `"inconclusive"` — the verifier could not complete verification (e.g.
    ///   external oracle unavailable).  Recorded but not counted.
    pub outcome: String,

    /// The content hash the verifier independently computed.
    ///
    /// For `"reproduced"`, this MUST match the original result's `content_hash`.
    /// The engine enforces this and returns `HashMismatch` if it doesn't.
    pub verifier_content_hash: String,

    /// Optional PoCD `DiscoveryReceipt.receipt_id` from the verifier's own
    /// proof run.  Stored for auditability; not required.
    pub verifier_receipt_id: Option<String>,

    /// Optional free-text notes from the verifier.
    pub notes: Option<String>,
}

/// Response body for a successful verification submission.
#[derive(Debug, serde::Serialize)]
pub struct VerifyResponse {
    /// UUID of the created verification record.
    pub verification_id: Uuid,

    /// Current reproduced-verification count for this result.
    pub reproduced_count: u64,

    /// Quorum required for canonical acceptance.
    pub quorum_required: u32,

    /// Whether quorum was reached and canonical acceptance triggered.
    pub quorum_reached: bool,

    /// If `quorum_reached`, the task/result status after acceptance.
    pub status: String,
}

/// Verification-specific errors.
#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
    #[error("result '{0}' not found")]
    ResultNotFound(Uuid),

    #[error("task '{0}' not found")]
    TaskNotFound(String),

    #[error("unknown outcome '{0}': expected 'reproduced', 'rejected', or 'inconclusive'")]
    UnknownOutcome(String),

    #[error(
        "hash mismatch: verifier computed '{verifier}' but result has '{original}'; \
         outcome must be 'rejected' or 'inconclusive' when hashes differ"
    )]
    HashMismatch { verifier: String, original: String },

    #[error("self-verification: verifier_id must differ from the original miner")]
    SelfVerification,

    #[error("result '{0}' is not in 'submitted' status — cannot add verification")]
    NotSubmitted(Uuid),

    #[error("database error: {0}")]
    Db(#[from] ResearchDbError),
}

// ── Engine ────────────────────────────────────────────────────────────────────

/// Stateless verification engine — all state lives in the DB.
///
/// Constructed once and shared via `AppState`.  Clone is cheap (Arc inside).
#[derive(Clone)]
pub struct VerificationEngine {
    db: Arc<dyn ResearchDb>,
}

impl VerificationEngine {
    pub fn new(db: Arc<dyn ResearchDb>) -> Self {
        Self { db }
    }

    /// Record one independent verification and, if quorum is now met, promote
    /// the result to canonical.
    ///
    /// # Errors
    ///
    /// - `ResultNotFound`  — `result_id` not in DB
    /// - `TaskNotFound`    — parent task missing (shouldn't happen in practice)
    /// - `UnknownOutcome`  — outcome string is not a known value
    /// - `HashMismatch`    — `"reproduced"` claimed but hashes differ
    /// - `SelfVerification`— verifier is the original miner
    /// - `NotSubmitted`    — result is not in `'submitted'` status
    /// - `Db`              — unexpected DB error
    pub async fn record_verification(
        &self,
        task_id: &str,
        req:     VerifyRequest,
    ) -> Result<VerifyResponse, VerificationError> {
        // ── 1. Validate outcome string ────────────────────────────────────────
        match req.outcome.as_str() {
            "reproduced" | "rejected" | "inconclusive" => {}
            other => return Err(VerificationError::UnknownOutcome(other.to_owned())),
        }

        // ── 2. Load the result being verified ─────────────────────────────────
        let result = self
            .db
            .get_result(req.result_id)
            .await?
            .ok_or(VerificationError::ResultNotFound(req.result_id))?;

        // ── 3. Guard: result must be in 'submitted' status ────────────────────
        //
        // 'accepted' results already have a canonical record; 'superseded' ones
        // lost the race.  Adding verifications to either is a logic error on the
        // caller's part, not a DB error.
        if result.result_status != "submitted" {
            return Err(VerificationError::NotSubmitted(req.result_id));
        }

        // ── 4. Hash consistency check (reproduced only) ───────────────────────
        //
        // A verifier claiming "reproduced" MUST present the same content_hash.
        // Differing hashes mean the verifier's computation diverged, so the
        // correct outcome is "rejected" or "inconclusive".
        if req.outcome == "reproduced" && req.verifier_content_hash != result.content_hash {
            return Err(VerificationError::HashMismatch {
                verifier: req.verifier_content_hash,
                original: result.content_hash,
            });
        }

        // ── 5. Insert verification record (DB enforces self-verification guard) ─
        let record = match self
            .db
            .insert_verification(NewVerificationRecord {
                result_id:             req.result_id,
                task_id:               task_id.to_owned(),
                verifier_id:           req.verifier_id.clone(),
                outcome:               req.outcome.clone(),
                verifier_content_hash: req.verifier_content_hash,
                notes:                 req.notes,
                verifier_receipt_id:   req.verifier_receipt_id,
            })
            .await
        {
            Ok(r) => r,
            Err(ResearchDbError::SelfVerification(_)) => {
                return Err(VerificationError::SelfVerification);
            }
            Err(e) => return Err(e.into()),
        };

        info!(
            task_id,
            result_id = %req.result_id,
            verifier_id = %req.verifier_id,
            outcome = %req.outcome,
            verification_id = %record.verification_id,
            "verification record stored"
        );

        // ── 6. Quorum check — only for 'reproduced' outcomes ─────────────────
        //
        // Non-reproduced verifications are recorded for audit but do not advance
        // the quorum counter.  A future change set may introduce dispute
        // resolution for results with many 'rejected' verifications.
        if req.outcome != "reproduced" {
            return Ok(VerifyResponse {
                verification_id: record.verification_id,
                reproduced_count: 0,
                quorum_required:  0,
                quorum_reached:   false,
                status:           "submitted".to_owned(),
            });
        }

        let reproduced_count = self
            .db
            .count_reproduced_verifications(req.result_id)
            .await?;

        let task = self
            .db
            .get_task(&result.task_id)
            .await?
            .ok_or_else(|| VerificationError::TaskNotFound(result.task_id.clone()))?;

        let quorum = self
            .db
            .get_verification_quorum(&task.objective_id)
            .await?;

        // ── 7. Canonical acceptance when quorum met ───────────────────────────
        if reproduced_count >= quorum as u64 {
            match self
                .db
                .accept_task_canonical(task_id, req.result_id)
                .await
            {
                Ok(()) => {
                    info!(
                        task_id,
                        result_id = %req.result_id,
                        reproduced_count,
                        quorum,
                        "quorum met — result promoted to canonical"
                    );
                    Ok(VerifyResponse {
                        verification_id: record.verification_id,
                        reproduced_count,
                        quorum_required:  quorum,
                        quorum_reached:   true,
                        status:           "accepted".to_owned(),
                    })
                }
                // Idempotent: another verifier's request raced and already set
                // canonical.  Return success — quorum was still met.
                Err(ResearchDbError::CanonicalAlreadySet { .. }) => {
                    warn!(
                        task_id,
                        result_id = %req.result_id,
                        "canonical already set (race) — returning quorum_reached=true"
                    );
                    Ok(VerifyResponse {
                        verification_id: record.verification_id,
                        reproduced_count,
                        quorum_required:  quorum,
                        quorum_reached:   true,
                        status:           "accepted".to_owned(),
                    })
                }
                Err(e) => Err(e.into()),
            }
        } else {
            Ok(VerifyResponse {
                verification_id: record.verification_id,
                reproduced_count,
                quorum_required:  quorum,
                quorum_reached:   false,
                status:           "submitted".to_owned(),
            })
        }
    }
}

// ── Scheduler error bridge ────────────────────────────────────────────────────

impl From<VerificationError> for SchedulerError {
    fn from(e: VerificationError) -> Self {
        // The API layer matches on VerificationError directly for proper HTTP
        // status codes, so this bridge is a safety net for unexpected code paths.
        SchedulerError::NotFound(e.to_string())
    }
}
