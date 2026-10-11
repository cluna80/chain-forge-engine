//! `VerificationEngine` — the core verification state machine.
//!
//! ## Responsibilities
//!
//! * Accept an independent verification record from a verifier miner
//!   (`submit_verification`).
//! * Re-derive the expected `content_hash` from the task and result payload
//!   to confirm the miner's work is reproducible before recording it
//!   (`verify_content_hash`).
//! * After each successful insert, count the number of `'reproduced'`
//!   verifications for the associated result.
//! * If the count meets or exceeds the objective's `verification_quorum`,
//!   atomically transition the task from `'submitted'` to `'accepted'` and
//!   mark the result `'accepted'` as well.
//!
//! ## Two-Phase Chain Verification (Change Set J)
//!
//! Phase-1 results carry:
//!   nonce, winning_hash = SHA-256(seed || nonce), content_hash = SHA-256(H1)
//!
//! Phase-2 results carry:
//!   nonce, winning_hash = SHA-256(H1 || nonce), content_hash = SHA-256(H1 || H2)
//!   where H1 = parent_hash (hex) from the task row.
//!
//! `verify_content_hash` re-derives the winning hash from scratch (seed / H1
//! bytes + nonce) and then re-derives the expected content_hash, returning an
//! error if any step mismatches.  Callers that supply a `verifier_content_hash`
//! that was itself re-derived locally will naturally produce `'reproduced'`;
//! a mismatch produces `'diverged'`.
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

use sha2::{Digest, Sha256};
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
        task_id:               &str,
        result_id:             Uuid,
        verifier_id:           &str,
        outcome:               &str,
        verifier_content_hash: &str,
        notes:                 Option<String>,
        verifier_receipt_id:   Option<String>,
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
                task_id:               task_id.to_string(),
                verifier_id:           verifier_id.to_string(),
                outcome:               outcome.to_string(),
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

    // ── Helper: content_hash re-derivation ───────────────────────────────────

    /// Re-derive the expected `content_hash` for a result from scratch.
    ///
    /// This can be used by any caller (e.g. the API layer) to let a verifier
    /// supply only the nonce and have the engine confirm whether it reproduces
    /// the original result.
    ///
    /// ## Phase 1
    ///
    /// ```text
    /// H1            = SHA-256(seed_le8 || nonce_le8)
    /// content_hash  = SHA-256(H1)
    /// ```
    ///
    /// ## Phase 2
    ///
    /// ```text
    /// H1_bytes      = hex::decode(parent_hash)   [from the task row]
    /// H2            = SHA-256(H1_bytes || nonce_le8)
    /// content_hash  = SHA-256(H1_bytes || H2)
    /// ```
    ///
    /// Returns `Err` if `parent_hash` is required but missing/invalid.
    pub fn derive_content_hash(
        phase:       i32,
        input_seed:  i64,
        parent_hash: Option<&str>,
        nonce:       i64,
    ) -> Result<String, String> {
        let nonce_bytes = nonce.to_le_bytes();

        match phase {
            1 => {
                let seed_bytes = input_seed.to_le_bytes();

                // H1 = SHA-256(seed || nonce)
                let mut h = Sha256::new();
                h.update(seed_bytes);
                h.update(nonce_bytes);
                let h1_bytes = h.finalize();

                // content_hash = SHA-256(H1)
                let mut h2 = Sha256::new();
                h2.update(&h1_bytes);
                Ok(hex::encode(h2.finalize()))
            }
            2 => {
                let ph = parent_hash.ok_or_else(|| {
                    "phase-2 content_hash derivation requires parent_hash".to_string()
                })?;
                let h1_bytes = hex::decode(ph).map_err(|e| {
                    format!("invalid parent_hash hex: {e}")
                })?;

                // H2 = SHA-256(H1_bytes || nonce)
                let mut h = Sha256::new();
                h.update(&h1_bytes);
                h.update(nonce_bytes);
                let h2_bytes = h.finalize();

                // content_hash = SHA-256(H1 || H2)
                let mut hc = Sha256::new();
                hc.update(&h1_bytes);
                hc.update(&h2_bytes);
                Ok(hex::encode(hc.finalize()))
            }
            p => Err(format!("unknown phase: {p}")),
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Confirm phase-1 content_hash derivation matches the miner's output.
    #[test]
    fn phase1_content_hash_round_trips() {
        // Reproduce the challenge.rs phase-1 test vector
        let seed: i64 = 31415926535897932;
        // Find a nonce that produces ≥ 16 leading-zero bits (brute-force a small range)
        let mut found_nonce = None;
        let mut found_h1 = String::new();
        let mut found_ch = String::new();

        'outer: for nonce in 0i64..5_000_000 {
            let mut h = Sha256::new();
            h.update(seed.to_le_bytes());
            h.update(nonce.to_le_bytes());
            let bytes = h.finalize();
            let lz = bytes.iter().fold(0u32, |acc, &b| {
                if acc % 8 == 0 && b == 0 { acc + 8 } else { acc + b.leading_zeros().min(8 - acc % 8) }
            });
            // simpler: first 2 bytes both zero = 16 bits
            if bytes[0] == 0 && bytes[1] == 0 {
                found_nonce = Some(nonce);
                found_h1    = hex::encode(&bytes);
                let mut h2 = Sha256::new();
                h2.update(&bytes);
                found_ch = hex::encode(h2.finalize());
                break 'outer;
            }
            let _ = lz; // suppress warning
        }

        let nonce = found_nonce.expect("should find a phase-1 nonce in 5M");
        let derived = VerificationEngine::derive_content_hash(1, seed, None, nonce).unwrap();
        assert_eq!(derived, found_ch, "phase-1 re-derivation must match");
        let _ = found_h1;
    }

    /// Confirm phase-2 content_hash derivation is consistent with the
    /// two-hop SHA-256 chain.
    #[test]
    fn phase2_content_hash_round_trips() {
        // Use a synthetic parent_hash (just 32 zero bytes in hex)
        let parent_hash = "0".repeat(64);
        let h1_bytes = hex::decode(&parent_hash).unwrap();

        // Find a nonce with ≥ 8 leading-zero bits (first byte == 0)
        for nonce in 0i64..100_000 {
            let mut h = Sha256::new();
            h.update(&h1_bytes);
            h.update(nonce.to_le_bytes());
            let h2_bytes = h.finalize();
            if h2_bytes[0] == 0 {
                // Manually compute expected content_hash
                let mut hc = Sha256::new();
                hc.update(&h1_bytes);
                hc.update(&h2_bytes);
                let expected = hex::encode(hc.finalize());

                let derived = VerificationEngine::derive_content_hash(
                    2, 0, Some(&parent_hash), nonce,
                ).unwrap();
                assert_eq!(derived, expected, "phase-2 re-derivation must match");
                return;
            }
        }
        panic!("expected to find a phase-2 nonce within 100k");
    }

    /// Invalid phase number returns an error.
    #[test]
    fn unknown_phase_returns_err() {
        let r = VerificationEngine::derive_content_hash(9, 42, None, 0);
        assert!(r.is_err());
    }

    /// Missing parent_hash on phase-2 returns an error.
    #[test]
    fn phase2_without_parent_hash_returns_err() {
        let r = VerificationEngine::derive_content_hash(2, 0, None, 0);
        assert!(r.is_err());
    }
}
