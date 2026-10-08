//! `DiscoveryRegistry` — in-memory ledger of active challenges and accepted receipts.
//!
//! This is the runtime state that a PoCD-enabled blockchain node maintains.
//! The chain's storage layer is responsible for persisting and restoring the
//! registry across node restarts; this crate only defines the data shape and
//! the mutating operations on it.
//!
//! ## Responsibilities
//! * Index active `DiscoveryChallenge`s by ID.
//! * Track which `proof_id`s have already been seen (deduplication).
//! * Store accepted `DiscoveryReceipt`s and mark them as reward-distributed.
//! * Answer epoch-boundary queries: "which receipts from blocks L..=R still
//!   need rewards?"

use std::collections::HashMap;

use crate::error::PoCDError;
use crate::types::challenge::{ChallengeStatus, DiscoveryChallenge};
use crate::types::receipt::DiscoveryReceipt;

/// Runtime ledger for a single PoCD-enabled blockchain.
///
/// All operations are chain-scoped; the registry does not enforce the
/// `chain_id` check itself — that is done by the `DiscoveryVerifier` before
/// insertion.
#[derive(Debug, Default)]
pub struct DiscoveryRegistry {
    /// All known challenges, keyed by `challenge_id`.
    pub challenges: HashMap<String, DiscoveryChallenge>,

    /// Accepted receipts, keyed by `receipt_id`.
    pub receipts: HashMap<String, DiscoveryReceipt>,

    /// Set of `proof_id`s already seen; prevents replay of the same proof.
    pub seen_proof_ids: std::collections::HashSet<String>,
}

impl DiscoveryRegistry {
    /// Create a new, empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    // ── Challenge management ──────────────────────────────────────────────

    /// Register a new challenge.  Returns an error if the ID already exists.
    pub fn add_challenge(&mut self, challenge: DiscoveryChallenge) -> Result<(), PoCDError> {
        if self.challenges.contains_key(&challenge.challenge_id) {
            return Err(PoCDError::Other(format!(
                "challenge already registered: {}",
                challenge.challenge_id
            )));
        }
        self.challenges.insert(challenge.challenge_id.clone(), challenge);
        Ok(())
    }

    /// Look up a challenge by ID.
    pub fn get_challenge(&self, challenge_id: &str) -> Option<&DiscoveryChallenge> {
        self.challenges.get(challenge_id)
    }

    /// Transition a challenge to `Active` at the given block height.
    ///
    /// The caller is responsible for checking governance conditions before
    /// calling this.
    pub fn activate_challenge(
        &mut self,
        challenge_id: &str,
        at_block: u64,
    ) -> Result<(), PoCDError> {
        let ch = self
            .challenges
            .get_mut(challenge_id)
            .ok_or_else(|| PoCDError::UnknownChallenge {
                challenge_id: challenge_id.to_owned(),
            })?;
        ch.status = ChallengeStatus::Active;
        ch.activated_at_block = Some(at_block);
        Ok(())
    }

    /// Close a challenge permanently.
    pub fn close_challenge(&mut self, challenge_id: &str) -> Result<(), PoCDError> {
        let ch = self
            .challenges
            .get_mut(challenge_id)
            .ok_or_else(|| PoCDError::UnknownChallenge {
                challenge_id: challenge_id.to_owned(),
            })?;
        ch.status = ChallengeStatus::Closed;
        Ok(())
    }

    /// Suspend a challenge (pause new submissions; prior receipts remain valid).
    pub fn suspend_challenge(&mut self, challenge_id: &str) -> Result<(), PoCDError> {
        let ch = self
            .challenges
            .get_mut(challenge_id)
            .ok_or_else(|| PoCDError::UnknownChallenge {
                challenge_id: challenge_id.to_owned(),
            })?;
        ch.status = ChallengeStatus::Suspended;
        Ok(())
    }

    /// Iterate over all challenges that are currently accepting submissions.
    pub fn active_challenges(&self) -> impl Iterator<Item = &DiscoveryChallenge> {
        self.challenges
            .values()
            .filter(|c| c.is_accepting_submissions())
    }

    // ── Proof deduplication ───────────────────────────────────────────────

    /// Returns `true` when the proof ID has already been processed.
    pub fn proof_seen(&self, proof_id: &str) -> bool {
        self.seen_proof_ids.contains(proof_id)
    }

    /// Mark a proof ID as seen.  Called by the verifier after accepting a proof.
    pub fn mark_proof_seen(&mut self, proof_id: impl Into<String>) {
        self.seen_proof_ids.insert(proof_id.into());
    }

    // ── Receipt management ────────────────────────────────────────────────

    /// Insert an accepted receipt.  Returns an error if the `receipt_id` is
    /// already present.
    pub fn add_receipt(&mut self, receipt: DiscoveryReceipt) -> Result<(), PoCDError> {
        if self.receipts.contains_key(&receipt.receipt_id) {
            return Err(PoCDError::DuplicateReceipt {
                receipt_id: receipt.receipt_id.clone(),
            });
        }
        self.mark_proof_seen(receipt.proof_id_ref());
        self.receipts.insert(receipt.receipt_id.clone(), receipt);
        Ok(())
    }

    /// Look up a receipt by ID.
    pub fn get_receipt(&self, receipt_id: &str) -> Option<&DiscoveryReceipt> {
        self.receipts.get(receipt_id)
    }

    /// Mark a receipt as having had its rewards distributed.
    ///
    /// Idempotent: if already marked, returns `Ok(())` without error.
    pub fn mark_reward_distributed(&mut self, receipt_id: &str) -> Result<(), PoCDError> {
        let r = self
            .receipts
            .get_mut(receipt_id)
            .ok_or_else(|| PoCDError::Other(format!("receipt not found: {receipt_id}")))?;
        r.reward_distributed = true;
        Ok(())
    }

    /// Return all receipts committed in the inclusive block range `[from, to]`
    /// that have not yet had rewards distributed.
    ///
    /// Used by `RewardPolicy::compute_rewards` at epoch boundaries.
    pub fn pending_reward_receipts(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> Vec<&DiscoveryReceipt> {
        self.receipts
            .values()
            .filter(|r| {
                !r.reward_distributed
                    && r.committed_at_block >= from_block
                    && r.committed_at_block <= to_block
            })
            .collect()
    }

    /// Iterate over all accepted receipts in the registry.
    pub fn all_receipts(&self) -> impl Iterator<Item = &DiscoveryReceipt> {
        self.receipts.values()
    }

    /// Total number of accepted receipts in the registry.
    pub fn receipt_count(&self) -> usize {
        self.receipts.len()
    }
}
