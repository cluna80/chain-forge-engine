//! `VerifierAttestationGossip` — the envelope gossiped on
//! `GossipTopic::VerifierAttestation`.
//!
//! ## Change Set S — Decentralized Verifier Attestation Gossip
//!
//! Before Change Set S each node's `VerificationEngine` independently tracked
//! verifier votes. Quorum (`reproduced_count >= verification_quorum`) was
//! declared locally, so two nodes could disagree on whether a task was
//! accepted depending on which verifier submissions they happened to receive.
//! Reward eligibility was therefore non-deterministic across validators.
//!
//! Change Set S fixes this: every node that records a successful local
//! verification vote immediately gossips a `VerifierAttestationGossip` on
//! `GossipTopic::VerifierAttestation`. Every other node ingests the gossip,
//! validates the verifier signature, deduplicates by `(task_id, verifier_id)`,
//! and accumulates per-`(task_id, output_hash)` attestation counts in
//! `Node::attestation_accumulator`. When a `(task_id, output_hash)` pair
//! accumulates 2 independent attestations (controllers distinct, same output
//! hash), the receiving node calls `accept_task_canonical()` locally so every
//! node converges on the same acceptance decision at quorum time.
//!
//! ## Anti-replay
//!
//! `Node::seen_attestation_keys` is a bounded `HashSet<String>` keyed on
//! `"{task_id}::{verifier_id}"`. Duplicate attestations from the same verifier
//! on the same task are silently dropped without touching the accumulator.
//!
//! ## Attestation content
//!
//! The verifier signs `canonical_payload(...)` — the same payload format used
//! by `VerificationEngine` (Change Set P, P2):
//! `"QCB-VERIFY-v1\x00" || chain_id \x00 task_id \x00 result_id \x00
//!  verifier_id \x00 outcome \x00 verifier_content_hash \x00
//!  workload_version \x00 submission_nonce`
//!
//! The gossip envelope carries the signature so receiving nodes can verify it
//! against the registered verifier public key even without the original HTTP
//! request context.
//!
//! ## Quorum
//!
//! Quorum = 2 independent attestations with:
//! - Same `(task_id, output_hash)` (consensus on correctness)
//! - Distinct `controller_id` values (anti-Sybil — Change Set P, P3)
//!
//! The `controller_id` is looked up from the local `VerifierRegistry` if one
//! is attached; if not (legacy mode), only same-`verifier_id` dedup is applied
//! and the controller uniqueness check is skipped.

use serde::{Deserialize, Serialize};

/// Envelope published on `GossipTopic::VerifierAttestation`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifierAttestationGossip {
    /// The chain this attestation was issued on. Receiving nodes MUST reject
    /// messages whose `chain_id` differs from their own genesis chain_id.
    pub chain_id: String,

    /// Task that was verified.
    pub task_id: String,

    /// The specific result being attested. Used to look up the miner for
    /// miner-verifier overlap checks (Change Set P, P3).
    pub result_id: String,

    /// The verifier that produced this attestation.
    pub verifier_id: String,

    /// The controller identity behind the verifier. Carried in the gossip
    /// envelope so receiving nodes can apply the controller-uniqueness check
    /// without a round-trip to the verifier registry API.
    pub controller_id: String,

    /// SHA-256 of the task output that the verifier reproduced (hex).
    /// Attestations on the same task but with a different `output_hash` are
    /// counted separately — they do not contribute to each other's quorum.
    pub output_hash: String,

    /// Outcome string — always `"reproduced"` for attestations that count
    /// toward quorum. `"failed"` attestations are gossiped for audit purposes
    /// but are never counted toward acceptance.
    pub outcome: String,

    /// Workload version string from the original `VerifyRequest`. Carried
    /// through for audit; not used in quorum logic.
    pub workload_version: String,

    /// Submission nonce from the original `VerifyRequest`. Carried through for
    /// replay protection at the HTTP layer; the gossip layer deduplicates by
    /// `(task_id, verifier_id)` instead.
    pub submission_nonce: String,

    /// The verifier's ML-DSA-65 signature over the canonical payload (hex).
    /// Receiving nodes verify this against the public key in the verifier
    /// registry before counting the attestation.
    pub signature: String,

    /// Millisecond UTC timestamp when this gossip was first published.
    /// Used for staleness filtering.
    pub published_at_ms: u64,
}

/// Gossip messages older than this are silently dropped.
pub const ATTESTATION_GOSSIP_MAX_AGE_MS: u64 = 10 * 60 * 1_000; // 10 minutes

/// How many `(task_id, verifier_id)` keys we track in the anti-replay set
/// before evicting the oldest entries (LRU-style cap).
pub const MAX_SEEN_ATTESTATION_KEYS: usize = 50_000;

/// Number of independent reproductions required for a task to become
/// reward-eligible. Must match `VerificationEngine::verification_quorum`.
pub const ATTESTATION_QUORUM: usize = 2;

impl VerifierAttestationGossip {
    /// Encode to JSON bytes for `OutboundMessage::payload`.
    pub fn to_payload(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Decode from `GossipMessage::payload`.
    pub fn from_payload(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }

    /// True if this message is too old to be useful.
    pub fn is_stale(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.published_at_ms) > ATTESTATION_GOSSIP_MAX_AGE_MS
    }

    /// True if this attestation counts toward acceptance quorum.
    /// Only `"reproduced"` outcomes contribute; `"failed"` are gossiped for
    /// audit but never trigger acceptance.
    pub fn counts_toward_quorum(&self) -> bool {
        self.outcome == "reproduced"
    }

    /// The canonical anti-replay key: `"{task_id}::{verifier_id}"`.
    pub fn replay_key(&self) -> String {
        format!("{}::{}", self.task_id, self.verifier_id)
    }

    /// The canonical quorum accumulator key: `"{task_id}::{output_hash}"`.
    pub fn quorum_key(&self) -> String {
        format!("{}::{}", self.task_id, self.output_hash)
    }

    /// Build the canonical signed payload for signature verification.
    ///
    /// Format matches `VerificationEngine::canonical_verify_payload()` in
    /// Change Set P so existing ML-DSA-65 signatures are valid here without
    /// re-signing.
    ///
    /// `"QCB-VERIFY-v1\x00" || chain_id \x00 task_id \x00 result_id \x00
    ///  verifier_id \x00 outcome \x00 verifier_content_hash \x00
    ///  workload_version \x00 submission_nonce`
    pub fn canonical_payload(&self, verifier_content_hash: &str) -> Vec<u8> {
        let mut buf = b"QCB-VERIFY-v1\x00".to_vec();
        for part in &[
            self.chain_id.as_str(),
            self.task_id.as_str(),
            self.result_id.as_str(),
            self.verifier_id.as_str(),
            self.outcome.as_str(),
            verifier_content_hash,
            self.workload_version.as_str(),
            self.submission_nonce.as_str(),
        ] {
            buf.extend_from_slice(part.as_bytes());
            buf.push(0x00);
        }
        buf
    }
}

/// Accumulated per-`(task_id, output_hash)` controller set.
/// When `controllers.len() >= ATTESTATION_QUORUM` the task is ready for
/// canonical acceptance. The `HashSet` dedups controllers so Sybil
/// attestations from the same controller don't inflate the count.
#[derive(Debug, Default, Clone)]
pub struct AttestationBucket {
    /// All distinct controller_ids that have reproduced this output.
    pub controllers: std::collections::HashSet<String>,
    /// One result_id per attestation (the most recently seen); used to
    /// call `accept_task_canonical(result_id, ...)`.
    pub latest_result_id: String,
}

impl AttestationBucket {
    /// Record a controller attestation. Returns `true` if this was a new
    /// controller (i.e. the bucket changed).
    pub fn record(&mut self, controller_id: &str, result_id: &str) -> bool {
        let new = self.controllers.insert(controller_id.to_string());
        if new {
            self.latest_result_id = result_id.to_string();
        }
        new
    }

    /// True when this bucket has reached the required quorum.
    pub fn has_quorum(&self) -> bool {
        self.controllers.len() >= ATTESTATION_QUORUM
    }
}
