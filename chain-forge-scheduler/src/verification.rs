//! Change Set M — Independent Verification Engine
//! Change Set P — Authenticated PoCD Verification (P2, P3)
//!
//! ## Purpose
//!
//! Bridges the gap between a miner submitting a result (`'submitted'` status)
//! and that result becoming eligible for reward settlement (`'accepted'` status).
//!
//! Change Set P extends this engine with authenticated verifier identities
//! (via [`VerifierRegistry`]) and signed submission enforcement (P2), plus
//! controller-independence quorum checks (P3).
//!
//! ## Protocol
//!
//! 1. A verifier calls `POST /scheduler/tasks/{task_id}/verify` and supplies:
//!    - `result_id`   — the UUID of the result being reproduced or rejected
//!    - `verifier_id` — the verifier's registered identity
//!    - `outcome`     — `"reproduced"` | `"rejected"` | `"inconclusive"`
//!    - `verifier_content_hash` — the hash the verifier independently computed
//!      (must match the original for `"reproduced"`)
//!    - `signature`   — (P2) ML-DSA-65 hex signature over canonical payload
//!    - `workload_version` — (P2) version string included in signed payload
//!    - `submission_nonce` — (P2) unique nonce to prevent replay
//!    - optional `verifier_receipt_id` — PoCD `DiscoveryReceipt.receipt_id` if
//!      the verifier used the PoCD protocol to produce their own proof
//!    - optional `notes`
//!
//! 2. `VerificationEngine::record_verification()` validates and stores the record.
//!    Self-verification is rejected at the DB layer (returns `SelfVerification`).
//!    (P2) Signature is verified against the registry public key before any DB
//!    write.  (P3) Controller independence and miner-self-verify checks run
//!    before quorum is counted.
//!
//! 3. After each successful `"reproduced"` record, the engine checks whether
//!    the `count(reproduced) >= verification_quorum` for the result's objective.
//!    (P3) Quorum contributors are also validated as independent before
//!    `accept_task_canonical` is called.
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
//!
//! ## Spec constraints (verbatim — must be preserved)
//!
//! > Do not modify QCB BFT consensus, token economics, or the existing
//! > research settlement transaction format.
//! >
//! > Preserve result deduplication, lease protections, and task ownership
//! > checks.
//! >
//! > Existing two-phase PoW cascade: Preserve unchanged.

use std::sync::Arc;

use uuid::Uuid;
use tracing::{info, warn};

use chain_forge_research_db::{
    ResearchDb, ResearchDbError,
    models::NewVerificationRecord,
};

use crate::{
    error::SchedulerError,
    verifier_registry::{RegistryError, VerifierRegistry, verify_submission_signature},
};

// ── Public request / response types ──────────────────────────────────────────

/// Request body for `POST /scheduler/tasks/{task_id}/verify`.
///
/// Change Set P (P2) adds `signature`, `workload_version`, and
/// `submission_nonce` fields.  All three are required when the scheduler is
/// running with a verifier registry attached.  Legacy callers that omit them
/// will receive a `403 Forbidden` when the registry is enforcing signatures.
#[derive(Debug, serde::Deserialize)]
pub struct VerifyRequest {
    /// UUID of the result being independently verified.
    pub result_id: Uuid,

    /// Verifier's registered identity.  Must match an authorized entry in the
    /// [`VerifierRegistry`]; must not match the original miner's ID (the DB
    /// layer returns `ResearchDbError::SelfVerification` if it does).
    pub verifier_id: String,

    /// Verification outcome.
    ///
    /// - `"reproduced"` — the verifier independently computed the same hash.
    ///   Counts toward the quorum.
    /// - `"rejected"` — the verifier's result differed.  Does NOT count toward
    ///   quorum.
    /// - `"inconclusive"` — the verifier could not complete verification (e.g.
    ///   external oracle unavailable).  Recorded but not counted.
    pub outcome: String,

    /// The content hash the verifier independently computed.
    ///
    /// For `"reproduced"`, this MUST match the original result's `content_hash`.
    /// The engine enforces this and returns `HashMismatch` if it doesn't.
    pub verifier_content_hash: String,

    // ── Change Set P fields (P2) ──────────────────────────────────────────────

    /// (P2) ML-DSA-65 hex-encoded signature over the canonical signed payload:
    ///
    /// ```text
    /// "QCB-VERIFY-v1\x00" chain_id \x00 task_id \x00 result_id \x00
    /// verifier_id \x00 outcome \x00 verifier_content_hash \x00
    /// workload_version \x00 submission_nonce
    /// ```
    ///
    /// Required when the engine has an attached verifier registry.
    pub signature: Option<String>,

    /// (P2) Verifier's workload version string, included in the signed payload
    /// to bind the submission to a specific verifier binary / protocol version.
    pub workload_version: Option<String>,

    /// (P2) Unique per-submission nonce (e.g. UUID or random hex string).
    /// Included in the signed payload to prevent replay of a previous signature.
    pub submission_nonce: Option<String>,

    // ── Existing optional fields ───────────────────────────────────────────────

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

    // ── Change Set P (P2) ────────────────────────────────────────────────────

    /// Verifier is not registered in the verifier registry.
    #[error("unregistered verifier '{0}': must be registered before submitting verifications")]
    UnregisteredVerifier(String),

    /// Verifier is registered but not currently authorized.
    #[error("verifier '{0}' is not authorized (revoked or suspended)")]
    UnauthorizedVerifier(String),

    /// The signed submission fields (signature / workload_version /
    /// submission_nonce) are required when a registry is configured but were
    /// not supplied.
    #[error("signed submission required: signature, workload_version, and submission_nonce must all be provided")]
    SignatureRequired,

    /// Signature is present but fails verification against the registered key.
    #[error("invalid signature: submission signature did not verify against registered public key")]
    InvalidSignature,

    // ── Change Set P (P3) ────────────────────────────────────────────────────

    /// The quorum set contains two verifiers controlled by the same entity.
    #[error("controller independence violation: quorum contains verifiers from the same controller: {0}")]
    ControllerOverlap(String),

    /// The quorum set contains two verifiers in the same independence group.
    #[error("independence-group violation: quorum contains multiple verifiers in group '{0}'")]
    IndependenceGroupOverlap(String),

    /// A quorum verifier shares a controller with the result's original miner.
    #[error("miner-verifier independence violation: verifier '{verifier}' shares controller '{controller}' with miner")]
    MinerVerifierOverlap {
        verifier:   String,
        controller: String,
    },

    #[error("database error: {0}")]
    Db(#[from] ResearchDbError),
}

// ── Engine ────────────────────────────────────────────────────────────────────

/// Verification engine — all persistent state lives in the DB.
///
/// Change Set P adds an optional [`VerifierRegistry`].  When `Some`, the engine
/// enforces:
/// - Registered and authorized verifier identity (P1)
/// - Cryptographic signature over the canonical payload (P2)
/// - Controller-independence and miner-self-verify prohibition (P3)
///
/// When `None`, the engine falls back to the Change Set M behaviour for
/// backward compatibility (no signature check, no independence check).
///
/// Constructed once and shared via `AppState`.  Clone is cheap (Arc inside).
#[derive(Clone)]
pub struct VerificationEngine {
    db:       Arc<dyn ResearchDb>,
    /// Change Set P — optional verifier registry.  `None` = legacy mode.
    registry: Option<Arc<VerifierRegistry>>,
    /// QCB chain ID included in the signed payload.
    chain_id: String,
}

impl VerificationEngine {
    /// Create the engine in legacy mode (no registry, no signature checks).
    pub fn new(db: Arc<dyn ResearchDb>) -> Self {
        Self { db, registry: None, chain_id: "qcb-devnet".to_owned() }
    }

    /// Create the engine with an attached verifier registry (Change Set P).
    pub fn with_registry(
        db:       Arc<dyn ResearchDb>,
        registry: VerifierRegistry,
        chain_id: impl Into<String>,
    ) -> Self {
        Self {
            db,
            registry: Some(Arc::new(registry)),
            chain_id: chain_id.into(),
        }
    }

    /// Record one independent verification and, if quorum is now met, promote
    /// the result to canonical.
    ///
    /// # Errors
    ///
    /// - `ResultNotFound`          — `result_id` not in DB
    /// - `TaskNotFound`            — parent task missing
    /// - `UnknownOutcome`          — outcome string is not a known value
    /// - `HashMismatch`            — `"reproduced"` claimed but hashes differ
    /// - `SelfVerification`        — verifier is the original miner
    /// - `NotSubmitted`            — result is not in `'submitted'` status
    /// - `UnregisteredVerifier`    — (P2) verifier_id not in registry
    /// - `UnauthorizedVerifier`    — (P2) verifier revoked or suspended
    /// - `SignatureRequired`       — (P2) signature fields omitted
    /// - `InvalidSignature`        — (P2) signature verification failed
    /// - `ControllerOverlap`       — (P3) two quorum verifiers share a controller
    /// - `IndependenceGroupOverlap`— (P3) two quorum verifiers share a group
    /// - `MinerVerifierOverlap`    — (P3) verifier's controller == miner's controller
    /// - `Db`                      — unexpected DB error
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

        // ── 2. P2: Registry lookup + signature verification ──────────────────
        if let Some(ref registry) = self.registry {
            // 2a. Verify identity is registered and authorized
            registry.lookup(&req.verifier_id).map_err(|e| match e {
                RegistryError::NotRegistered(id)      => VerificationError::UnregisteredVerifier(id),
                RegistryError::NotAuthorized(id, _)   => VerificationError::UnauthorizedVerifier(id),
                other                                 => {
                    VerificationError::Db(ResearchDbError::Internal(other.to_string()))
                }
            })?;

            // 2b. Require all three signature fields
            let signature       = req.signature.as_deref().ok_or(VerificationError::SignatureRequired)?;
            let workload_version = req.workload_version.as_deref().ok_or(VerificationError::SignatureRequired)?;
            let submission_nonce = req.submission_nonce.as_deref().ok_or(VerificationError::SignatureRequired)?;

            // 2c. Verify signature over canonical payload
            verify_submission_signature(
                registry,
                &self.chain_id,
                task_id,
                &req.result_id.to_string(),
                &req.verifier_id,
                &req.outcome,
                &req.verifier_content_hash,
                workload_version,
                submission_nonce,
                signature,
            )
            .map_err(|e| match e {
                RegistryError::InvalidPoP | RegistryError::SigDecode(_) => {
                    VerificationError::InvalidSignature
                }
                RegistryError::NotRegistered(id) => VerificationError::UnregisteredVerifier(id),
                RegistryError::NotAuthorized(id, _) => VerificationError::UnauthorizedVerifier(id),
                other => VerificationError::Db(ResearchDbError::Internal(other.to_string())),
            })?;

            info!(
                verifier_id = %req.verifier_id,
                task_id,
                result_id = %req.result_id,
                "P2 signature verified"
            );
        }

        // ── 3. Load the result being verified ─────────────────────────────────
        let result = self
            .db
            .get_result(req.result_id)
            .await?
            .ok_or(VerificationError::ResultNotFound(req.result_id))?;

        // ── 4. Guard: result must be in 'submitted' status ────────────────────
        //
        // 'accepted' results already have a canonical record; 'superseded' ones
        // lost the race.  Adding verifications to either is a logic error on the
        // caller's part, not a DB error.
        if result.result_status != "submitted" {
            return Err(VerificationError::NotSubmitted(req.result_id));
        }

        // ── 5. Hash consistency check (reproduced only) ───────────────────────
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

        // ── 6. P3 (pre-insert): miner-self-verify check ──────────────────────
        //
        // The string-level self-verify guard in the DB catches verifier_id ==
        // miner_id.  The registry-level check (P3) catches the Sybil case where
        // the verifier's *controller* matches the miner's controller.
        if let Some(ref registry) = self.registry {
            // We use the verifier_id as a proxy for its controller; the registry
            // lookup retrieves the actual controller_id.
            if let Ok(vrec) = registry.lookup(&req.verifier_id) {
                // We don't have the miner's registered controller_id here (miners
                // have a separate identity model), so we check verifier_id != miner_id
                // via the registry: if verifier's controller == result's miner_id
                // string, reject.  A proper miner registry would provide the
                // controller lookup; for Phase 1, compare controller to miner_id
                // directly since miners register their own controller_id.
                if vrec.controller_id == result.miner_id {
                    return Err(VerificationError::MinerVerifierOverlap {
                        verifier:   req.verifier_id.clone(),
                        controller: vrec.controller_id,
                    });
                }
            }
        }

        // ── 7. Insert verification record (DB enforces self-verification guard) ─
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

        // ── 8. Quorum check — only for 'reproduced' outcomes ─────────────────
        //
        // Non-reproduced verifications are recorded for audit but do not advance
        // the quorum counter.
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

        // ── 9. P3: Independence check before canonical acceptance ─────────────
        //
        // If we now have enough raw "reproduced" votes, verify that the quorum
        // contributors are genuinely independent before we promote the result.
        if reproduced_count >= quorum as u64 {
            if let Some(ref registry) = self.registry {
                // Fetch the verifier IDs that have submitted "reproduced" for this result.
                let quorum_verifiers = self
                    .db
                    .list_reproduced_verifier_ids(req.result_id)
                    .await?;

                let vid_refs: Vec<&str> = quorum_verifiers.iter().map(|s| s.as_str()).collect();

                registry.check_quorum_independence(&vid_refs).map_err(|e| match e {
                    RegistryError::ControllerOverlap(ids) => {
                        VerificationError::ControllerOverlap(ids.join(", "))
                    }
                    RegistryError::IndependenceGroupOverlap(g) => {
                        VerificationError::IndependenceGroupOverlap(g)
                    }
                    RegistryError::NotRegistered(id) => {
                        VerificationError::UnregisteredVerifier(id)
                    }
                    RegistryError::NotAuthorized(id, _) => {
                        VerificationError::UnauthorizedVerifier(id)
                    }
                    other => VerificationError::Db(ResearchDbError::Internal(other.to_string())),
                })?;

                info!(
                    task_id,
                    result_id = %req.result_id,
                    quorum_verifiers = ?quorum_verifiers,
                    "P3 independence check passed"
                );
            }

            // ── 10. Canonical acceptance ──────────────────────────────────────
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

impl From<RegistryError> for VerificationError {
    fn from(e: RegistryError) -> Self {
        match e {
            RegistryError::NotRegistered(id)      => VerificationError::UnregisteredVerifier(id),
            RegistryError::NotAuthorized(id, _)   => VerificationError::UnauthorizedVerifier(id),
            RegistryError::InvalidPoP |
            RegistryError::SigDecode(_)           => VerificationError::InvalidSignature,
            RegistryError::ControllerOverlap(ids) => VerificationError::ControllerOverlap(ids.join(", ")),
            RegistryError::IndependenceGroupOverlap(g) => VerificationError::IndependenceGroupOverlap(g),
            RegistryError::MinerControllerOverlap { verifier, controller, .. } => {
                VerificationError::MinerVerifierOverlap { verifier, controller }
            }
            other => VerificationError::Db(ResearchDbError::Internal(other.to_string())),
        }
    }
}
