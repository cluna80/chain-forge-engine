//! `DiscoveryWorker` and `DiscoveryVerifier` — the two active participants in
//! the PoCD protocol.
//!
//! ## Worker
//! A `DiscoveryWorker` is a trait that any machine can implement to:
//!   1. Fetch an active challenge from the chain (out of scope for this crate —
//!      handled by the chain's P2P layer).
//!   2. Perform the domain-specific computation.
//!   3. Build a `DiscoveryProof` (including finding the seal nonce).
//!   4. Submit the proof to the chain.
//!
//! ## Verifier
//! A `DiscoveryVerifier` is a chain-side component that:
//!   1. Receives a submitted `DiscoveryProof`.
//!   2. Checks the seal (deterministic SHA256; can be done without domain
//!      knowledge).
//!   3. Checks the scientific result (domain-specific; delegated to the
//!      challenge's `verification_criteria`).
//!   4. Optionally verifies identity.
//!   5. On success, produces a `DiscoveryReceipt` and inserts it into the
//!      `DiscoveryRegistry`.

use crate::error::PoCDError;
use crate::types::challenge::DiscoveryChallenge;
use crate::types::config::PoCDConfig;
use crate::types::proof::DiscoveryProof;
use crate::types::receipt::DiscoveryReceipt;

// ── Worker ────────────────────────────────────────────────────────────────

/// A machine that performs PoCD mining work.
///
/// Implementors supply `run_challenge` which encapsulates the domain-specific
/// computation loop.  The scaffolding in this crate handles seal finding and
/// proof construction.
///
/// # Example usage
/// ```rust,ignore
/// struct MyCryptoWorker;
///
/// impl DiscoveryWorker for MyCryptoWorker {
///     fn run_challenge(&self, challenge: &DiscoveryChallenge, config: &PoCDConfig)
///     -> Result<WorkResult, PoCDError> {
///         // ... compute ...
///         Ok(WorkResult { output_hash: "deadbeef…".into(), discovery_nonce: 42,
///                         checks_performed: 1_000_000, elapsed_seconds: 3.7,
///                         input_hash: "…".into(), methodology_ref: "ipfs://…".into() })
///     }
/// }
/// ```
pub trait DiscoveryWorker: Send + Sync {
    /// Perform the domain-specific computation for `challenge` under `config`.
    ///
    /// Returns a `WorkResult` describing the output.  The caller will then
    /// find a seal nonce and build the full `DiscoveryProof`.
    fn run_challenge(
        &self,
        challenge: &DiscoveryChallenge,
        config: &PoCDConfig,
    ) -> Result<WorkResult, PoCDError>;

    /// Machine ID as known to this chain.
    fn machine_id(&self) -> &str;

    /// Sign a serialized payload with the machine's Ed25519 key.
    /// Returns a base64-encoded signature.
    fn sign(&self, payload: &[u8]) -> Result<String, PoCDError>;
}

/// Result of a worker's computation on a challenge — the raw output before
/// the seal is found and the proof is packaged.
#[derive(Debug, Clone)]
pub struct WorkResult {
    /// SHA-256 hex of the raw output / discovered value.
    pub output_hash: String,

    /// Domain-specific nonce or found candidate value.
    pub discovery_nonce: u64,

    /// Number of candidates checked.
    pub checks_performed: u64,

    /// Wall-clock seconds spent.
    pub elapsed_seconds: f64,

    /// SHA-256 hex of the input / parameter bundle.
    pub input_hash: String,

    /// Content-addressable reference to the methodology description.
    pub methodology_ref: String,
}

// ── Verifier ──────────────────────────────────────────────────────────────

/// Outcome of verifying a proof's scientific result.
#[derive(Debug, Clone)]
pub enum VerificationOutcome {
    /// The result is correct according to the challenge's criteria.
    Accepted,
    /// The result is technically valid (seal ok) but scientifically wrong.
    Rejected { reason: String },
    /// Verification could not be completed (e.g. external oracle unavailable).
    Inconclusive { reason: String },
}

/// A chain-side component that validates submitted proofs and issues receipts.
///
/// Implementors handle the domain-specific part of `verify_result`; this
/// crate's internals check the seal and enforce chain-level rules
/// (cross-chain guard, difficulty floor, deduplication).
///
/// The `verify_and_issue` method orchestrates the full pipeline:
///
/// ```text
/// verify_and_issue(proof, at_block, registry)
///   ├─ proof.verify_seal()           ← generic (SHA256, in this crate)
///   ├─ dedup check (registry)        ← generic
///   ├─ challenge active? (registry)  ← generic
///   ├─ difficulty floor (config)     ← generic
///   ├─ verify_result(proof, ch)      ← IMPLEMENTOR (domain-specific)
///   ├─ verify_identity(machine_id)   ← IMPLEMENTOR (if require_verified_identity)
///   └─ build + return DiscoveryReceipt
/// ```
pub trait DiscoveryVerifier: Send + Sync {
    /// Verifier's own ID (node or service identifier).
    fn verifier_id(&self) -> &str;

    /// Sign a serialized payload with the verifier's Ed25519 key.
    /// Returns a base64-encoded signature.
    fn sign(&self, payload: &[u8]) -> Result<String, PoCDError>;

    /// Domain-specific result check.
    ///
    /// Called after the seal has passed and the challenge is known to be
    /// active.  Implementors may call an external oracle, re-run the
    /// computation, or apply a known-answer check.
    fn verify_result(
        &self,
        proof: &DiscoveryProof,
        challenge: &DiscoveryChallenge,
    ) -> Result<VerificationOutcome, PoCDError>;

    /// Optional identity check.
    ///
    /// Called when `config.require_verified_identity == true`.
    /// Return `Ok(())` to approve; return `Err(PoCDError::IdentityRequired)`
    /// or another variant to reject.
    ///
    /// The default implementation always approves; override when your chain
    /// has on-chain identity.
    fn verify_identity(&self, _machine_id: &str) -> Result<(), PoCDError> {
        Ok(())
    }
}

// ── Proof builder helper ──────────────────────────────────────────────────

/// Build a `DiscoveryProof` from a `WorkResult` by finding the seal nonce.
///
/// `max_seal_attempts` caps the search; pass `u64::MAX` in production.
/// Returns `None` when no nonce is found within the attempt limit.
pub fn build_proof(
    proof_id: impl Into<String>,
    challenge:        &DiscoveryChallenge,
    machine_id:       impl Into<String>,
    result:           WorkResult,
    timestamp_utc:    impl Into<String>,
    machine_signature: impl Into<String>,
    max_seal_attempts: u64,
) -> Option<DiscoveryProof> {
    use crate::types::proof::find_seal_nonce;

    let (seal_nonce, seal_hash) = find_seal_nonce(
        &result.output_hash,
        &challenge.challenge_id,
        challenge.seal_difficulty_bits,
        0,
        max_seal_attempts,
    )?;

    Some(DiscoveryProof {
        proof_id:          proof_id.into(),
        challenge_id:      challenge.challenge_id.clone(),
        machine_id:        machine_id.into(),
        output_hash:       result.output_hash,
        input_hash:        result.input_hash,
        methodology_ref:   result.methodology_ref,
        discovery_nonce:   result.discovery_nonce,
        checks_performed:  result.checks_performed,
        elapsed_seconds:   result.elapsed_seconds,
        timestamp_utc:     timestamp_utc.into(),
        machine_signature: machine_signature.into(),
        seal_nonce,
        seal_hash,
        seal_difficulty_bits: challenge.seal_difficulty_bits,
    })
}

/// Build a `DiscoveryReceipt` from an already-verified `DiscoveryProof`.
///
/// The `verifier_signature` should be the verifier's Ed25519 signature over
/// a canonical serialisation of the receipt fields.
pub fn build_receipt(
    receipt_id:         impl Into<String>,
    proof:              &DiscoveryProof,
    chain_id:           impl Into<String>,
    verifier_id:        impl Into<String>,
    verifier_signature: impl Into<String>,
    committed_at_block: u64,
) -> DiscoveryReceipt {
    DiscoveryReceipt {
        receipt_id:          receipt_id.into(),
        chain_id:            chain_id.into(),
        challenge_id:        proof.challenge_id.clone(),
        machine_id:          proof.machine_id.clone(),
        output_hash:         proof.output_hash.clone(),
        input_hash:          proof.input_hash.clone(),
        methodology_ref:     proof.methodology_ref.clone(),
        discovery_nonce:     proof.discovery_nonce,
        checks_performed:    proof.checks_performed,
        elapsed_seconds:     proof.elapsed_seconds,
        submitted_at:        proof.timestamp_utc.clone(),
        machine_signature:   proof.machine_signature.clone(),
        seal_nonce:          proof.seal_nonce,
        seal_hash:           proof.seal_hash.clone(),
        seal_difficulty_bits: proof.seal_difficulty_bits,
        verifier_id:         verifier_id.into(),
        verifier_signature:  verifier_signature.into(),
        committed_at_block,
        reward_distributed:  false,
        _proof_id:           proof.proof_id.clone(),
    }
}
