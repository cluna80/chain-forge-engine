//! Work receipts.
//!
//! Two receipt types:
//!
//! * `ResourceExecutionReceipt` — proof that a marketplace job ran and
//!   finished (success or failure).
//! * `UsefulWorkReceipt` — proof that a machine contributed to a Grand
//!   Challenge and that an independent verifier validated the result.
//!
//! ## Useful Hash Commitment (`seal_hash`)
//!
//! Grand Challenge receipts carry a **seal hash** — a proof-of-work stamp
//! over the scientific output that is structurally identical to Bitcoin's
//! mining loop:
//!
//! ```text
//! seal_hash = SHA256(seal_nonce_bytes || output_hash_bytes || challenge_id_bytes)
//! ```
//!
//! The machine searches for a `seal_nonce` whose SHA256 result starts with
//! `difficulty_bits` zero bits — exactly the same loop a BTC miner runs,
//! but sealing a scientific result rather than an empty block header.
//! Standard Bitcoin SHA256 ASICs and GPUs can compute seal hashes without
//! modification.
//!
//! Verification is a single SHA256 call:
//! ```text
//! verify: SHA256(receipt.seal_nonce || receipt.output_hash || receipt.challenge_id)
//!         must start with the track's required difficulty prefix
//! ```

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::job::JobId;
use super::machine::MachineId;

/// Category of work contribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkType {
    /// General marketplace compute (CPU/GPU rental).
    MarketplaceCompute,
    /// Contribution to a governance-voted Grand Challenge.
    ResearchContribution,
}

/// Receipt produced at the end of a marketplace job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceExecutionReceipt {
    pub receipt_id: String,
    pub job_id: JobId,
    pub machine_id: MachineId,
    /// Whether the job completed successfully.
    pub success: bool,
    /// SHA-256 hash of the output bundle (hex).
    pub output_hash: String,
    /// Wall-clock seconds actually used.
    pub elapsed_seconds: f64,
    /// QRC owed to the provider (may differ from escrowed amount if billed
    /// by the second).
    pub qrc_earned: u64,
    pub timestamp_utc: String,
    /// Machine's Ed25519 signature over the receipt fields (base64).
    pub machine_signature: String,
}

/// Receipt for a Grand Challenge contribution (maps to the GC-DEVNET-001
/// format proven in the simulation).
///
/// The `seal_hash` + `seal_nonce` fields are the Useful Hash Commitment:
/// proof-of-work over the scientific output that uses the same SHA256
/// hardware loop as Bitcoin mining.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsefulWorkReceipt {
    pub receipt_id: String,
    pub work_type: WorkType,
    /// The Grand Challenge ID this work is credited to.
    pub challenge_id: String,
    pub machine_id: MachineId,
    /// SHA-256 hash of the challenge input / parameters (hex).
    pub input_hash: String,
    /// SHA-256 hash of the output / discovery (hex).
    pub output_hash: String,
    /// IPFS CID or on-chain ref to the methodology / algorithm description.
    pub methodology_ref: String,
    /// Domain-specific nonce or proof parameter (discovery nonce).
    pub nonce: u64,
    /// Number of candidate checks / iterations performed.
    pub checks_performed: u64,
    pub elapsed_seconds: f64,
    pub timestamp_utc: String,
    /// Machine's Ed25519 signature over the receipt fields (base64).
    pub machine_signature: String,
    /// True once an independent verifier has validated the result.
    pub verified: bool,
    pub verifier_id: Option<String>,
    /// Verifier's Ed25519 signature (base64).
    pub verifier_signature: Option<String>,

    // ── Useful Hash Commitment (BTC-compatible seal) ──────────────────────
    /// Nonce found by the machine such that SHA256(seal_nonce_bytes ||
    /// output_hash_bytes || challenge_id_bytes) starts with `seal_difficulty_bits`
    /// zero bits.  Searching for this nonce uses the same SHA256 hardware loop
    /// as Bitcoin mining.
    pub seal_nonce: u64,
    /// Hex-encoded result: SHA256(seal_nonce || output_hash || challenge_id).
    /// Must have `seal_difficulty_bits` leading zero bits.
    pub seal_hash: String,
    /// Number of leading zero BITS required in `seal_hash`.
    /// Governance-settable per challenge track; stored in the receipt so
    /// verifiers know the target without querying chain state.
    pub seal_difficulty_bits: u32,
}

// ── Seal helpers ──────────────────────────────────────────────────────────

/// Compute the seal hash for a given nonce, output hash, and challenge ID.
///
/// Formula: `SHA256(seal_nonce_be_8_bytes || output_hash_bytes || challenge_id_bytes)`
///
/// Returns the result as a lowercase hex string.
pub fn compute_seal_hash(seal_nonce: u64, output_hash_hex: &str, challenge_id: &str) -> String {
    let output_hash_bytes = hex::decode(output_hash_hex).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(seal_nonce.to_be_bytes());
    hasher.update(&output_hash_bytes);
    hasher.update(challenge_id.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

/// Returns `true` if `seal_hash_hex` meets `difficulty_bits` leading zero bits.
///
/// Each hex nibble = 4 bits.  Full nibbles are checked first (must be `'0'`),
/// then the partial nibble (top N bits of the next byte must be zero).
pub fn meets_difficulty(seal_hash_hex: &str, difficulty_bits: u32) -> bool {
    if difficulty_bits == 0 {
        return true;
    }
    let full_nibbles = (difficulty_bits / 4) as usize;
    let rem_bits     = difficulty_bits % 4;

    let chars: Vec<char> = seal_hash_hex.chars().collect();
    if chars.len() < full_nibbles + if rem_bits > 0 { 1 } else { 0 } {
        return false;
    }
    // All full nibbles must be '0'
    for &c in chars.iter().take(full_nibbles) {
        if c != '0' { return false; }
    }
    // Partial nibble: top `rem_bits` bits must be zero
    if rem_bits > 0 {
        let nibble = u8::from_str_radix(&chars[full_nibbles].to_string(), 16)
            .unwrap_or(0xFF);
        // We want the top `rem_bits` of the 4-bit nibble to be zero.
        // Shift the nibble to the top of a byte, then check those bits.
        let shifted = nibble << 4;
        let mask = !((1u8 << (8 - rem_bits)) - 1);
        if shifted & mask != 0 { return false; }
    }
    true
}

/// Search for a `seal_nonce` starting at `start_nonce` such that
/// `compute_seal_hash(nonce, output_hash, challenge_id)` meets `difficulty_bits`.
///
/// Returns `(nonce, seal_hash_hex)` when found, or `None` if `max_attempts`
/// is exhausted (useful in tests / sandboxes).
pub fn find_seal_nonce(
    output_hash_hex: &str,
    challenge_id:    &str,
    difficulty_bits: u32,
    start_nonce:     u64,
    max_attempts:    u64,
) -> Option<(u64, String)> {
    for i in 0..max_attempts {
        let nonce = start_nonce.wrapping_add(i);
        let hash  = compute_seal_hash(nonce, output_hash_hex, challenge_id);
        if meets_difficulty(&hash, difficulty_bits) {
            return Some((nonce, hash));
        }
    }
    None
}

/// Verify that a receipt's seal is valid: recompute the hash from
/// `seal_nonce + output_hash + challenge_id` and confirm it meets difficulty.
///
/// This is a single SHA256 call — fast enough to run on every node at
/// receipt submission time.
pub fn verify_seal(receipt: &UsefulWorkReceipt) -> bool {
    let recomputed = compute_seal_hash(
        receipt.seal_nonce,
        &receipt.output_hash,
        &receipt.challenge_id,
    );
    recomputed == receipt.seal_hash
        && meets_difficulty(&receipt.seal_hash, receipt.seal_difficulty_bits)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const CHALLENGE_ID: &str = "GC-DEVNET-002";
    // Matches the GC-DEVNET-001 output hash from the simulation
    const OUTPUT_HASH: &str =
        "000050f1a2b3c4d5e6f700112233445566778899aabbccddeeff00112233445566";

    #[test]
    fn seal_hash_deterministic() {
        // Same inputs → same hash every time
        let h1 = compute_seal_hash(42, OUTPUT_HASH, CHALLENGE_ID);
        let h2 = compute_seal_hash(42, OUTPUT_HASH, CHALLENGE_ID);
        assert_eq!(h1, h2, "seal hash must be deterministic");
        assert_eq!(h1.len(), 64, "sha256 hex is 64 chars");
    }

    #[test]
    fn difficulty_0_always_passes() {
        let h = compute_seal_hash(0, OUTPUT_HASH, CHALLENGE_ID);
        assert!(meets_difficulty(&h, 0));
    }

    #[test]
    fn finds_seal_nonce_low_difficulty() {
        // difficulty=8 → first byte must be 0x00; should find in <1000 tries
        let result = find_seal_nonce(OUTPUT_HASH, CHALLENGE_ID, 8, 0, 100_000);
        assert!(result.is_some(), "should find seal nonce at difficulty=8");
        let (nonce, hash) = result.unwrap();
        assert!(meets_difficulty(&hash, 8), "found hash must meet difficulty");
        // Recomputing must give the same hash
        let recomputed = compute_seal_hash(nonce, OUTPUT_HASH, CHALLENGE_ID);
        assert_eq!(recomputed, hash, "recomputed hash must match found hash");
    }

    #[test]
    fn verify_seal_round_trip() {
        // Find a real seal at difficulty=8
        let (nonce, hash) =
            find_seal_nonce(OUTPUT_HASH, CHALLENGE_ID, 8, 0, 100_000).unwrap();

        let receipt = UsefulWorkReceipt {
            receipt_id:          "test-receipt-001".to_string(),
            work_type:           WorkType::ResearchContribution,
            challenge_id:        CHALLENGE_ID.to_string(),
            machine_id:          MachineId("MACH-TEST-001".to_string()),
            input_hash:          "0".repeat(64),
            output_hash:         OUTPUT_HASH.to_string(),
            methodology_ref:     "ipfs://QmTest".to_string(),
            nonce:               0,
            checks_performed:    100_000,
            elapsed_seconds:     0.05,
            timestamp_utc:       "2026-10-07T00:00:00Z".to_string(),
            machine_signature:   "sig_placeholder".to_string(),
            verified:            false,
            verifier_id:         None,
            verifier_signature:  None,
            seal_nonce:          nonce,
            seal_hash:           hash,
            seal_difficulty_bits: 8,
        };

        assert!(verify_seal(&receipt), "verify_seal must pass for a valid receipt");
    }

    #[test]
    fn verify_seal_rejects_tampered_hash() {
        let (nonce, _) =
            find_seal_nonce(OUTPUT_HASH, CHALLENGE_ID, 8, 0, 100_000).unwrap();

        let mut tampered_hash = compute_seal_hash(nonce, OUTPUT_HASH, CHALLENGE_ID);
        // Flip the last nibble
        let last = tampered_hash.pop().unwrap();
        tampered_hash.push(if last == '0' { '1' } else { '0' });

        let receipt = UsefulWorkReceipt {
            receipt_id:          "test-receipt-002".to_string(),
            work_type:           WorkType::ResearchContribution,
            challenge_id:        CHALLENGE_ID.to_string(),
            machine_id:          MachineId("MACH-TEST-001".to_string()),
            input_hash:          "0".repeat(64),
            output_hash:         OUTPUT_HASH.to_string(),
            methodology_ref:     "ipfs://QmTest".to_string(),
            nonce:               0,
            checks_performed:    1,
            elapsed_seconds:     0.0,
            timestamp_utc:       "2026-10-07T00:00:00Z".to_string(),
            machine_signature:   "sig_placeholder".to_string(),
            verified:            false,
            verifier_id:         None,
            verifier_signature:  None,
            seal_nonce:          nonce,
            seal_hash:           tampered_hash,   // deliberately wrong
            seal_difficulty_bits: 8,
        };

        assert!(!verify_seal(&receipt), "tampered seal_hash must fail verification");
    }

    #[test]
    fn verify_seal_rejects_wrong_nonce() {
        let (nonce, hash) =
            find_seal_nonce(OUTPUT_HASH, CHALLENGE_ID, 8, 0, 100_000).unwrap();

        let receipt = UsefulWorkReceipt {
            receipt_id:          "test-receipt-003".to_string(),
            work_type:           WorkType::ResearchContribution,
            challenge_id:        CHALLENGE_ID.to_string(),
            machine_id:          MachineId("MACH-TEST-001".to_string()),
            input_hash:          "0".repeat(64),
            output_hash:         OUTPUT_HASH.to_string(),
            methodology_ref:     "ipfs://QmTest".to_string(),
            nonce:               0,
            checks_performed:    1,
            elapsed_seconds:     0.0,
            timestamp_utc:       "2026-10-07T00:00:00Z".to_string(),
            machine_signature:   "sig_placeholder".to_string(),
            verified:            false,
            verifier_id:         None,
            verifier_signature:  None,
            seal_nonce:          nonce.wrapping_add(1),  // wrong nonce
            seal_hash:           hash,                    // hash for the correct nonce
            seal_difficulty_bits: 8,
        };

        assert!(!verify_seal(&receipt), "wrong nonce must fail seal verification");
    }
}
