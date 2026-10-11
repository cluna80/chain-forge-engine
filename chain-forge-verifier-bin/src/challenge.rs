//! Independent hash re-derivation for PoCD and avalanche results.
//!
//! Given a result row fetched from the scheduler, re-derives the expected
//! `content_hash` from the result payload without trusting the stored value.
//!
//! This implements the same derivation as `chain-forge-miner/src/challenge.rs`
//! so the two computations must produce identical hashes for any valid result.
//!
//! ## Scientific integrity note
//!
//! A matching `content_hash` means only that the verifier independently ran
//! the same deterministic function and obtained the same output.  It does NOT
//! classify the underlying research result as a cryptographic breakthrough,
//! anomaly, or discovery.  Scientific interpretation is left to human
//! researchers and the chain's governance processes.

use sha2::{Digest, Sha256};

use crate::client::SubmittedResult;

// ── Public re-derivation entry point ─────────────────────────────────────────

/// Re-derive the `content_hash` for a submitted result.
///
/// Dispatches to the appropriate algorithm based on the `task_kind` field
/// in the result row (set when the scheduler joins the result with its task).
///
/// Returns:
/// - `Ok(hash_hex)` — re-derived hash; caller compares to `result.content_hash`.
/// - `Err(msg)`     — payload is missing required fields; caller records
///                    `"inconclusive"` rather than `"rejected"`.
pub fn rederive_content_hash(
    result:       &SubmittedResult,
    objective_id: &str,
) -> Result<String, String> {
    match result.task_kind.as_str() {
        "pocd_phase1" => rederive_phase1(result),
        "pocd_phase2" => rederive_phase2(result),
        "avalanche_experiment" | "avalanche_replication" => {
            rederive_avalanche(result, objective_id)
        }
        other => Err(format!("unknown task_kind: {other}")),
    }
}

// ── Phase-1 re-derivation ─────────────────────────────────────────────────────
//
// Original miner:
//   H1 = SHA-256(seed_le64 || nonce_le64)  — must have ≥ 16 leading zero bits
//   content_hash = SHA-256(H1)
//
// The nonce and seed are both in the result payload.

fn rederive_phase1(result: &SubmittedResult) -> Result<String, String> {
    let nonce = payload_i64(&result.result_payload, "nonce")?;
    let seed  = payload_i64(&result.result_payload, "input_seed")?;

    let seed_bytes  = seed.to_le_bytes();
    let nonce_bytes = nonce.to_le_bytes();

    let mut h = Sha256::new();
    h.update(seed_bytes);
    h.update(nonce_bytes);
    let h1_bytes = h.finalize();

    // content_hash = SHA-256(H1)
    let mut h2 = Sha256::new();
    h2.update(&h1_bytes);
    Ok(hex::encode(h2.finalize()))
}

// ── Phase-2 re-derivation ─────────────────────────────────────────────────────
//
// Original miner:
//   H1_bytes = hex::decode(task.parent_hash)
//   H2 = SHA-256(H1_bytes || nonce_le64)  — must have ≥ 8 leading zero bits
//   content_hash = SHA-256(H1_bytes || H2_bytes)
//
// The winning_hash in the payload is H2, and the parent_hash is H1.
// Both are available in the result row: parent_hash comes from the task join,
// nonce comes from the payload.

fn rederive_phase2(result: &SubmittedResult) -> Result<String, String> {
    let nonce = payload_i64(&result.result_payload, "nonce")?;

    // parent_hash is H1 (hex), joined from the task row by the scheduler
    let parent_hash_hex = result
        .parent_hash
        .as_deref()
        .ok_or_else(|| "phase-2 result missing parent_hash".to_string())?;

    let h1_bytes = hex::decode(parent_hash_hex)
        .map_err(|e| format!("parent_hash decode error: {e}"))?;

    let nonce_bytes = nonce.to_le_bytes();

    // H2 = SHA-256(H1 || nonce)
    let mut h = Sha256::new();
    h.update(&h1_bytes);
    h.update(nonce_bytes);
    let h2_bytes = h.finalize();

    // content_hash = SHA-256(H1 || H2)
    let mut h3 = Sha256::new();
    h3.update(&h1_bytes);
    h3.update(&h2_bytes);
    Ok(hex::encode(h3.finalize()))
}

// ── Avalanche re-derivation ───────────────────────────────────────────────────
//
// Original miner (deterministic — no nonce search):
//   canonical_seed = SHA-256("qcb-avalanche-v1" || objective_id_utf8 || seed_index_le64)
//   original_hash  = SHA-256(canonical_seed)
//   flipped_seed   = canonical_seed with bit `bit_index` flipped
//                    (byte = bit_index/8, shift = 7 - (bit_index%8), MSB-first)
//   flipped_hash   = SHA-256(flipped_seed)
//   content_hash   = SHA-256(original_hash || flipped_hash)

fn rederive_avalanche(result: &SubmittedResult, objective_id: &str) -> Result<String, String> {
    let seed_index = payload_u32(&result.result_payload, "seed_index")?;
    let bit_index  = payload_u32(&result.result_payload, "bit_index")?;

    if bit_index >= 256 {
        return Err(format!("bit_index {bit_index} out of range 0..255"));
    }

    // ── Canonical seed ────────────────────────────────────────────────────────
    let canonical_seed: [u8; 32] = derive_avalanche_seed(objective_id, seed_index);

    // ── Original hash ─────────────────────────────────────────────────────────
    let mut h = Sha256::new();
    h.update(&canonical_seed);
    let original_bytes: [u8; 32] = h.finalize().into();

    // ── Flipped seed ──────────────────────────────────────────────────────────
    let mut flipped_seed = canonical_seed;
    let byte_idx  = (bit_index / 8) as usize;
    let bit_shift = 7 - (bit_index % 8); // MSB-first: bit 7 is the high bit of byte 0
    flipped_seed[byte_idx] ^= 1u8 << bit_shift;

    // ── Flipped hash ──────────────────────────────────────────────────────────
    let mut h2 = Sha256::new();
    h2.update(&flipped_seed);
    let flipped_bytes: [u8; 32] = h2.finalize().into();

    // ── content_hash = SHA-256(original || flipped) ───────────────────────────
    let mut h3 = Sha256::new();
    h3.update(&original_bytes);
    h3.update(&flipped_bytes);
    Ok(hex::encode(h3.finalize()))
}

// ── Seed derivation (matches chain-forge-miner) ───────────────────────────────

fn derive_avalanche_seed(objective_id: &str, seed_index: u32) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"qcb-avalanche-v1");
    h.update(objective_id.as_bytes());
    h.update((seed_index as u64).to_le_bytes());
    h.finalize().into()
}

// ── Payload helpers ───────────────────────────────────────────────────────────

fn payload_i64(payload: &serde_json::Value, key: &str) -> Result<i64, String> {
    payload
        .get(key)
        .and_then(|v| v.as_i64())
        .ok_or_else(|| format!("result_payload missing or non-integer field '{key}'"))
}

fn payload_u32(payload: &serde_json::Value, key: &str) -> Result<u32, String> {
    payload
        .get(key)
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)
        .ok_or_else(|| format!("result_payload missing or non-integer field '{key}'"))
}
