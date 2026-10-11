//! Independent local recomputation of avalanche experiments.
//!
//! The analyzer recomputes every result from `(objective_id, seed_index, bit_index)`
//! using the same deterministic algorithm that miners use.
//!
//! This is a software consistency check — it verifies that submitted hashes
//! match the canonical derivation.  It does NOT constitute independent miner
//! verification (that requires a separate machine running qcb-miner).

use sha2::{Digest, Sha256};

use crate::fetch::SettledResult;

/// A single result annotated with local recomputation output.
#[derive(Debug, Clone)]
pub struct VerifiedResult {
    /// The raw result as returned by the scheduler
    pub result: SettledResult,

    /// The analyzer's own recomputed values (None if not an avalanche result)
    pub recomputed: Option<Recomputed>,

    /// Whether the submitted hashes match the recomputed values.
    /// `None` if this is not an avalanche task (PoCD tasks are not checked here).
    pub matches: Option<bool>,
}

/// Locally recomputed values for one avalanche experiment.
#[derive(Debug, Clone)]
pub struct Recomputed {
    pub original_hash: String,
    pub flipped_hash:  String,
    pub xor_diff:      String,
    pub hamming_dist:  u32,
    pub content_hash:  String,
}

/// Derive the canonical seed for (objective_id, seed_index).
///
/// canonical_seed = SHA-256("qcb-avalanche-v1" || objective_id_utf8 || seed_index_le64)
pub fn derive_canonical_seed(objective_id: &str, seed_index: u32) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"qcb-avalanche-v1");
    h.update(objective_id.as_bytes());
    h.update((seed_index as u64).to_le_bytes());
    h.finalize().into()
}

/// Recompute one avalanche experiment from (objective_id, seed_index, bit_index).
///
/// Bit flip convention: byte_idx = bit_index / 8; bit_shift = 7 - (bit_index % 8)
/// (MSB = bit 7 of byte 0, consistent with qcb-miner's challenge::solve_avalanche)
pub fn recompute(objective_id: &str, seed_index: u32, bit_index: u32) -> Recomputed {
    assert!(bit_index < 256, "bit_index must be 0..255");

    let canonical_seed = derive_canonical_seed(objective_id, seed_index);

    // original_hash = SHA-256(canonical_seed)
    let original_bytes: [u8; 32] = Sha256::digest(canonical_seed).into();

    // Flip bit bit_index in the canonical seed
    let mut flipped_seed = canonical_seed;
    let byte_idx  = (bit_index / 8) as usize;
    let bit_shift = 7 - (bit_index % 8);
    flipped_seed[byte_idx] ^= 1u8 << bit_shift;

    // flipped_hash = SHA-256(flipped_seed)
    let flipped_bytes: [u8; 32] = Sha256::digest(flipped_seed).into();

    // xor_diff[i] = original_bytes[i] ^ flipped_bytes[i]
    let mut xor_bytes = [0u8; 32];
    for i in 0..32 {
        xor_bytes[i] = original_bytes[i] ^ flipped_bytes[i];
    }

    let hamming_dist: u32 = xor_bytes.iter().map(|b| b.count_ones()).sum();

    // content_hash = SHA-256(original_bytes || flipped_bytes)
    let mut ch = Sha256::new();
    ch.update(original_bytes);
    ch.update(flipped_bytes);
    let content_hash_bytes: [u8; 32] = ch.finalize().into();

    Recomputed {
        original_hash: hex::encode(original_bytes),
        flipped_hash:  hex::encode(flipped_bytes),
        xor_diff:      hex::encode(xor_bytes),
        hamming_dist,
        content_hash:  hex::encode(content_hash_bytes),
    }
}

/// Verify all settled results.  Non-avalanche tasks are passed through with
/// `recomputed = None` and `matches = None`.
pub fn verify_all(objective_id: &str, results: &[SettledResult]) -> Vec<VerifiedResult> {
    results
        .iter()
        .map(|r| {
            if r.task_kind != "avalanche_experiment" && r.task_kind != "avalanche_replication" {
                return VerifiedResult {
                    result:     r.clone(),
                    recomputed: None,
                    matches:    None,
                };
            }

            let (Some(seed_idx), Some(bit_idx)) = (r.avl_seed_index, r.avl_bit_index) else {
                // Malformed avalanche result — missing index fields
                return VerifiedResult {
                    result:     r.clone(),
                    recomputed: None,
                    matches:    Some(false),
                };
            };

            let rc = recompute(objective_id, seed_idx, bit_idx);

            // Compare submitted vs recomputed
            let hash_ok = r.avl_original_hash.as_deref() == Some(rc.original_hash.as_str())
                && r.avl_flipped_hash.as_deref() == Some(rc.flipped_hash.as_str())
                && r.avl_xor_diff.as_deref()     == Some(rc.xor_diff.as_str())
                && r.content_hash                 == rc.content_hash;

            // Hamming distance should match (integer, so exact equality expected)
            let hamming_ok = r.avl_hamming_dist == Some(rc.hamming_dist);

            VerifiedResult {
                result:     r.clone(),
                recomputed: Some(rc),
                matches:    Some(hash_ok && hamming_ok),
            }
        })
        .collect()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const OBJ: &str = "test-objective-id-for-analyzer";

    #[test]
    fn canonical_seed_is_deterministic() {
        let a = derive_canonical_seed(OBJ, 0);
        let b = derive_canonical_seed(OBJ, 0);
        assert_eq!(a, b);
    }

    #[test]
    fn canonical_seed_differs_by_index() {
        let a = derive_canonical_seed(OBJ, 0);
        let b = derive_canonical_seed(OBJ, 1);
        assert_ne!(a, b);
    }

    #[test]
    fn recompute_is_deterministic() {
        let a = recompute(OBJ, 0, 0);
        let b = recompute(OBJ, 0, 0);
        assert_eq!(a.original_hash, b.original_hash);
        assert_eq!(a.hamming_dist,  b.hamming_dist);
    }

    #[test]
    fn different_bit_indices_differ() {
        let a = recompute(OBJ, 0, 0);
        let b = recompute(OBJ, 0, 1);
        // Flipping different bits should (with overwhelming probability) produce
        // different hashes.
        assert_ne!(a.flipped_hash, b.flipped_hash);
    }

    #[test]
    fn hamming_in_range() {
        for bit in 0u32..16 {
            let rc = recompute(OBJ, 0, bit);
            assert!(
                rc.hamming_dist <= 256,
                "hamming_dist {bit} out of range: {}",
                rc.hamming_dist
            );
        }
    }

    #[test]
    fn xor_consistency() {
        let rc = recompute(OBJ, 0, 42);
        let orig  = hex::decode(&rc.original_hash).unwrap();
        let flip  = hex::decode(&rc.flipped_hash).unwrap();
        let xor   = hex::decode(&rc.xor_diff).unwrap();
        let ham   = xor.iter().map(|b| b.count_ones()).sum::<u32>();
        assert_eq!(ham, rc.hamming_dist);
        for i in 0..32 {
            assert_eq!(xor[i], orig[i] ^ flip[i]);
        }
    }

    #[test]
    fn content_hash_derivation() {
        let rc = recompute(OBJ, 3, 100);
        let orig_bytes = hex::decode(&rc.original_hash).unwrap();
        let flip_bytes = hex::decode(&rc.flipped_hash).unwrap();
        let mut h = sha2::Sha256::new();
        sha2::Digest::update(&mut h, &orig_bytes);
        sha2::Digest::update(&mut h, &flip_bytes);
        let expected = hex::encode(sha2::Digest::finalize(h));
        assert_eq!(rc.content_hash, expected);
    }
}
