//! Cryptographic challenge solver — two-phase PoCD cascade + avalanche experiments.
//!
//! ## Phase 1
//!
//!   SHA-256(seed_bytes || nonce_bytes) must have ≥ PHASE1_DIFFICULTY_BITS leading zero bits.
//!
//!   seed_bytes  = input_seed as little-endian i64 (8 bytes)
//!   nonce_bytes = nonce as little-endian i64 (8 bytes)
//!
//! ## Phase 2
//!
//!   SHA-256(parent_hash_bytes || nonce_bytes) must have ≥ PHASE2_DIFFICULTY_BITS leading zero bits.
//!
//!   parent_hash_bytes = 32 raw bytes decoded from the hex parent_hash string
//!   nonce_bytes       = nonce as little-endian i64 (8 bytes)
//!
//! ## Content hash (PoCD)
//!
//!   Phase 1: content_hash = SHA-256(H1_bytes)
//!   Phase 2: content_hash = SHA-256(H1_bytes || H2_bytes)
//!              where H1_bytes = hex::decode(parent_hash) passed in from the task
//!
//! The content_hash is what multiple miners must independently reproduce for
//! the quorum check to pass.  Any verifier can re-derive it from the nonce alone.
//!
//! ## Difficulty
//!
//! Phase 1: 16 leading zero bits (2 zero bytes) — real work, ~65k hashes avg
//! Phase 2:  8 leading zero bits (1 zero byte)  — lighter, chained on H1
//!
//! ## Avalanche experiments (Change Set K)
//!
//!   Canonical seed derivation:
//!     canonical_seed = SHA-256("qcb-avalanche-v1" || objective_id_utf8 || seed_index_le64)
//!
//!   For each (seed_index, bit_index) task:
//!     original_hash = SHA-256(canonical_seed_bytes)
//!     flipped_seed  = canonical_seed with bit bit_index flipped
//!     flipped_hash  = SHA-256(flipped_seed_bytes)
//!     xor_diff      = original_hash XOR flipped_hash  (256 bits)
//!     hamming_dist  = popcount(xor_diff)
//!
//!   content_hash = SHA-256(original_hash || flipped_hash)
//!     — deterministic, verifiable by any party with the objective_id and indices.

use sha2::{Digest, Sha256};

/// Phase-1 difficulty: leading zero bits the first hash must have.
const PHASE1_DIFFICULTY_BITS: u32 = 16;

/// Phase-2 difficulty: leading zero bits the second hash must have.
/// Lighter than phase-1 because it already depends on phase-1 work.
const PHASE2_DIFFICULTY_BITS: u32 = 8;

// ── Solution types ────────────────────────────────────────────────────────────

/// A found phase-1 solution.
#[derive(Debug, Clone)]
pub struct Phase1Solution {
    pub nonce:        i64,
    /// Hex-encoded raw SHA-256 output (H1).
    pub winning_hash: String,
    /// Hex-encoded SHA-256(H1) — submitted as content_hash.
    pub content_hash: String,
}

/// A found phase-2 solution.
#[derive(Debug, Clone)]
pub struct Phase2Solution {
    pub nonce:        i64,
    /// Hex-encoded raw SHA-256(parent_hash_bytes || nonce) output (H2).
    pub winning_hash: String,
    /// Hex-encoded SHA-256(H1_bytes || H2_bytes) — the combined proof.
    pub content_hash: String,
}

// ── Solvers ───────────────────────────────────────────────────────────────────

/// Search `[range_start, range_end)` for a phase-1 nonce.
///
/// CPU-bound; call from `spawn_blocking`.
pub fn solve_phase1(seed: i64, range_start: i64, range_end: i64) -> Option<Phase1Solution> {
    let seed_bytes = seed.to_le_bytes();

    for nonce in range_start..range_end {
        let nonce_bytes = nonce.to_le_bytes();

        let mut h = Sha256::new();
        h.update(seed_bytes);
        h.update(nonce_bytes);
        let hash_bytes = h.finalize();

        if leading_zero_bits(&hash_bytes) >= PHASE1_DIFFICULTY_BITS {
            let winning_hash = hex::encode(&hash_bytes);

            // content_hash = SHA-256(H1)
            let mut h2 = Sha256::new();
            h2.update(&hash_bytes);
            let content_hash = hex::encode(h2.finalize());

            return Some(Phase1Solution { nonce, winning_hash, content_hash });
        }
    }
    None
}

/// Search `[range_start, range_end)` for a phase-2 nonce.
///
/// `parent_hash_hex` is the hex-encoded H1 from the phase-1 winner.
/// CPU-bound; call from `spawn_blocking`.
pub fn solve_phase2(
    parent_hash_hex: &str,
    range_start:     i64,
    range_end:       i64,
) -> Option<Phase2Solution> {
    // Decode the phase-1 hash bytes — these are the prefix for every hash attempt.
    let h1_bytes = match hex::decode(parent_hash_hex) {
        Ok(b) => b,
        Err(_) => return None,
    };

    for nonce in range_start..range_end {
        let nonce_bytes = nonce.to_le_bytes();

        let mut h = Sha256::new();
        h.update(&h1_bytes);
        h.update(nonce_bytes);
        let h2_bytes = h.finalize();

        if leading_zero_bits(&h2_bytes) >= PHASE2_DIFFICULTY_BITS {
            let winning_hash = hex::encode(&h2_bytes);

            // content_hash = SHA-256(H1 || H2) — the combined two-machine proof
            let mut hc = Sha256::new();
            hc.update(&h1_bytes);
            hc.update(&h2_bytes);
            let content_hash = hex::encode(hc.finalize());

            return Some(Phase2Solution { nonce, winning_hash, content_hash });
        }
    }
    None
}

// ── Helper ────────────────────────────────────────────────────────────────────

/// Count the number of leading zero bits in a byte slice.
pub fn leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut count = 0u32;
    for &b in bytes {
        if b == 0 {
            count += 8;
        } else {
            count += b.leading_zeros();
            break;
        }
    }
    count
}

// ── Avalanche experiment (Change Set K) ──────────────────────────────────────

/// Result of a single SHA-256 avalanche measurement.
///
/// For a given `(objective_id, seed_index, bit_index)` triple this is
/// completely deterministic and can be independently reproduced by any party.
#[derive(Debug, Clone)]
pub struct AvalancheResult {
    /// Hex-encoded SHA-256(canonical_seed) — the "before" hash, 64 chars.
    pub original_hash: String,
    /// Hex-encoded SHA-256(canonical_seed with bit `bit_index` flipped) — "after", 64 chars.
    pub flipped_hash:  String,
    /// Hex-encoded XOR of both hashes — 256-bit difference vector, 64 chars.
    pub xor_diff:      String,
    /// popcount(xor_diff) — number of output bits that changed (0..=256).
    pub hamming_dist:  u32,
    /// Hex-encoded SHA-256(original_hash_bytes || flipped_hash_bytes) — dedup key.
    pub content_hash:  String,
}

/// Derive the canonical 32-byte seed for `seed_index` within `objective_id`.
///
/// canonical_seed = SHA-256("qcb-avalanche-v1" || objective_id_utf8 || seed_index_le64)
///
/// Both machines must produce identical byte sequences. All inputs are
/// deterministic: the domain separator is a fixed ASCII string, the
/// objective_id is the UTF-8 bytes of the UUID string, and the seed_index
/// is the 8-byte little-endian encoding of the u64.
pub fn derive_avalanche_seed(objective_id: &str, seed_index: u32) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"qcb-avalanche-v1");
    h.update(objective_id.as_bytes());
    h.update((seed_index as u64).to_le_bytes());
    h.finalize().into()
}

/// Compute the SHA-256 avalanche measurement for one `(seed_index, bit_index)` pair.
///
/// `objective_id` is the UUID string of the research objective — used only
/// for canonical seed derivation and does not appear in any hash over the
/// experimental data.
///
/// CPU-bound but fast (two SHA-256 calls); no blocking wrapper needed.
pub fn solve_avalanche(
    objective_id: &str,
    seed_index:   u32,
    bit_index:    u32,
) -> AvalancheResult {
    assert!(bit_index < 256, "bit_index must be 0..255");

    // ── Canonical seed ────────────────────────────────────────────────────────
    let canonical_seed: [u8; 32] = derive_avalanche_seed(objective_id, seed_index);

    // ── Original hash: SHA-256(canonical_seed) ───────────────────────────────
    let mut h = Sha256::new();
    h.update(&canonical_seed);
    let original_bytes: [u8; 32] = h.finalize().into();

    // ── Flipped seed: flip bit `bit_index` in canonical_seed ─────────────────
    let mut flipped_seed = canonical_seed;
    let byte_idx  = (bit_index / 8) as usize;
    let bit_shift = 7 - (bit_index % 8); // MSB = bit 7 of byte 0
    flipped_seed[byte_idx] ^= 1u8 << bit_shift;

    // ── Flipped hash: SHA-256(flipped_seed) ──────────────────────────────────
    let mut h2 = Sha256::new();
    h2.update(&flipped_seed);
    let flipped_bytes: [u8; 32] = h2.finalize().into();

    // ── XOR difference vector (256 bits) ─────────────────────────────────────
    let mut xor_bytes = [0u8; 32];
    for i in 0..32 {
        xor_bytes[i] = original_bytes[i] ^ flipped_bytes[i];
    }

    // ── Hamming distance: popcount of XOR vector ──────────────────────────────
    let hamming_dist: u32 = xor_bytes.iter().map(|b| b.count_ones()).sum();

    // ── Content hash: SHA-256(original || flipped) ────────────────────────────
    let mut hc = Sha256::new();
    hc.update(&original_bytes);
    hc.update(&flipped_bytes);
    let content_hash_bytes: [u8; 32] = hc.finalize().into();

    AvalancheResult {
        original_hash: hex::encode(&original_bytes),
        flipped_hash:  hex::encode(&flipped_bytes),
        xor_diff:      hex::encode(&xor_bytes),
        hamming_dist,
        content_hash:  hex::encode(&content_hash_bytes),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Phase 1 ──────────────────────────────────────────────────────────────

    #[test]
    fn phase1_finds_solution() {
        let sol = solve_phase1(31415926535897932i64, 0, 5_000_000)
            .expect("solution in 5M nonces at 16 bits");

        // Re-verify the winning hash
        let seed_bytes = 31415926535897932i64.to_le_bytes();
        let nonce_bytes = sol.nonce.to_le_bytes();
        let mut h = Sha256::new();
        h.update(seed_bytes);
        h.update(nonce_bytes);
        let expected = h.finalize();
        assert_eq!(hex::encode(&expected), sol.winning_hash);
        assert!(leading_zero_bits(&expected) >= PHASE1_DIFFICULTY_BITS);

        // Re-verify content_hash = SHA-256(H1)
        let mut h2 = Sha256::new();
        h2.update(&expected);
        assert_eq!(hex::encode(h2.finalize()), sol.content_hash);
    }

    #[test]
    fn phase1_none_on_empty_range() {
        assert!(solve_phase1(42, 5, 5).is_none());
    }

    #[test]
    fn phase1_deterministic() {
        let s1 = solve_phase1(7, 0, 5_000_000).unwrap();
        let s2 = solve_phase1(7, 0, 5_000_000).unwrap();
        assert_eq!(s1.nonce, s2.nonce);
        assert_eq!(s1.content_hash, s2.content_hash);
    }

    // ── Phase 2 ──────────────────────────────────────────────────────────────

    #[test]
    fn phase2_finds_solution_from_phase1_hash() {
        // First get a real phase-1 hash to use as parent
        let p1 = solve_phase1(31415926535897932i64, 0, 5_000_000).unwrap();

        // Phase-2 should find a solution quickly (8-bit difficulty)
        let sol = solve_phase2(&p1.winning_hash, 0, 500_000)
            .expect("phase-2 solution in 500k nonces at 8 bits");

        // Re-verify H2
        let h1_bytes = hex::decode(&p1.winning_hash).unwrap();
        let nonce_bytes = sol.nonce.to_le_bytes();
        let mut h = Sha256::new();
        h.update(&h1_bytes);
        h.update(nonce_bytes);
        let h2_bytes = h.finalize();
        assert_eq!(hex::encode(&h2_bytes), sol.winning_hash);
        assert!(leading_zero_bits(&h2_bytes) >= PHASE2_DIFFICULTY_BITS);

        // Re-verify combined content_hash = SHA-256(H1 || H2)
        let mut hc = Sha256::new();
        hc.update(&h1_bytes);
        hc.update(&h2_bytes);
        assert_eq!(hex::encode(hc.finalize()), sol.content_hash);
    }

    #[test]
    fn phase2_different_miners_same_content_hash() {
        // Two miners solving the same phase-2 task must agree on content_hash
        let p1 = solve_phase1(42, 0, 5_000_000).unwrap();
        let sol_a = solve_phase2(&p1.winning_hash, 0, 500_000).unwrap();
        let sol_b = solve_phase2(&p1.winning_hash, 0, 500_000).unwrap();
        assert_eq!(sol_a.nonce, sol_b.nonce);
        assert_eq!(sol_a.content_hash, sol_b.content_hash);
    }

    #[test]
    fn phase2_invalid_parent_hash_returns_none() {
        // Bad hex → returns None gracefully
        assert!(solve_phase2("not_hex!!", 0, 100).is_none());
    }

    // ── Avalanche ─────────────────────────────────────────────────────────────

    #[test]
    fn avalanche_seed_derivation_is_deterministic() {
        let obj = "023807d7-6b28-43a4-8761-2ffa014ecb43";
        let s1 = derive_avalanche_seed(obj, 0);
        let s2 = derive_avalanche_seed(obj, 0);
        assert_eq!(s1, s2, "same inputs must produce same seed");
    }

    #[test]
    fn avalanche_seed_differs_by_index() {
        let obj = "023807d7-6b28-43a4-8761-2ffa014ecb43";
        let s0 = derive_avalanche_seed(obj, 0);
        let s1 = derive_avalanche_seed(obj, 1);
        assert_ne!(s0, s1, "different seed_index must produce different seed");
    }

    #[test]
    fn avalanche_result_is_deterministic() {
        let obj = "023807d7-6b28-43a4-8761-2ffa014ecb43";
        let r1 = solve_avalanche(obj, 0, 0);
        let r2 = solve_avalanche(obj, 0, 0);
        assert_eq!(r1.original_hash, r2.original_hash);
        assert_eq!(r1.flipped_hash,  r2.flipped_hash);
        assert_eq!(r1.xor_diff,      r2.xor_diff);
        assert_eq!(r1.hamming_dist,  r2.hamming_dist);
        assert_eq!(r1.content_hash,  r2.content_hash);
    }

    #[test]
    fn avalanche_xor_and_hamming_consistent() {
        let obj = "023807d7-6b28-43a4-8761-2ffa014ecb43";
        let r = solve_avalanche(obj, 3, 127);

        // XOR must be 64 hex chars (32 bytes)
        assert_eq!(r.xor_diff.len(), 64);

        // hamming_dist == popcount(xor_diff)
        let xor_bytes = hex::decode(&r.xor_diff).unwrap();
        let expected_hamming: u32 = xor_bytes.iter().map(|b| b.count_ones()).sum();
        assert_eq!(r.hamming_dist, expected_hamming);
    }

    #[test]
    fn avalanche_different_bit_indices_differ() {
        let obj = "023807d7-6b28-43a4-8761-2ffa014ecb43";
        let r0   = solve_avalanche(obj, 0, 0);
        let r100 = solve_avalanche(obj, 0, 100);
        // Two different bit flips should (almost certainly) produce different results
        assert_ne!(r0.flipped_hash, r100.flipped_hash);
        assert_ne!(r0.xor_diff,     r100.xor_diff);
    }

    #[test]
    fn avalanche_content_hash_is_sha256_of_both_hashes() {
        // Independently recompute content_hash and confirm it matches
        let obj = "023807d7-6b28-43a4-8761-2ffa014ecb43";
        let r = solve_avalanche(obj, 5, 200);

        let orig_bytes    = hex::decode(&r.original_hash).unwrap();
        let flipped_bytes = hex::decode(&r.flipped_hash).unwrap();

        let mut h = Sha256::new();
        h.update(&orig_bytes);
        h.update(&flipped_bytes);
        let expected = hex::encode(h.finalize());

        assert_eq!(r.content_hash, expected);
    }

    #[test]
    fn avalanche_hamming_in_plausible_range() {
        // For SHA-256, Hamming distance should be roughly 128 (binomial, p=0.5, n=256)
        // A single result can deviate, but must be in 0..=256.
        let obj = "023807d7-6b28-43a4-8761-2ffa014ecb43";
        for bit_idx in [0u32, 1, 63, 127, 200, 255] {
            let r = solve_avalanche(obj, 0, bit_idx);
            assert!(r.hamming_dist <= 256,
                "hamming_dist={} out of range for bit_index={}", r.hamming_dist, bit_idx);
        }
    }
}
