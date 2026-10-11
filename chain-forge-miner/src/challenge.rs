//! Cryptographic challenge solver — two-phase PoCD cascade.
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
//! ## Content hash
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
}
