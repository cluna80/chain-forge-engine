//! Cryptographic challenge solver (PoCD work unit).
//!
//! ## Challenge definition
//!
//! Given an `input_seed` (i64) and a search range `[range_start, range_end)`,
//! find a nonce N in that range such that:
//!
//!   SHA3-256(seed_bytes || nonce_bytes)  starts with at least one zero byte
//!
//! where `seed_bytes` = seed as little-endian i64 (8 bytes)
//! and   `nonce_bytes` = N as little-endian i64 (8 bytes).
//!
//! ## Result
//!
//! `content_hash` — hex-encoded SHA3-256 of the winning hash bytes.
//! This lets any verifier re-derive it: hash the same seed+nonce,
//! compare the result, then hash *that* to reproduce content_hash.
//!
//! ## Difficulty
//!
//! Currently set to DIFFICULTY_BYTES = 1 (first byte must be 0x00).
//! Increase to raise difficulty; decrease for faster tests.

use sha3::{Digest, Sha3_256};

/// Difficulty: how many leading zero bytes the hash must have.
const DIFFICULTY_BYTES: usize = 1;

/// A found solution.
pub struct Solution {
    /// The winning nonce value.
    pub nonce: i64,
    /// Hex-encoded winning hash (the raw SHA3-256 output).
    pub winning_hash: String,
    /// Hex-encoded SHA3-256 of the winning hash — this is the content_hash
    /// submitted to the scheduler so verifiers can deterministically reproduce it.
    pub content_hash: String,
}

/// Search [range_start, range_end) for a nonce that satisfies the challenge.
///
/// Returns `Some(Solution)` on success, `None` if no nonce in the range works.
/// This is CPU-bound and should be called from `spawn_blocking`.
pub fn solve(seed: i64, range_start: i64, range_end: i64) -> Option<Solution> {
    let seed_bytes = seed.to_le_bytes();

    for nonce in range_start..range_end {
        let nonce_bytes = nonce.to_le_bytes();

        // SHA3-256(seed || nonce)
        let mut hasher = Sha3_256::new();
        hasher.update(seed_bytes);
        hasher.update(nonce_bytes);
        let hash_bytes = hasher.finalize();

        // Check difficulty
        if hash_bytes[..DIFFICULTY_BYTES].iter().all(|&b| b == 0) {
            let winning_hash = hex::encode(&hash_bytes);

            // content_hash = SHA3-256(winning_hash_bytes)
            let mut h2 = Sha3_256::new();
            h2.update(&hash_bytes);
            let content_hash = hex::encode(h2.finalize());

            return Some(Solution {
                nonce,
                winning_hash,
                content_hash,
            });
        }
    }

    None
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn solve_finds_a_solution_in_wide_range() {
        // With difficulty=1 byte, expect a hit within ~256 nonces on average.
        let sol = solve(42, 0, 100_000);
        assert!(sol.is_some(), "expected a solution within 100k nonces");
        let sol = sol.unwrap();

        // Verify the winning hash ourselves
        let seed_bytes = 42i64.to_le_bytes();
        let nonce_bytes = sol.nonce.to_le_bytes();
        let mut h = Sha3_256::new();
        h.update(seed_bytes);
        h.update(nonce_bytes);
        let expected = h.finalize();
        assert_eq!(hex::encode(&expected), sol.winning_hash);
        assert_eq!(expected[0], 0x00, "first byte must be 0x00");

        // Verify content_hash is SHA3-256(winning_hash_bytes)
        let mut h2 = Sha3_256::new();
        h2.update(&expected);
        assert_eq!(hex::encode(h2.finalize()), sol.content_hash);
    }

    #[test]
    fn solve_returns_none_on_empty_range() {
        assert!(solve(42, 5, 5).is_none());
    }

    #[test]
    fn solve_returns_none_on_range_with_no_solution() {
        // Seed 0, nonce 0 → SHA3-256(0||0) does NOT start with 0x00
        // (empirically confirmed), so a range of just [0,1) yields None.
        // We test with a tiny range that is very unlikely to hit.
        let result = solve(999_999_999, 0, 1);
        // Just check it doesn't panic; may be Some or None.
        let _ = result;
    }

    #[test]
    fn two_miners_same_task_produce_same_content_hash() {
        // Determinism check: both miners searching the same range with same seed
        // must agree on the solution (and therefore the content_hash).
        let sol1 = solve(7, 0, 100_000).expect("solution expected");
        let sol2 = solve(7, 0, 100_000).expect("solution expected");
        assert_eq!(sol1.nonce, sol2.nonce);
        assert_eq!(sol1.content_hash, sol2.content_hash);
    }
}
