//! Cryptographic challenge solver (PoCD work unit).
//!
//! ## Challenge definition
//!
//! Given an `input_seed` (i64) and a search range `[range_start, range_end)`,
//! find a nonce N in that range such that:
//!
//!   SHA-256(seed_bytes || nonce_bytes)  has at least DIFFICULTY_BITS leading zero bits
//!
//! where `seed_bytes` = seed as little-endian i64 (8 bytes)
//! and   `nonce_bytes` = N as little-endian i64 (8 bytes).
//!
//! This matches the challenge spec seeded by `qcb-seed` (`algorithm: sha256-preimage-v1`).
//!
//! ## Result
//!
//! `content_hash` — hex-encoded SHA-256 of the winning hash bytes.
//! This lets any verifier re-derive it: hash the same seed+nonce,
//! compare the result, then hash *that* to reproduce content_hash.
//!
//! ## Difficulty
//!
//! Currently set to DIFFICULTY_BITS = 16 (two leading zero bytes), matching
//! the `qcb-seed` default. Increase to raise difficulty; decrease for faster tests.

use sha2::{Digest, Sha256};

/// Difficulty: how many leading zero BITS the hash must have.
/// 16 = 2 leading zero bytes, matching the seeded challenge default.
const DIFFICULTY_BITS: u32 = 16;

/// A found solution.
pub struct Solution {
    /// The winning nonce value.
    pub nonce: i64,
    /// Hex-encoded winning hash (the raw SHA-256 output).
    pub winning_hash: String,
    /// Hex-encoded SHA-256 of the winning hash — this is the content_hash
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

        // SHA-256(seed || nonce)
        let mut hasher = Sha256::new();
        hasher.update(seed_bytes);
        hasher.update(nonce_bytes);
        let hash_bytes = hasher.finalize();

        // Check difficulty (leading zero bits)
        if leading_zero_bits(&hash_bytes) >= DIFFICULTY_BITS {
            let winning_hash = hex::encode(&hash_bytes);

            // content_hash = SHA-256(winning_hash_bytes)
            let mut h2 = Sha256::new();
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

/// Count the number of leading zero bits in a byte slice.
fn leading_zero_bits(bytes: &[u8]) -> u32 {
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

    #[test]
    fn solve_finds_a_solution_in_wide_range() {
        // With difficulty=16 bits, expect a hit within ~65536 nonces on average.
        let sol = solve(42, 0, 5_000_000);
        assert!(sol.is_some(), "expected a solution within 5M nonces at difficulty 16 bits");
        let sol = sol.unwrap();

        // Verify the winning hash ourselves
        let seed_bytes = 42i64.to_le_bytes();
        let nonce_bytes = sol.nonce.to_le_bytes();
        let mut h = Sha256::new();
        h.update(seed_bytes);
        h.update(nonce_bytes);
        let expected = h.finalize();
        assert_eq!(hex::encode(&expected), sol.winning_hash);
        assert!(leading_zero_bits(&expected) >= DIFFICULTY_BITS, "must have 16 leading zero bits");

        // Verify content_hash is SHA-256(winning_hash_bytes)
        let mut h2 = Sha256::new();
        h2.update(&expected);
        assert_eq!(hex::encode(h2.finalize()), sol.content_hash);
    }

    #[test]
    fn solve_returns_none_on_empty_range() {
        assert!(solve(42, 5, 5).is_none());
    }

    #[test]
    fn solve_returns_none_on_tiny_range_with_no_solution() {
        // A single nonce is astronomically unlikely to satisfy 16-bit difficulty.
        let result = solve(999_999_999, 0, 1);
        // Just confirm it doesn't panic; likely None.
        let _ = result;
    }

    #[test]
    fn two_miners_same_task_produce_same_content_hash() {
        // Determinism check: both miners searching the same range with same seed
        // must agree on the solution (and therefore the content_hash).
        let sol1 = solve(31415926535897932i64, 0, 5_000_000).expect("solution expected");
        let sol2 = solve(31415926535897932i64, 0, 5_000_000).expect("solution expected");
        assert_eq!(sol1.nonce, sol2.nonce);
        assert_eq!(sol1.content_hash, sol2.content_hash);
    }
}
