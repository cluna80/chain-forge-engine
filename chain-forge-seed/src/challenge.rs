//! Challenge verification helper used during seeding.
//!
//! Proves that at least one task in the objective is actually solvable
//! before committing all tasks to the DB — a fast sanity check so you
//! don't seed an unsolvable challenge.

use sha2::{Digest, Sha256};

/// Search [range_start, range_end) for a nonce satisfying the difficulty.
///
/// Returns `Some((nonce, hex_hash))` on the first hit, `None` if none found.
pub fn verify_solvable(
    seed:       i64,
    range_start: i64,
    range_end:   i64,
    difficulty_bits: u32,
) -> Option<(i64, String)> {
    let seed_bytes = seed.to_le_bytes();

    for nonce in range_start..range_end {
        let nonce_bytes = nonce.to_le_bytes();
        let mut h = Sha256::new();
        h.update(seed_bytes);
        h.update(nonce_bytes);
        let hash = h.finalize();

        if leading_zero_bits(&hash) >= difficulty_bits {
            return Some((nonce, hex::encode(&hash)));
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
    fn leading_zero_bits_counts_correctly() {
        assert_eq!(leading_zero_bits(&[0x00, 0x80]), 8 + 0); // 8 from first byte, 0 from 0x80
        assert_eq!(leading_zero_bits(&[0x00, 0x00, 0x40]), 8 + 8 + 1);
        assert_eq!(leading_zero_bits(&[0x80]), 0);
        assert_eq!(leading_zero_bits(&[0x00]), 8);
        assert_eq!(leading_zero_bits(&[0x01]), 7);
    }

    #[test]
    fn verify_solvable_finds_difficulty_8() {
        // Difficulty 8 = 1 zero byte. Should hit within a few hundred nonces.
        let result = verify_solvable(12345, 0, 1_000_000, 8);
        assert!(result.is_some(), "expected a solution within 1M nonces at difficulty 8");
        let (nonce, hash_hex) = result.unwrap();

        // Re-verify
        let seed_bytes = 12345i64.to_le_bytes();
        let nonce_bytes = nonce.to_le_bytes();
        let mut h = Sha256::new();
        h.update(seed_bytes);
        h.update(nonce_bytes);
        let expected = h.finalize();
        assert_eq!(hex::encode(&expected), hash_hex);
        assert_eq!(leading_zero_bits(&expected), leading_zero_bits(&expected));
        assert!(leading_zero_bits(&expected) >= 8);
    }

    #[test]
    fn verify_solvable_finds_difficulty_16() {
        // Difficulty 16 = 2 zero bytes. Expect hit within 100k nonces on average.
        let result = verify_solvable(31415926, 0, 10_000_000, 16);
        assert!(result.is_some(), "expected a solution within 10M nonces at difficulty 16");
    }

    #[test]
    fn verify_solvable_returns_none_on_empty_range() {
        assert!(verify_solvable(42, 5, 5, 8).is_none());
    }
}
