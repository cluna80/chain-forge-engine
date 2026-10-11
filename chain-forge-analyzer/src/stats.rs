//! Statistical summaries for avalanche experiment results.
//!
//! All functions return descriptive statistics only.  No inferences about
//! cryptographic security are drawn automatically.

use std::collections::HashMap;

use crate::compute::VerifiedResult;

/// Summary statistics for the full result set.
#[derive(Debug, Clone)]
pub struct AvalancheStats {
    /// Number of avalanche results (experiment + replication)
    pub avalanche_count:    usize,
    /// Hamming distances collected (for histogram and per-bit analysis)
    pub hamming_values:     Vec<u32>,
    /// Mean Hamming distance (None if no avalanche results)
    pub hamming_mean:       Option<f64>,
    /// Standard deviation of Hamming distance (None if < 2 results)
    pub hamming_std:        Option<f64>,
    /// Minimum Hamming distance observed
    pub hamming_min:        Option<u32>,
    /// Maximum Hamming distance observed
    pub hamming_max:        Option<u32>,
    /// Number of results that deviate by more than 3 standard deviations from mean
    pub outliers_3sigma:    usize,
    /// Number of results where the analyzer's recomputation disagrees
    pub compute_mismatches: usize,
    /// Histogram: hamming_dist → count
    pub hamming_histogram:  HashMap<u32, usize>,
    /// Per-output-bit flip frequency matrix:
    /// `output_bit_flip_freq[bit]` = fraction of experiments where that output bit flipped.
    /// Indexed 0..255; bit 0 = MSB of byte 0 of xor_diff.
    pub output_bit_flip_freq: Vec<f64>,
    /// Per-input-bit flip frequency matrix:
    /// `input_bit_flip_freq[bit]` = fraction of all experiments where the
    /// flipping of that input bit caused each of the 256 output bits to change.
    /// outer: input bit 0..255; inner: output bit 0..255 (fraction 0.0..1.0)
    pub input_bit_flip_matrix: Vec<Vec<f64>>,
}

/// Replication agreement summary.
#[derive(Debug, Clone)]
pub struct ReplicationStats {
    /// Number of primary/replication pairs found (matched by seed_index + bit_index)
    pub pairs_checked: usize,
    /// Number of pairs where hashes disagree between miners
    pub disagreements: usize,
    /// Details on each disagreeing pair
    pub disagreement_details: Vec<ReplicationDisagreement>,
}

#[derive(Debug, Clone)]
pub struct ReplicationDisagreement {
    pub seed_index:       u32,
    pub bit_index:        u32,
    pub primary_miner:    String,
    pub replication_miner: String,
    pub primary_hash:     Option<String>,
    pub replication_hash: Option<String>,
}

// ── Main statistics entry point ───────────────────────────────────────────────

pub fn compute(results: &[VerifiedResult]) -> AvalancheStats {
    let avalanche: Vec<&VerifiedResult> = results
        .iter()
        .filter(|r| {
            r.result.task_kind == "avalanche_experiment"
                || r.result.task_kind == "avalanche_replication"
        })
        .collect();

    let avalanche_count = avalanche.len();

    let hamming_values: Vec<u32> = avalanche
        .iter()
        .filter_map(|r| r.result.avl_hamming_dist)
        .collect();

    let compute_mismatches = avalanche
        .iter()
        .filter(|r| r.matches == Some(false))
        .count();

    // ── Hamming statistics ────────────────────────────────────────────────────
    let hamming_mean = if hamming_values.is_empty() {
        None
    } else {
        Some(hamming_values.iter().map(|&h| h as f64).sum::<f64>() / hamming_values.len() as f64)
    };

    let hamming_std = hamming_mean.and_then(|mean| {
        if hamming_values.len() < 2 {
            return None;
        }
        let variance = hamming_values
            .iter()
            .map(|&h| {
                let d = h as f64 - mean;
                d * d
            })
            .sum::<f64>()
            / (hamming_values.len() - 1) as f64;
        Some(variance.sqrt())
    });

    let hamming_min = hamming_values.iter().copied().min();
    let hamming_max = hamming_values.iter().copied().max();

    // Outliers: |h - mean| > 3 * std
    let outliers_3sigma = match (hamming_mean, hamming_std) {
        (Some(mean), Some(std)) if std > 0.0 => hamming_values
            .iter()
            .filter(|&&h| ((h as f64) - mean).abs() > 3.0 * std)
            .count(),
        _ => 0,
    };

    // ── Hamming histogram ─────────────────────────────────────────────────────
    let mut hamming_histogram: HashMap<u32, usize> = HashMap::new();
    for &h in &hamming_values {
        *hamming_histogram.entry(h).or_insert(0) += 1;
    }

    // ── Per-output-bit flip frequency ─────────────────────────────────────────
    // Collect xor_diff vectors from all experiment results
    let xor_diffs: Vec<[u8; 32]> = avalanche
        .iter()
        .filter_map(|r| {
            r.recomputed.as_ref().map(|rc| {
                let bytes = hex::decode(&rc.xor_diff).unwrap_or_default();
                let mut arr = [0u8; 32];
                let len = bytes.len().min(32);
                arr[..len].copy_from_slice(&bytes[..len]);
                arr
            })
        })
        .collect();

    let n_xor = xor_diffs.len() as f64;
    let mut output_bit_flip_freq = vec![0.0f64; 256];
    if n_xor > 0.0 {
        for xd in &xor_diffs {
            for byte_idx in 0..32usize {
                for bit_shift in 0u32..8 {
                    let output_bit = byte_idx * 8 + (7 - bit_shift as usize);
                    if xd[byte_idx] & (1 << bit_shift) != 0 {
                        output_bit_flip_freq[output_bit] += 1.0;
                    }
                }
            }
        }
        for freq in &mut output_bit_flip_freq {
            *freq /= n_xor;
        }
    }

    // ── Per-input-bit flip frequency matrix ───────────────────────────────────
    // For each input bit position, count how often each output bit flipped.
    // outer[input_bit][output_bit] = flip_count / experiments_for_that_input_bit
    let mut input_bit_flip_matrix: Vec<Vec<f64>> = vec![vec![0.0f64; 256]; 256];

    // Group results by input bit index
    let mut by_input_bit: HashMap<u32, Vec<[u8; 32]>> = HashMap::new();
    for r in &avalanche {
        if let (Some(bit_idx), Some(rc)) = (r.result.avl_bit_index, r.recomputed.as_ref()) {
            let xor_bytes = hex::decode(&rc.xor_diff).unwrap_or_default();
            let mut arr = [0u8; 32];
            let len = xor_bytes.len().min(32);
            arr[..len].copy_from_slice(&xor_bytes[..len]);
            by_input_bit.entry(bit_idx).or_default().push(arr);
        }
    }

    for (input_bit, xors) in &by_input_bit {
        let n = xors.len() as f64;
        if n == 0.0 || *input_bit >= 256 {
            continue;
        }
        for xd in xors {
            for byte_idx in 0..32usize {
                for bit_shift in 0u32..8 {
                    let output_bit = byte_idx * 8 + (7 - bit_shift as usize);
                    if xd[byte_idx] & (1 << bit_shift) != 0 {
                        input_bit_flip_matrix[*input_bit as usize][output_bit] += 1.0;
                    }
                }
            }
        }
        for output_bit in 0..256 {
            input_bit_flip_matrix[*input_bit as usize][output_bit] /= n;
        }
    }

    AvalancheStats {
        avalanche_count,
        hamming_values,
        hamming_mean,
        hamming_std,
        hamming_min,
        hamming_max,
        outliers_3sigma,
        compute_mismatches,
        hamming_histogram,
        output_bit_flip_freq,
        input_bit_flip_matrix,
    }
}

// ── Replication agreement check ───────────────────────────────────────────────

pub fn check_replication(results: &[VerifiedResult]) -> ReplicationStats {
    // Key: (seed_index, bit_index)
    type Key = (u32, u32);
    let mut experiments: HashMap<Key, Vec<&VerifiedResult>> = HashMap::new();
    let mut replications: HashMap<Key, Vec<&VerifiedResult>> = HashMap::new();

    for r in results {
        let (Some(si), Some(bi)) = (r.result.avl_seed_index, r.result.avl_bit_index) else {
            continue;
        };
        let key = (si, bi);
        if r.result.task_kind == "avalanche_experiment" {
            experiments.entry(key).or_default().push(r);
        } else if r.result.task_kind == "avalanche_replication" {
            replications.entry(key).or_default().push(r);
        }
    }

    let mut pairs_checked = 0;
    let mut disagreements = 0;
    let mut disagreement_details = Vec::new();

    for (key, repls) in &replications {
        let Some(exps) = experiments.get(key) else {
            continue;
        };
        // Use the first settled result from each kind for comparison
        let exp  = &exps[0];
        let repl = &repls[0];

        pairs_checked += 1;

        // Compare content_hash — the canonical dedup key
        if exp.result.content_hash != repl.result.content_hash {
            disagreements += 1;
            disagreement_details.push(ReplicationDisagreement {
                seed_index:        key.0,
                bit_index:         key.1,
                primary_miner:     exp.result.miner_id.clone(),
                replication_miner: repl.result.miner_id.clone(),
                primary_hash:      Some(exp.result.content_hash.clone()),
                replication_hash:  Some(repl.result.content_hash.clone()),
            });
        }
    }

    ReplicationStats {
        pairs_checked,
        disagreements,
        disagreement_details,
    }
}
