//! Report writers: JSON data file + Markdown human-readable report.
//!
//! Scientific integrity note: all reports describe the data as measured.
//! No automatic classification of results as anomalies or breakthroughs.
//! Outliers are flagged for human review.

use std::path::Path;

use serde_json::json;

use crate::compute::VerifiedResult;
use crate::stats::{AvalancheStats, ReplicationStats};

// ── JSON ──────────────────────────────────────────────────────────────────────

pub fn write_json(
    path:         &Path,
    objective_id: &str,
    results:      &[VerifiedResult],
    stats:        &AvalancheStats,
    replication:  &ReplicationStats,
) -> anyhow::Result<()> {
    // Build per-result rows (avalanche only)
    let result_rows: Vec<serde_json::Value> = results
        .iter()
        .filter(|r| {
            r.result.task_kind == "avalanche_experiment"
                || r.result.task_kind == "avalanche_replication"
        })
        .map(|r| {
            json!({
                "task_id":          r.result.task_id,
                "miner_id":         r.result.miner_id,
                "task_kind":        r.result.task_kind,
                "avl_seed_index":   r.result.avl_seed_index,
                "avl_bit_index":    r.result.avl_bit_index,
                "avl_original_hash": r.result.avl_original_hash,
                "avl_flipped_hash": r.result.avl_flipped_hash,
                "avl_xor_diff":     r.result.avl_xor_diff,
                "avl_hamming_dist": r.result.avl_hamming_dist,
                "content_hash":     r.result.content_hash,
                "compute_match":    r.matches,
                "recomputed": r.recomputed.as_ref().map(|rc| json!({
                    "original_hash": rc.original_hash,
                    "flipped_hash":  rc.flipped_hash,
                    "xor_diff":      rc.xor_diff,
                    "hamming_dist":  rc.hamming_dist,
                    "content_hash":  rc.content_hash,
                })),
            })
        })
        .collect();

    // Build histogram as sorted array
    let mut histogram: Vec<(u32, usize)> = stats.hamming_histogram.iter().map(|(&k, &v)| (k, v)).collect();
    histogram.sort_by_key(|&(k, _)| k);
    let histogram_json: Vec<serde_json::Value> = histogram
        .iter()
        .map(|(dist, count)| json!({"hamming_dist": dist, "count": count}))
        .collect();

    // Disagreement details
    let disagreements_json: Vec<serde_json::Value> = replication
        .disagreement_details
        .iter()
        .map(|d| json!({
            "seed_index":        d.seed_index,
            "bit_index":         d.bit_index,
            "primary_miner":     d.primary_miner,
            "replication_miner": d.replication_miner,
            "primary_hash":      d.primary_hash,
            "replication_hash":  d.replication_hash,
        }))
        .collect();

    let doc = json!({
        "schema_version":   "avalanche-report-v1",
        "objective_id":     objective_id,
        "disclaimer": "No result is automatically classified as a cryptographic anomaly \
                       or breakthrough. Outliers require independent human review.",
        "summary": {
            "avalanche_count":     stats.avalanche_count,
            "compute_mismatches":  stats.compute_mismatches,
            "hamming_mean":        stats.hamming_mean,
            "hamming_std":         stats.hamming_std,
            "hamming_min":         stats.hamming_min,
            "hamming_max":         stats.hamming_max,
            "outliers_3sigma":     stats.outliers_3sigma,
            "replication_pairs":   replication.pairs_checked,
            "replication_disagreements": replication.disagreements,
        },
        "hamming_histogram":          histogram_json,
        "output_bit_flip_freq":       stats.output_bit_flip_freq,
        "replication_disagreements":  disagreements_json,
        "results":                    result_rows,
    });

    let json_str = serde_json::to_string_pretty(&doc)?;
    std::fs::write(path, json_str)?;
    Ok(())
}

// ── Markdown ──────────────────────────────────────────────────────────────────

pub fn write_markdown(
    path:         &Path,
    objective_id: &str,
    results:      &[VerifiedResult],
    stats:        &AvalancheStats,
    replication:  &ReplicationStats,
) -> anyhow::Result<String> {
    let mut md = String::with_capacity(4096);

    // Header
    md.push_str("# QCB SHA-256 Avalanche Experiment Report\n\n");
    md.push_str(&format!(
        "**Objective ID:** `{}`  \n",
        objective_id
    ));
    md.push_str(&format!(
        "**Generated:** {}  \n\n",
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    ));

    // Disclaimer
    md.push_str("> **Scientific integrity notice:** All measurements in this report are \
        descriptive statistics of the raw data. No result is automatically classified as a \
        cryptographic anomaly or breakthrough. Outliers flagged below require independent \
        human review before drawing conclusions.\n\n");

    // Summary table
    md.push_str("## Summary\n\n");
    md.push_str("| Metric | Value |\n");
    md.push_str("|--------|-------|\n");
    md.push_str(&format!("| Results analyzed    | {} |\n", stats.avalanche_count));
    md.push_str(&format!("| Compute mismatches  | {} |\n", stats.compute_mismatches));
    if let Some(mean) = stats.hamming_mean {
        md.push_str(&format!("| Hamming mean        | {:.4} bits (expected ~128) |\n", mean));
    }
    if let Some(std) = stats.hamming_std {
        md.push_str(&format!("| Hamming std dev     | {:.4} bits (expected ~8) |\n", std));
    }
    if let Some(min) = stats.hamming_min {
        md.push_str(&format!("| Hamming min         | {} bits |\n", min));
    }
    if let Some(max) = stats.hamming_max {
        md.push_str(&format!("| Hamming max         | {} bits |\n", max));
    }
    md.push_str(&format!("| Outliers (>3σ)      | {} |\n", stats.outliers_3sigma));
    md.push_str(&format!("| Replication pairs   | {} |\n", replication.pairs_checked));
    md.push_str(&format!("| Replication disagree| {} |\n", replication.disagreements));
    md.push_str("\n");

    // Hamming histogram (condensed — group into bins of 4)
    if !stats.hamming_histogram.is_empty() {
        md.push_str("## Hamming Distance Distribution\n\n");
        md.push_str("Histogram of output bits changed per experiment \
            (expected: approximately normal, mean ≈ 128, std ≈ 8).\n\n");
        md.push_str("| Distance | Count |\n");
        md.push_str("|----------|-------|\n");
        let mut sorted: Vec<(u32, usize)> = stats.hamming_histogram
            .iter().map(|(&k, &v)| (k, v)).collect();
        sorted.sort_by_key(|&(k, _)| k);
        for (dist, count) in &sorted {
            md.push_str(&format!("| {} | {} |\n", dist, count));
        }
        md.push_str("\n");
    }

    // Compute mismatches
    if stats.compute_mismatches > 0 {
        md.push_str("## ⚠ Compute Verification Failures\n\n");
        md.push_str("The following results did not match the analyzer's local recomputation. \
            This may indicate a miner bug, data corruption, or transmission error. \
            These are NOT automatically evidence of a cryptographic attack.\n\n");
        md.push_str("| Task ID | Miner | Seed | Bit | Kind |\n");
        md.push_str("|---------|-------|------|-----|------|\n");
        for r in results.iter().filter(|r| r.matches == Some(false)) {
            md.push_str(&format!(
                "| `{}` | `{}` | {} | {} | {} |\n",
                r.result.task_id,
                r.result.miner_id,
                r.result.avl_seed_index.map_or("?".to_string(), |v| v.to_string()),
                r.result.avl_bit_index.map_or("?".to_string(), |v| v.to_string()),
                r.result.task_kind,
            ));
        }
        md.push_str("\n");
    }

    // Replication disagreements
    if replication.disagreements > 0 {
        md.push_str("## ⚠ Cross-Machine Replication Disagreements\n\n");
        md.push_str("Primary and replication miners submitted different content hashes \
            for the same (seed_index, bit_index). Human review required.\n\n");
        md.push_str("| Seed | Bit | Primary Miner | Replication Miner |\n");
        md.push_str("|------|-----|---------------|-------------------|\n");
        for d in &replication.disagreement_details {
            md.push_str(&format!(
                "| {} | {} | `{}` | `{}` |\n",
                d.seed_index, d.bit_index, d.primary_miner, d.replication_miner
            ));
        }
        md.push_str("\n");
    }

    // Outliers section
    if stats.outliers_3sigma > 0 {
        if let (Some(mean), Some(std)) = (stats.hamming_mean, stats.hamming_std) {
            md.push_str("## ℹ Hamming Distance Outliers (>3σ)\n\n");
            md.push_str(&format!(
                "Results where |hamming_dist − {:.2}| > 3 × {:.2} = {:.2}. \
                 For a binomial distribution (n=256, p=0.5), values outside 3σ \
                 occur ~0.3% of the time by chance alone.  \
                 **These require independent human review before drawing any conclusion.**\n\n",
                mean, std, 3.0 * std
            ));
            md.push_str("| Seed | Bit | Miner | Hamming dist | Δ from mean |\n");
            md.push_str("|------|-----|-------|--------------|-------------|\n");
            for r in results.iter().filter(|r| {
                r.result.avl_hamming_dist
                    .map(|h| ((h as f64) - mean).abs() > 3.0 * std)
                    .unwrap_or(false)
            }) {
                let h = r.result.avl_hamming_dist.unwrap_or(0);
                md.push_str(&format!(
                    "| {} | {} | `{}` | {} | {:.2} |\n",
                    r.result.avl_seed_index.map_or("?".to_string(), |v| v.to_string()),
                    r.result.avl_bit_index.map_or("?".to_string(), |v| v.to_string()),
                    r.result.miner_id,
                    h,
                    (h as f64) - mean,
                ));
            }
            md.push_str("\n");
        }
    }

    // Output bit flip frequency (compressed summary)
    if stats.output_bit_flip_freq.iter().any(|&f| f > 0.0) {
        md.push_str("## Per-Output-Bit Flip Frequency\n\n");
        md.push_str("Fraction of experiments in which each output bit changed. \
            Ideal: all values close to 0.500 (strict avalanche criterion).\n\n");
        // Print only the min, max, mean, and any bits with freq < 0.3 or > 0.7
        let freqs = &stats.output_bit_flip_freq;
        let n = freqs.len() as f64;
        let fmean = freqs.iter().sum::<f64>() / n;
        let fmin  = freqs.iter().cloned().fold(f64::INFINITY, f64::min);
        let fmax  = freqs.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        md.push_str(&format!(
            "- Mean flip frequency: {:.4}  \n- Min: {:.4}  \n- Max: {:.4}\n\n",
            fmean, fmin, fmax
        ));
        let extreme: Vec<(usize, f64)> = freqs
            .iter()
            .enumerate()
            .filter(|(_, &f)| f < 0.3 || f > 0.7)
            .map(|(i, &f)| (i, f))
            .collect();
        if extreme.is_empty() {
            md.push_str("All output bits have flip frequency in [0.3, 0.7]. \
                No anomalous output-bit bias detected in this sample.\n\n");
        } else {
            md.push_str(&format!(
                "{} output bit(s) outside [0.3, 0.7] — listed in the JSON report. \
                 Requires human review; may be a statistical artifact at small sample sizes.\n\n",
                extreme.len()
            ));
        }
    }

    // Footer
    md.push_str("---\n\n");
    md.push_str("*Generated by qcb-analyzer. \
        Full per-result data and per-input-bit flip matrix are in the accompanying JSON file.*\n");

    std::fs::write(path, &md)?;
    Ok(md)
}
