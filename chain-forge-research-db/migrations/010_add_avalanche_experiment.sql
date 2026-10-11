-- Migration 010: Avalanche experiment columns for Change Set K
--
-- Adds the columns needed to support AvalancheExperiment and
-- AvalancheReplication task kinds alongside the existing PoCD cascade.
--
-- research_tasks additions:
--   task_kind       — discriminator: 'pocd_phase1' | 'pocd_phase2' |
--                     'avalanche_experiment' | 'avalanche_replication'
--   avl_seed_index  — which of the 10 canonical seeds this task uses (0..9)
--   avl_bit_index   — which input bit position is flipped (0..255)
--
-- experiment_results additions:
--   avl_original_hash — SHA-256(canonical_seed) as 64 hex chars
--   avl_flipped_hash  — SHA-256(flip(seed, bit_index)) as 64 hex chars
--   avl_xor_diff      — XOR of both hashes as 64 hex chars (full 256-bit vector)
--   avl_hamming_dist  — popcount(xor_diff), denormalized for fast aggregates

-- ── research_tasks ────────────────────────────────────────────────────────────

ALTER TABLE research_tasks
    ADD COLUMN task_kind      TEXT    NOT NULL DEFAULT 'pocd_phase1',
    ADD COLUMN avl_seed_index INTEGER,
    ADD COLUMN avl_bit_index  INTEGER;

COMMENT ON COLUMN research_tasks.task_kind IS
    'Task kind discriminator.
     ''pocd_phase1''          — PoW partial-preimage Phase 1 (original).
     ''pocd_phase2''          — PoW partial-preimage Phase 2 (original).
     ''avalanche_experiment'' — SHA-256 avalanche single-bit-flip measurement.
     ''avalanche_replication'' — 5% cross-machine replication of an avalanche result.';

COMMENT ON COLUMN research_tasks.avl_seed_index IS
    'For avalanche tasks: which of the 10 canonical seeds this task uses (0..9).
     Canonical seed = SHA-256("qcb-avalanche-v1" || objective_id_bytes || seed_index_le64).
     NULL for PoCD tasks.';

COMMENT ON COLUMN research_tasks.avl_bit_index IS
    'For avalanche tasks: which input bit position (0..255) is flipped.
     NULL for PoCD tasks.';

-- Fast lookup: all avalanche tasks for an objective in seed/bit order
CREATE INDEX IF NOT EXISTS idx_research_tasks_avalanche
    ON research_tasks (objective_id, avl_seed_index, avl_bit_index)
    WHERE task_kind IN ('avalanche_experiment', 'avalanche_replication');

-- Fast lookup: all tasks of a given kind for an objective
CREATE INDEX IF NOT EXISTS idx_research_tasks_kind
    ON research_tasks (objective_id, task_kind);

-- ── experiment_results ────────────────────────────────────────────────────────

ALTER TABLE experiment_results
    ADD COLUMN avl_original_hash TEXT,
    ADD COLUMN avl_flipped_hash  TEXT,
    ADD COLUMN avl_xor_diff      TEXT,
    ADD COLUMN avl_hamming_dist  INTEGER;

COMMENT ON COLUMN experiment_results.avl_original_hash IS
    'For avalanche results: hex-encoded SHA-256(canonical_seed), 64 characters.
     NULL for PoCD results.';

COMMENT ON COLUMN experiment_results.avl_flipped_hash IS
    'For avalanche results: hex-encoded SHA-256(flip(canonical_seed, bit_index)), 64 chars.
     NULL for PoCD results.';

COMMENT ON COLUMN experiment_results.avl_xor_diff IS
    'For avalanche results: hex-encoded XOR of avl_original_hash and avl_flipped_hash.
     64 characters (256 bits). Enables per-output-bit flip-frequency matrix analysis.
     NULL for PoCD results.';

COMMENT ON COLUMN experiment_results.avl_hamming_dist IS
    'For avalanche results: popcount(xor_diff), the number of output bits that changed.
     Ideally ~128 with std dev ~8 for SHA-256. Denormalized for fast aggregate queries.
     NULL for PoCD results.';

-- Fast aggregation: Hamming distance distribution for an objective's avalanche results
CREATE INDEX IF NOT EXISTS idx_experiment_results_hamming
    ON experiment_results (avl_hamming_dist)
    WHERE avl_hamming_dist IS NOT NULL;
