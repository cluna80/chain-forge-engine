-- Migration 003: experiment_results
--
-- Records every experimental result submitted by a miner for a microtask.
-- Multiple results per task are allowed (intentional replication support).
-- Deduplication is by content_hash — identical experiments are detected here.
--
-- This table stores submitted evidence; it does NOT grant reward eligibility.
-- Reward eligibility is enforced on-chain via MicrotaskCommitment / DiscoveryReceipt.

CREATE TABLE IF NOT EXISTS experiment_results (
    -- UUID primary key (prevents confusion with deterministic task/objective IDs)
    result_id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Parent task
    task_id             TEXT        NOT NULL
        REFERENCES research_tasks (task_id) ON DELETE CASCADE,

    -- DiscoveryReceipt ID from the on-chain record — the canonical commitment link
    receipt_id          TEXT        NOT NULL,

    -- Miner identity (public key hex or address)
    miner_id            TEXT        NOT NULL,

    -- Content hash of the experimental evidence (hex of SHA-256 over canonical bytes)
    -- Used for deduplication detection.
    content_hash        TEXT        NOT NULL,

    -- Result status
    -- Values: 'submitted' | 'provisionally_checked' | 'independently_verified' | 'rejected'
    result_status       TEXT        NOT NULL DEFAULT 'submitted',

    -- Raw result payload (JSON).  Includes output hash, iterations, timing metadata.
    -- Not parsed by consensus; stored verbatim as submitted evidence.
    result_payload      JSONB       NOT NULL DEFAULT '{}',

    -- Algorithm and workload version used by the miner
    algorithm_version   TEXT        NOT NULL,
    workload_version    TEXT        NOT NULL DEFAULT '1',

    -- Seal nonce from the DiscoveryProof — ties this result to a specific PoCD attempt
    seal_nonce          BIGINT,

    -- Timestamps
    submitted_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Prevent exact duplicate submissions (same content, same task, same miner)
CREATE UNIQUE INDEX IF NOT EXISTS idx_experiment_results_dedup
    ON experiment_results (task_id, miner_id, content_hash);

-- Allow fast lookup of all results for a task
CREATE INDEX IF NOT EXISTS idx_experiment_results_task
    ON experiment_results (task_id);

-- Allow fast lookup of all submissions by a miner
CREATE INDEX IF NOT EXISTS idx_experiment_results_miner
    ON experiment_results (miner_id);

-- Allow fast lookup by on-chain receipt
CREATE INDEX IF NOT EXISTS idx_experiment_results_receipt
    ON experiment_results (receipt_id);

CREATE TRIGGER trg_experiment_results_updated_at
    BEFORE UPDATE ON experiment_results
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
