-- Migration 004: verification_records
--
-- Records independent reproduction attempts for submitted experiment_results.
-- An independent verification is performed by a DIFFERENT miner than the one
-- who submitted the original result.
--
-- Design note: the existing self-verification mechanism in DiscoveryVerifier
-- must NOT be presented as independent scientific verification.  An
-- independently_verified status here requires a separate miner_id on a
-- re-execution of the same task range.

CREATE TABLE IF NOT EXISTS verification_records (
    -- UUID primary key
    verification_id     UUID        PRIMARY KEY DEFAULT gen_random_uuid(),

    -- The result being verified
    result_id           UUID        NOT NULL
        REFERENCES experiment_results (result_id) ON DELETE CASCADE,

    -- The task the result covers (denormalised for query performance)
    task_id             TEXT        NOT NULL,

    -- Miner that performed the independent verification
    verifier_id         TEXT        NOT NULL,

    -- Verification outcome
    -- Values: 'reproduced' | 'diverged' | 'inconclusive'
    outcome             TEXT        NOT NULL,

    -- Content hash of the verifier's own result (for comparison to original)
    verifier_content_hash   TEXT    NOT NULL,

    -- Notes / divergence description (optional, human or AI generated)
    notes               TEXT,

    -- Receipt ID from the verifier's own on-chain submission (if any)
    verifier_receipt_id TEXT,

    -- Timestamps
    verified_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Prevent a miner from "verifying" their own submission
ALTER TABLE verification_records
    ADD CONSTRAINT chk_different_verifier
    CHECK (verifier_id != (
        SELECT miner_id FROM experiment_results
        WHERE experiment_results.result_id = verification_records.result_id
        LIMIT 1
    ));

CREATE INDEX IF NOT EXISTS idx_verification_records_result
    ON verification_records (result_id);

CREATE INDEX IF NOT EXISTS idx_verification_records_task
    ON verification_records (task_id);

CREATE INDEX IF NOT EXISTS idx_verification_records_verifier
    ON verification_records (verifier_id);
