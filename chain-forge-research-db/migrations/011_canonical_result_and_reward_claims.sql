-- Migration 011: Canonical-result enforcement + research_reward_claims
--
-- Change Set L — QCB-PoCD-001 On-Chain Research Reward Settlement
--
-- # Canonical-result enforcement
--
-- Each task_id must have AT MOST ONE canonical accepted result.
-- The `canonical_result_id` column on `research_tasks` enforces this with a
-- UNIQUE constraint: only one result can ever be nominated as canonical for a
-- given task.
--
-- Duplicate submissions (same content_hash, same miner) are already blocked by
-- the existing idx_experiment_results_dedup unique index.  What was previously
-- unguarded was the case where the SAME miner submitted TWO distinct results for
-- the same task_id with different content_hash values (a malformed or racing
-- client), or where two different miners both submitted valid results (intentional
-- replication) and both later tried to claim acceptance.
--
-- Resolution: `accept_task_canonical()` (see db.rs) uses a single transaction
-- that:
--   1. Sets canonical_result_id = $result_id WHERE task_id = $task_id AND
--      canonical_result_id IS NULL  (atomic; fails if already set)
--   2. Updates that result to result_status = 'accepted'
--   3. Updates all OTHER results for the same task to result_status = 'superseded'
--   4. Transitions task status from 'submitted' → 'accepted'
--
-- The UNIQUE constraint on canonical_result_id acts as a second-layer guard
-- against any concurrent transaction that somehow bypasses step 1's WHERE clause.
--
-- # research_reward_claims
--
-- Tracks settlement of on-chain research reward transactions.  One row per
-- (objective_id, task_id, reward_kind) triple.  The claim_id is deterministic
-- (domain-separated hash), not a random UUID, so duplicate-claim protection is
-- both in this table (UNIQUE constraint) and on-chain (`claim:{claim_id}` state
-- key).
--
-- Settlement lifecycle:
--   pending    → submitted  (tx constructed and POSTed to node)
--   submitted  → finalized  (tx confirmed in canonical chain state)
--   submitted  → rejected   (tx invalid or node rejected it)
--
-- The claim is persisted as 'pending' BEFORE any tx is submitted.  Finality is
-- reconciled from chain state, NOT from the HTTP submission response.

-- ── research_tasks: add canonical_result_id ───────────────────────────────────

ALTER TABLE research_tasks
    ADD COLUMN canonical_result_id UUID
        REFERENCES experiment_results (result_id) ON DELETE SET NULL;

-- Enforce: at most one task may nominate a given result as canonical.
-- (In practice each result belongs to one task, but this blocks mis-wiring.)
CREATE UNIQUE INDEX IF NOT EXISTS idx_research_tasks_canonical_result
    ON research_tasks (canonical_result_id)
    WHERE canonical_result_id IS NOT NULL;

COMMENT ON COLUMN research_tasks.canonical_result_id IS
    'The single accepted result for this task.  Set atomically by accept_task_canonical().
     NULL until a result is accepted.  Once set, competing results are superseded.
     UNIQUE constraint ensures no two tasks can share a canonical result.';

-- ── result_status: add ''superseded'' as valid value ─────────────────────────
-- (The column is TEXT with no CHECK constraint, so this is documentation only.)
COMMENT ON COLUMN experiment_results.result_status IS
    'Lifecycle status of this result.
     submitted            — received from miner, awaiting verification.
     independently_verified — at least one verifier confirmed it.
     accepted             — selected as the canonical result for its task.
     superseded           — another result was selected as canonical instead.
     rejected             — failed independent verification.';

-- ── research_reward_claims ────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS research_reward_claims (
    -- Deterministic claim ID: hex(SHA-256("qcb-claim-v1" || chain_id ||
    --   objective_id || task_id || reward_kind)).
    -- Not a random UUID — allows idempotent re-submission after crashes.
    claim_id            TEXT        PRIMARY KEY,

    -- Objective this claim belongs to
    objective_id        TEXT        NOT NULL
        REFERENCES research_objectives (objective_id) ON DELETE CASCADE,

    -- Task whose canonical result is being rewarded
    task_id             TEXT        NOT NULL
        REFERENCES research_tasks (task_id) ON DELETE CASCADE,

    -- The canonical result row that earned this reward
    result_id           UUID        NOT NULL
        REFERENCES experiment_results (result_id) ON DELETE CASCADE,

    -- Content hash of the canonical result (denormalized for fast checks without join)
    contribution_hash   TEXT        NOT NULL,

    -- Reward recipient (miner wallet address / public key hex)
    recipient           TEXT        NOT NULL,

    -- Reward amount in uqcb (micro-QCB; 1 QCB = 1_000_000 uqcb)
    amount_uqcb         BIGINT      NOT NULL CHECK (amount_uqcb > 0),

    -- Policy version string used to compute the reward
    -- e.g. "QcbResearchRewardPolicy-v1"
    policy_version      TEXT        NOT NULL,

    -- Reward kind: 'primary' | 'replication'
    reward_kind         TEXT        NOT NULL CHECK (reward_kind IN ('primary', 'replication')),

    -- On-chain transaction ID that submitted this claim (NULL until submitted)
    tx_id               TEXT,

    -- Settlement lifecycle status
    claim_status        TEXT        NOT NULL DEFAULT 'pending'
        CHECK (claim_status IN ('pending', 'submitted', 'finalized', 'rejected')),

    -- Rejection reason (NULL unless claim_status = 'rejected')
    rejection_reason    TEXT,

    -- Timestamps
    submitted_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    finalized_at        TIMESTAMPTZ,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Enforce exactly-once payout per (objective, task, reward_kind) triple.
-- This catches duplicate settle calls before any tx hits the chain.
CREATE UNIQUE INDEX IF NOT EXISTS idx_reward_claims_task_kind
    ON research_reward_claims (task_id, reward_kind);

-- Fast lookup by objective (for settle-objective queries)
CREATE INDEX IF NOT EXISTS idx_reward_claims_objective
    ON research_reward_claims (objective_id);

-- Fast lookup by status (for finality-polling background job)
CREATE INDEX IF NOT EXISTS idx_reward_claims_status
    ON research_reward_claims (claim_status)
    WHERE claim_status IN ('pending', 'submitted');

-- Prevent result_id from being claimed under multiple reward_kinds for same task
-- (Each result can be both 'primary' and 'replication' for different tasks,
--  but within one task, only one row per kind.)
-- Already covered by idx_reward_claims_task_kind above.

COMMENT ON TABLE research_reward_claims IS
    'Tracks on-chain settlement of research rewards.  One row per (task, reward_kind).
     claim_id is deterministic so idempotent re-submission is safe after crashes.
     Never deleted; rejected claims remain for audit.';

CREATE OR REPLACE FUNCTION update_reward_claims_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_reward_claims_updated_at
    BEFORE UPDATE ON research_reward_claims
    FOR EACH ROW EXECUTE FUNCTION update_reward_claims_updated_at();
