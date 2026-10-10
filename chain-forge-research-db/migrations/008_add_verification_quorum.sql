-- Migration 008: Add verification_quorum to research_objectives
--
-- Change Set F: Independent Verification
--
-- Each objective now carries a required quorum of independent 'reproduced'
-- verifications before a submitted result can transition to 'accepted'.
-- The default of 2 means two different miners (neither being the original
-- submitter) must independently reproduce the result before it is accepted.
--
-- 'accepted' is the ONLY status that can trigger on-chain rewards via
-- DiscoveryReceipt.  'submitted' is NOT accepted.

ALTER TABLE research_objectives
    ADD COLUMN IF NOT EXISTS verification_quorum INTEGER NOT NULL DEFAULT 2;

-- Partial index to efficiently find submitted tasks awaiting verification
CREATE INDEX IF NOT EXISTS idx_research_tasks_submitted
    ON research_tasks (objective_id, task_id)
    WHERE status = 'submitted';
