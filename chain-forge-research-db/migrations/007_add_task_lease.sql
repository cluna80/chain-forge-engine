-- Migration 007: task lease columns for Change Set E (Continuous Scheduling)
--
-- Adds three columns to research_tasks that the scheduler uses to track
-- which miner owns the current lease and to detect stale submissions.
--
-- lease_expires_at  — wall-clock deadline for the current assignment.
--                     NULL when status = 'available' or 'submitted'.
-- lease_generation  — monotonic counter incremented on every assign_task().
--                     A miner's submission must carry the generation it was
--                     issued; a mismatch means the task was reassigned while
--                     the miner was offline — the old submission is rejected.
--                     NOT reset on lease expiry: expiry clears the miner and
--                     the deadline but leaves the counter so the evicted
--                     miner's generation is always stale.
-- attempt_count     — running tally of how many times assign_task() has fired
--                     for this task. Useful for monitoring miner reliability.

ALTER TABLE research_tasks
    ADD COLUMN lease_expires_at  TIMESTAMPTZ,
    ADD COLUMN lease_generation  BIGINT   NOT NULL DEFAULT 0,
    ADD COLUMN attempt_count     INTEGER  NOT NULL DEFAULT 0;

COMMENT ON COLUMN research_tasks.lease_expires_at IS
    'Wall-clock deadline for the current assignment lease.
     NULL when status = ''available'' or ''submitted''.
     Set by assign_task(); cleared when the task returns to available
     (expiry) or advances to submitted.';

COMMENT ON COLUMN research_tasks.lease_generation IS
    'Monotonically incremented each time assign_task() fires for this task.
     A miner must present the generation it was issued when submitting results.
     A mismatch means the task was reassigned while the miner was silent —
     the submission is rejected without touching the current assignment.
     Intentionally NOT reset on lease expiry; only incremented on next assign.';

COMMENT ON COLUMN research_tasks.attempt_count IS
    'Running count of how many times assign_task() has been called for
     this task (i.e. how many miners have held a lease). Incremented by
     assign_task(). Available for monitoring; a high value flags miner
     reliability issues.';

-- Fast look-up for the expiry sweep:
--   "find every assigned task whose deadline has passed"
CREATE INDEX IF NOT EXISTS idx_research_tasks_lease_expires
    ON research_tasks (lease_expires_at)
    WHERE status = 'assigned';
