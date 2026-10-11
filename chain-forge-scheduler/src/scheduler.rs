//! `ResearchScheduler` — the core scheduling state machine.
//!
//! ## Responsibilities
//!
//! * Atomically assign tasks to miners (`assign_task`).
//! * Accept and persist miner results, guarding against stale submissions
//!   (`submit_result`).
//! * Spawn phase-2 tasks immediately after a phase-1 result is submitted
//!   (`spawn_phase2_task` called internally in `submit_result`).
//! * Sweep expired leases back to `available` (`expire_stale_leases`).
//! * Run a background ticker that fires the expiry sweep periodically
//!   (`run_expiry_loop`).
//!
//! ## Two-Phase Cascade (Change Set J)
//!
//! Phase-1 tasks are seeded by `qcb-seed` and placed in the DB as `phase = 1`.
//! When a phase-1 result is successfully submitted, `submit_result` immediately
//! calls `db.spawn_phase2_task(...)` to create the corresponding phase-2 task.
//! The scheduler then enforces the different-miner rule via `exclude_miner` in
//! `assign_task`: a miner that completed phase-1 is NEVER assigned the derived
//! phase-2 task.
//!
//! ## Consensus separation
//!
//! The scheduler is NOT on the consensus critical path.  Reward eligibility,
//! double-payment protection, and accepted-commitment enforcement remain
//! exclusively in `chain-forge-pocd::MicrotaskRegistry` (in-memory) and
//! on-chain via `DiscoveryReceipt`.
//!
//! `submit_result` transitions a task to `'submitted'`; that state is NOT
//! `'accepted'`.  Independent verification (Change Set F) converts a
//! submitted result into an accepted one.  Only accepted results can
//! trigger on-chain rewards.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use tracing::{debug, info};

use chain_forge_research_db::{
    models::{NewExperimentResult, TaskRow},
    ResearchDb,
};

use crate::error::SchedulerError;

/// Default lease duration issued by `assign_task`.
const DEFAULT_LEASE_SECS: i64 = 120;

/// Default nonce search range assigned to each phase-2 task.
///
/// Phase-2 has only 8-bit difficulty (~256 hashes expected), so a range of
/// 100 000 provides a comfortable headroom while keeping task sizes small.
const DEFAULT_PHASE2_RANGE: u64 = 100_000;

/// The scheduler.  Clone-cheap (holds an `Arc` internally).
#[derive(Clone)]
pub struct ResearchScheduler {
    pub(crate) db:   Arc<dyn ResearchDb>,
    lease_secs:      i64,
    phase2_range:    u64,
}

impl ResearchScheduler {
    /// Create a new scheduler with the given database handle.
    ///
    /// Uses `DEFAULT_LEASE_SECS` and `DEFAULT_PHASE2_RANGE` unless overridden.
    pub fn new(db: Arc<dyn ResearchDb>) -> Self {
        Self {
            db,
            lease_secs:   DEFAULT_LEASE_SECS,
            phase2_range: DEFAULT_PHASE2_RANGE,
        }
    }

    /// Override the lease duration.
    pub fn with_lease_secs(mut self, secs: i64) -> Self {
        self.lease_secs = secs;
        self
    }

    /// Override the nonce range created for each phase-2 task.
    pub fn with_phase2_range(mut self, range: u64) -> Self {
        self.phase2_range = range;
        self
    }

    /// Expose the underlying database handle — used by the seed endpoint
    /// to insert objectives and tasks directly into the scheduler's DB.
    pub fn db(&self) -> &Arc<dyn ResearchDb> {
        &self.db
    }

    // ── public API ────────────────────────────────────────────────────────────

    /// Atomically assign the next available task for the given objective and
    /// workload class to `miner_id`.
    ///
    /// Enforces the two-phase different-miner rule: the DB query skips any
    /// task whose `phase1_miner_id` equals `miner_id`, so a miner that
    /// completed phase-1 cannot be assigned the derived phase-2 task.
    ///
    /// Returns the assigned `TaskRow`, including `lease_generation` — the
    /// miner **must** include this value in its result submission.
    ///
    /// Returns `SchedulerError::NoTaskAvailable` when the queue is empty.
    pub async fn assign_task(
        &self,
        objective_id:  &str,
        workload_class: &str,
        miner_id:      &str,
    ) -> Result<TaskRow, SchedulerError> {
        let lease_expires_at = Utc::now() + chrono::Duration::seconds(self.lease_secs);

        // exclude_miner = Some(miner_id) enforces the two-phase different-miner rule.
        self.db
            .assign_task(
                objective_id,
                workload_class,
                miner_id,
                lease_expires_at,
                Some(miner_id),
            )
            .await?
            .ok_or_else(|| SchedulerError::NoTaskAvailable {
                objective_id:  objective_id.to_string(),
                workload_class: workload_class.to_string(),
            })
    }

    /// Submit a result for a task the miner was assigned.
    ///
    /// ## Stale-submission guard
    ///
    /// Before writing anything to the database this method performs three
    /// checks against the stored `TaskRow`:
    ///
    /// 1. `task.assigned_to == miner_id` — the miner must still own the lease.
    /// 2. `task.lease_generation == submitted_generation` — the generation the
    ///    miner was issued must match the stored one.  A mismatch means the
    ///    task was reassigned while the miner was silent.
    /// 3. `task.lease_expires_at > now` — the lease must not have expired.
    ///
    /// Any failure returns `SchedulerError::LeaseSuperseded` (or a related
    /// variant) and the submission is discarded without touching the database.
    ///
    /// ## Phase-2 spawning (Change Set J)
    ///
    /// When a **phase-1** result passes all guards and is persisted, this
    /// method immediately calls `db.spawn_phase2_task(...)` to queue the
    /// second hop.  The phase-2 task records `phase1_miner_id = miner_id` so
    /// the scheduler's `assign_task` can exclude that miner.
    ///
    /// The `winning_hash` for the phase-2 seed is extracted from
    /// `result.result_payload["winning_hash"]`; if it is absent (e.g. from a
    /// third-party miner that uses a different payload shape), `spawn_phase2_task`
    /// will receive an empty string and the DB's idempotency guard will still
    /// create the row, but miners will fail to solve it.  In practice the QCB
    /// miner always includes `winning_hash` in the payload.
    pub async fn submit_result(
        &self,
        task_id:              &str,
        miner_id:             &str,
        submitted_generation: i64,
        result:               NewExperimentResult,
    ) -> Result<(), SchedulerError> {
        // Fetch current task state for the pre-write checks.
        let task = self
            .db
            .get_task(task_id)
            .await?
            .ok_or_else(|| SchedulerError::NotFound(format!("task_id={task_id}")))?;

        // Guard 1 — ownership check.
        if task.assigned_to.as_deref() != Some(miner_id) {
            return Err(SchedulerError::WrongMiner {
                task_id:   task_id.to_string(),
                attempted: miner_id.to_string(),
                actual:    task.assigned_to.clone(),
            });
        }

        // Guard 2 — generation check.  This is the primary stale-submission
        // guard: even if Guard 1 passes (e.g. the same miner got reassigned),
        // the generation must match exactly.
        if task.lease_generation != submitted_generation {
            return Err(SchedulerError::LeaseSuperseded {
                task_id:   task_id.to_string(),
                expected:  task.lease_generation,
                submitted: submitted_generation,
            });
        }

        // Guard 3 — wall-clock expiry check.
        if let Some(exp) = task.lease_expires_at {
            if exp <= Utc::now() {
                return Err(SchedulerError::LeaseExpired {
                    task_id:    task_id.to_string(),
                    expired_at: exp,
                });
            }
        }

        // Capture the task phase and any winning_hash from the payload BEFORE
        // we move `result` into insert_result.
        let task_phase = task.phase;
        let winning_hash = result
            .result_payload
            .get("winning_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        // All guards passed — persist the result, then transition task status.
        self.db.insert_result(result).await?;
        self.db.submit_task_result(task_id, miner_id).await?;

        // ── Two-phase cascade: spawn phase-2 task ─────────────────────────────
        //
        // Immediately after a phase-1 result is persisted, create the derived
        // phase-2 task so the next available miner can pick it up.
        //
        // `spawn_phase2_task` is idempotent — if the phase-2 task already
        // exists (e.g. a duplicate submission race), it returns the existing row.
        if task_phase == 1 {
            let p2 = self
                .db
                .spawn_phase2_task(task_id, &winning_hash, miner_id, self.phase2_range)
                .await?;

            info!(
                parent_task_id  = task_id,
                phase2_task_id  = %p2.task_id,
                phase1_miner_id = miner_id,
                "Phase-2 task spawned — different miner required"
            );
        } else {
            debug!(task_id, phase = task_phase, "Phase-2+ result submitted (no further cascade)");
        }

        Ok(())
    }

    /// Run the expiry sweep once, returning the number of tasks returned to
    /// `'available'`.
    pub async fn expire_stale_leases(&self) -> Result<u64, SchedulerError> {
        Ok(self.db.expire_stale_leases(Utc::now()).await?)
    }

    /// Spawn a background task that runs the expiry sweep every `interval`.
    ///
    /// The task is detached (fire-and-forget); it stops automatically when the
    /// last clone of this `ResearchScheduler` is dropped.
    pub fn run_expiry_loop(self, interval: Duration) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.tick().await; // skip the first immediate tick
            loop {
                ticker.tick().await;
                match self.expire_stale_leases().await {
                    Ok(n) if n > 0 => {
                        tracing::info!(count = n, "expire_stale_leases: returned to available");
                    }
                    Ok(_) => {}
                    Err(e) => {
                        tracing::warn!(error = %e, "expire_stale_leases error");
                    }
                }
            }
        })
    }

    /// List all objectives that still have pending work.
    /// Useful on startup to rebuild the scheduling queue without manual DB queries.
    pub async fn objectives_with_pending_work(&self) -> Result<Vec<String>, SchedulerError> {
        Ok(self.db.objectives_with_pending_work().await?)
    }
}
