//! Change Set E unit tests — ResearchScheduler
//!
//! All tests use `MemResearchDb` (no PostgreSQL required).
//! The SKIP LOCKED atomicity guarantee is tested against a real PostgreSQL
//! instance (integration tests, gated behind `--features integration`).

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_json::json;

    use chain_forge_research_db::{
        MemResearchDb, ResearchDb,
        models::{NewExperimentResult, NewObjective, NewTask},
    };

    use crate::{
        error::SchedulerError,
        scheduler::ResearchScheduler,
    };

    // ── helpers ───────────────────────────────────────────────────────────────

    fn make_objective(slug: &str, n_tasks: u64) -> (NewObjective, Vec<NewTask>) {
        let obj = NewObjective {
            objective_id:        format!("ch::obj::{slug}"),
            challenge_id:        "ch".to_string(),
            slug:                slug.to_string(),
            track:               "hash".to_string(),
            algorithm_version:   "sha256_v1".to_string(),
            range_start:         0,
            range_end:           n_tasks * 1_000,
            workload_class:      "cpu".to_string(),
            verification_spec:   json!({ "method": "sha256_preimage" }),
            verification_quorum: 2,
        };
        let tasks: Vec<NewTask> = (0..n_tasks)
            .map(|i| NewTask {
                task_id:         format!("{}::task::{i:016x}-{:016x}", obj.objective_id, i + 1),
                objective_id:    obj.objective_id.clone(),
                range_start:     i * 1_000,
                range_end:       (i + 1) * 1_000,
                workload_class:  "cpu".to_string(),
                input_seed:      i ^ (i + 1),
                phase:           1,
                parent_hash:     None,
                phase1_miner_id: None,
                // PoCD phase-1 task — no avalanche fields
                task_kind:       "pocd_phase1".to_string(),
                avl_seed_index:  None,
                avl_bit_index:   None,
            })
            .collect();
        (obj, tasks)
    }

    fn make_result(task_id: &str, miner: &str, gen: i64) -> NewExperimentResult {
        make_result_with_hash(task_id, miner, gen, &format!("deadbeef{gen:016x}deadbeef{gen:016x}"))
    }

    fn make_result_with_hash(task_id: &str, miner: &str, gen: i64, winning_hash: &str) -> NewExperimentResult {
        NewExperimentResult {
            task_id:           task_id.to_string(),
            receipt_id:        format!("rcpt_{miner}_{gen}"),
            miner_id:          miner.to_string(),
            content_hash:      format!("hash_{miner}_{gen}"),
            result_payload:    json!({
                "nonce":        gen,
                "winning_hash": winning_hash,
                "phase":        1,
            }),
            algorithm_version: "sha256_v1".to_string(),
            workload_version:  "1.0".to_string(),
            seal_nonce:        Some(gen as u64),
            // PoCD task — no avalanche fields
            avl_original_hash: None,
            avl_flipped_hash:  None,
            avl_xor_diff:      None,
            avl_hamming_dist:  None,
        }
    }

    async fn setup(n: u64) -> (MemResearchDb, ResearchScheduler, String) {
        let db = MemResearchDb::new();
        let (obj, tasks) = make_objective("test_obj", n);
        let obj_id = obj.objective_id.clone();
        db.insert_objective(obj).await.unwrap();
        db.upsert_tasks(tasks).await.unwrap();
        let sched = ResearchScheduler::new(Arc::new(db.clone())).with_lease_secs(60);
        (db, sched, obj_id)
    }

    // ── assign_task ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn assign_returns_task_with_lease_generation() {
        let (_db, sched, obj_id) = setup(3).await;
        let row = sched.assign_task(&obj_id, "cpu", "miner_a").await.unwrap();
        assert_eq!(row.status, "assigned");
        assert_eq!(row.lease_generation, 1);
        assert!(row.lease_expires_at.is_some());
    }

    #[tokio::test]
    async fn assign_returns_no_task_available_when_queue_is_empty() {
        let (_db, sched, obj_id) = setup(1).await;
        sched.assign_task(&obj_id, "cpu", "miner_a").await.unwrap();
        let err = sched.assign_task(&obj_id, "cpu", "miner_b").await.unwrap_err();
        assert!(matches!(err, SchedulerError::NoTaskAvailable { .. }));
    }

    // ── submit_result — happy path ────────────────────────────────────────────

    #[tokio::test]
    async fn submit_result_happy_path_transitions_task_to_submitted() {
        let (db, sched, obj_id) = setup(1).await;
        let row = sched.assign_task(&obj_id, "cpu", "miner_a").await.unwrap();
        let gen = row.lease_generation;

        sched
            .submit_result(
                &row.task_id,
                "miner_a",
                gen,
                make_result(&row.task_id, "miner_a", gen),
            )
            .await
            .unwrap();

        let updated = db.get_task(&row.task_id).await.unwrap().unwrap();
        assert_eq!(updated.status, "submitted");
        assert!(updated.lease_expires_at.is_none());
    }

    // ── submit_result — stale generation guard ────────────────────────────────

    #[tokio::test]
    async fn submit_with_wrong_generation_returns_lease_superseded() {
        let (_db, sched, obj_id) = setup(1).await;
        let row = sched.assign_task(&obj_id, "cpu", "miner_a").await.unwrap();
        let real_gen = row.lease_generation; // == 1

        let err = sched
            .submit_result(
                &row.task_id,
                "miner_a",
                real_gen + 99, // stale generation
                make_result(&row.task_id, "miner_a", real_gen),
            )
            .await
            .unwrap_err();

        assert!(
            matches!(err, SchedulerError::LeaseSuperseded { .. }),
            "expected LeaseSuperseded, got {err:?}"
        );
    }

    #[tokio::test]
    async fn evicted_miner_submission_rejected_after_reassign() {
        // Full scenario:
        //   1. miner_a holds gen=1 with a past deadline
        //   2. expiry sweep runs → task returns to available
        //   3. miner_b takes over (gen=2)
        //   4. miner_a comes back and tries to submit gen=1 → rejected
        let (_db, sched, obj_id) = setup(1).await;

        // Give miner_a a very short-lived lease
        let sched_short = ResearchScheduler::new(sched.db_ref().clone()).with_lease_secs(-1);
        let row_a = sched_short.assign_task(&obj_id, "cpu", "miner_a").await.unwrap();
        let stale_gen = row_a.lease_generation; // 1

        // Sweep now; the lease deadline is in the past
        let sched_b = ResearchScheduler::new(sched.db_ref().clone()).with_lease_secs(60);
        sched_b.expire_stale_leases().await.unwrap();

        // miner_b gets gen=2
        let row_b = sched_b.assign_task(&obj_id, "cpu", "miner_b").await.unwrap();
        assert_eq!(row_b.lease_generation, 2);

        // miner_a tries to submit with its stale gen=1
        let err = sched_b
            .submit_result(
                &row_a.task_id,
                "miner_a",
                stale_gen,
                make_result(&row_a.task_id, "miner_a", stale_gen),
            )
            .await
            .unwrap_err();

        // Expected: WrongMiner (miner_a is no longer assigned_to) OR LeaseSuperseded.
        // Either error is correct — the submission must be rejected.
        assert!(
            matches!(
                err,
                SchedulerError::WrongMiner { .. } | SchedulerError::LeaseSuperseded { .. }
            ),
            "stale miner_a submission must be rejected; got {err:?}"
        );
    }

    // ── submit_result — wrong miner guard ─────────────────────────────────────

    #[tokio::test]
    async fn submit_by_non_owner_returns_wrong_miner() {
        let (_db, sched, obj_id) = setup(1).await;
        let row = sched.assign_task(&obj_id, "cpu", "miner_a").await.unwrap();

        let err = sched
            .submit_result(
                &row.task_id,
                "miner_impostor",
                row.lease_generation,
                make_result(&row.task_id, "miner_impostor", row.lease_generation),
            )
            .await
            .unwrap_err();

        assert!(
            matches!(err, SchedulerError::WrongMiner { .. }),
            "non-owner submission must return WrongMiner; got {err:?}"
        );
    }

    // ── expire_stale_leases ───────────────────────────────────────────────────

    #[tokio::test]
    async fn expire_stale_leases_returns_count() {
        let (_db, sched, obj_id) = setup(2).await;

        // Assign two tasks with an immediate-past deadline
        let sched_short = ResearchScheduler::new(sched.db_ref().clone()).with_lease_secs(-1);
        sched_short.assign_task(&obj_id, "cpu", "m1").await.unwrap();
        sched_short.assign_task(&obj_id, "cpu", "m2").await.unwrap();

        // Sweep
        let count = sched_short.expire_stale_leases().await.unwrap();
        assert_eq!(count, 2);
    }

    // ── restart recovery ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn objectives_with_pending_work_lists_in_flight_objectives() {
        let (_db, sched, obj_id) = setup(3).await;
        sched.assign_task(&obj_id, "cpu", "m1").await.unwrap();

        let pending = sched.objectives_with_pending_work().await.unwrap();
        assert!(pending.contains(&obj_id), "in-flight objective must appear in pending list");
    }

    // ── miner registry ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn miner_registry_register_and_count() {
        let registry = crate::MinerRegistry::new();
        registry.register("m1", "cpu");
        registry.register("m2", "gpu");
        assert_eq!(registry.count(), 2);
    }

    #[tokio::test]
    async fn miner_registry_deregister() {
        let registry = crate::MinerRegistry::new();
        registry.register("m1", "cpu");
        registry.deregister("m1");
        assert_eq!(registry.count(), 0);
    }

    #[tokio::test]
    async fn miner_registry_filter_by_workload() {
        let registry = crate::MinerRegistry::new();
        registry.register("m1", "cpu");
        registry.register("m2", "cpu");
        registry.register("m3", "gpu");
        let cpu = registry.for_workload("cpu");
        assert_eq!(cpu.len(), 2);
    }

    // ── Two-phase cascade (Change Set J) ─────────────────────────────────────

    /// After a phase-1 result is submitted, a phase-2 task must be spawned.
    #[tokio::test]
    async fn phase2_task_spawned_after_phase1_submit() {
        let (db, sched, obj_id) = setup(1).await;
        let row = sched.assign_task(&obj_id, "cpu", "miner_a").await.unwrap();
        assert_eq!(row.phase, 1);
        let gen = row.lease_generation;

        // Supply a fake winning_hash (32 bytes = 64 hex chars)
        let winning_hash = "00".repeat(32); // 64 zeros — valid hex, 32 bytes
        sched
            .submit_result(
                &row.task_id,
                "miner_a",
                gen,
                make_result_with_hash(&row.task_id, "miner_a", gen, &winning_hash),
            )
            .await
            .unwrap();

        // The phase-2 task should now exist in the DB.
        let p2_id = format!("phase2-{}", row.task_id);
        let p2 = db.get_task(&p2_id).await.unwrap();
        assert!(p2.is_some(), "phase-2 task must be spawned after phase-1 submit");
        let p2 = p2.unwrap();
        assert_eq!(p2.phase, 2);
        assert_eq!(p2.parent_hash.as_deref(), Some(winning_hash.as_str()));
        assert_eq!(p2.phase1_miner_id.as_deref(), Some("miner_a"));
        assert_eq!(p2.status, "available");
    }

    /// The phase-1 miner must NOT be assigned the derived phase-2 task.
    #[tokio::test]
    async fn phase1_miner_excluded_from_phase2_assignment() {
        let (db, sched, obj_id) = setup(1).await;
        let row = sched.assign_task(&obj_id, "cpu", "miner_a").await.unwrap();
        let gen = row.lease_generation;
        let winning_hash = "00".repeat(32);

        sched
            .submit_result(
                &row.task_id,
                "miner_a",
                gen,
                make_result_with_hash(&row.task_id, "miner_a", gen, &winning_hash),
            )
            .await
            .unwrap();

        // miner_a tries to pick up the phase-2 task — must fail.
        let err = sched.assign_task(&obj_id, "cpu", "miner_a").await.unwrap_err();
        assert!(
            matches!(err, SchedulerError::NoTaskAvailable { .. }),
            "phase-1 miner must be excluded from phase-2 assignment; got {err:?}"
        );

        // miner_b can pick it up.
        let p2_row = sched.assign_task(&obj_id, "cpu", "miner_b").await.unwrap();
        assert_eq!(p2_row.phase, 2, "miner_b should receive the phase-2 task");
        assert_eq!(p2_row.parent_hash.as_deref(), Some(winning_hash.as_str()));

        // Clean up so we have a reference to db (avoids unused warning)
        let _ = db;
    }

    /// Spawning a phase-2 task twice (idempotency) must not error.
    #[tokio::test]
    async fn spawn_phase2_task_idempotent() {
        let (db, sched, obj_id) = setup(1).await;
        let row = sched.assign_task(&obj_id, "cpu", "miner_a").await.unwrap();
        let gen = row.lease_generation;
        let winning_hash = "ab".repeat(32); // 64 hex chars

        sched
            .submit_result(
                &row.task_id,
                "miner_a",
                gen,
                make_result_with_hash(&row.task_id, "miner_a", gen, &winning_hash),
            )
            .await
            .unwrap();

        // Call spawn directly a second time — must return the same task.
        let p2_again = db
            .spawn_phase2_task(&row.task_id, &winning_hash, "miner_a", 100_000)
            .await
            .unwrap();
        assert_eq!(p2_again.task_id, format!("phase2-{}", row.task_id));
        assert_eq!(p2_again.phase, 2);
    }
}

// ── ResearchScheduler private helper (test only) ──────────────────────────────

impl crate::scheduler::ResearchScheduler {
    /// Expose the `Arc<dyn ResearchDb>` for test helpers that need to build
    /// a second scheduler pointing at the same in-memory state.
    pub(crate) fn db_ref(&self) -> &std::sync::Arc<dyn chain_forge_research_db::ResearchDb> {
        &self.db
    }
}
