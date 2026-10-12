//! Change Set E / M unit tests — ResearchScheduler + VerificationEngine
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
        verification::{VerificationEngine, VerificationError, VerifyRequest},
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

    // ── Verification Engine (Change Set M) ───────────────────────────────────

    /// Helper: assign + submit a result, return (db, engine, task_id, result_id).
    async fn setup_with_submitted_result(
        n_tasks: u64,
    ) -> (MemResearchDb, VerificationEngine, String, uuid::Uuid) {
        let (db, sched, obj_id) = setup(n_tasks).await;
        let engine = VerificationEngine::new(Arc::new(db.clone()));

        let row = sched.assign_task(&obj_id, "cpu", "miner_a").await.unwrap();
        let gen = row.lease_generation;
        let winning_hash = "aa".repeat(32);

        sched
            .submit_result(
                &row.task_id,
                "miner_a",
                gen,
                make_result_with_hash(&row.task_id, "miner_a", gen, &winning_hash),
            )
            .await
            .unwrap();

        // Retrieve the result_id from the DB.
        let results = db.list_results_for_task(&row.task_id).await.unwrap();
        assert_eq!(results.len(), 1, "expected exactly one submitted result");
        let result_id = results[0].result_id;
        let content_hash = results[0].content_hash.clone();

        // Stash content_hash on a field we can access in tests via the UUID.
        // We return the raw result_id; callers must use the actual content_hash
        // from `make_result` (format: "hash_miner_a_{gen}").
        let _ = content_hash; // avoid unused warning; callers use make_result's hash formula

        (db, engine, row.task_id, result_id)
    }

    /// A single 'reproduced' verification is stored but does not trigger
    /// canonical acceptance when quorum > 1.
    #[tokio::test]
    async fn single_reproduced_verification_below_quorum() {
        let (db, engine, task_id, result_id) = setup_with_submitted_result(1).await;
        // quorum defaults to 2; one reproduced should NOT promote to canonical.
        let results = db.list_results_for_task(&task_id).await.unwrap();
        let content_hash = results[0].content_hash.clone();

        let resp = engine
            .record_verification(
                &task_id,
                VerifyRequest {
                    result_id,
                    verifier_id:          "verifier_x".to_string(),
                    outcome:              "reproduced".to_string(),
                    verifier_content_hash: content_hash,
                    signature:             None,
                    workload_version:      None,
                    submission_nonce:      None,
                    verifier_receipt_id:  None,
                    notes:                None,
                },
            )
            .await
            .unwrap();

        assert!(!resp.quorum_reached, "one reproduced should not meet quorum=2");
        assert_eq!(resp.reproduced_count, 1);
        assert_eq!(resp.quorum_required, 2);
        assert_eq!(resp.status, "submitted");
    }

    /// Two independent 'reproduced' verifications meet quorum=2 → task accepted.
    #[tokio::test]
    async fn two_reproduced_verifications_meet_quorum_and_accept_task() {
        let (db, engine, task_id, result_id) = setup_with_submitted_result(1).await;
        let results = db.list_results_for_task(&task_id).await.unwrap();
        let content_hash = results[0].content_hash.clone();

        // First verifier — below quorum.
        engine
            .record_verification(
                &task_id,
                VerifyRequest {
                    result_id,
                    verifier_id:          "verifier_x".to_string(),
                    outcome:              "reproduced".to_string(),
                    verifier_content_hash: content_hash.clone(),
                    signature:             None,
                    workload_version:      None,
                    submission_nonce:      None,
                    verifier_receipt_id:  None,
                    notes:                None,
                },
            )
            .await
            .unwrap();

        // Second verifier — meets quorum.
        let resp = engine
            .record_verification(
                &task_id,
                VerifyRequest {
                    result_id,
                    verifier_id:          "verifier_y".to_string(),
                    outcome:              "reproduced".to_string(),
                    verifier_content_hash: content_hash.clone(),
                    signature:             None,
                    workload_version:      None,
                    submission_nonce:      None,
                    verifier_receipt_id:  Some("rcpt_verifier_y_001".to_string()),
                    notes:                None,
                },
            )
            .await
            .unwrap();

        assert!(resp.quorum_reached, "second reproduced should meet quorum=2");
        assert_eq!(resp.reproduced_count, 2);
        assert_eq!(resp.status, "accepted");

        // Task must now have the canonical result set.
        let task = db.get_task(&task_id).await.unwrap().unwrap();
        assert_eq!(task.status, "accepted");
    }

    /// Self-verification must be rejected.
    #[tokio::test]
    async fn self_verification_rejected() {
        let (db, engine, task_id, result_id) = setup_with_submitted_result(1).await;
        let results = db.list_results_for_task(&task_id).await.unwrap();
        let content_hash = results[0].content_hash.clone();

        let err = engine
            .record_verification(
                &task_id,
                VerifyRequest {
                    result_id,
                    verifier_id:          "miner_a".to_string(), // same as original miner
                    outcome:              "reproduced".to_string(),
                    verifier_content_hash: content_hash,
                    signature:             None,
                    workload_version:      None,
                    submission_nonce:      None,
                    verifier_receipt_id:  None,
                    notes:                None,
                },
            )
            .await
            .unwrap_err();

        assert!(
            matches!(err, VerificationError::SelfVerification),
            "self-verification must return SelfVerification; got {err:?}"
        );
    }

    /// A 'reproduced' claim with a mismatched hash must be rejected.
    #[tokio::test]
    async fn reproduced_with_wrong_hash_rejected() {
        let (_db, engine, task_id, result_id) = setup_with_submitted_result(1).await;

        let err = engine
            .record_verification(
                &task_id,
                VerifyRequest {
                    result_id,
                    verifier_id:          "verifier_z".to_string(),
                    outcome:              "reproduced".to_string(),
                    verifier_content_hash: "totally_different_hash".to_string(),
                    signature:             None,
                    workload_version:      None,
                    submission_nonce:      None,
                    verifier_receipt_id:  None,
                    notes:                None,
                },
            )
            .await
            .unwrap_err();

        assert!(
            matches!(err, VerificationError::HashMismatch { .. }),
            "reproduced with wrong hash must return HashMismatch; got {err:?}"
        );
    }

    /// A 'rejected' verification is stored but does not advance quorum.
    #[tokio::test]
    async fn rejected_verification_stored_but_does_not_advance_quorum() {
        let (_db, engine, task_id, result_id) = setup_with_submitted_result(1).await;

        let resp = engine
            .record_verification(
                &task_id,
                VerifyRequest {
                    result_id,
                    verifier_id:          "verifier_q".to_string(),
                    outcome:              "rejected".to_string(),
                    verifier_content_hash: "divergent_hash".to_string(),
                    signature:             None,
                    workload_version:      None,
                    submission_nonce:      None,
                    verifier_receipt_id:  None,
                    notes:                Some("hash differs".to_string()),
                },
            )
            .await
            .unwrap();

        // rejected → reproduced_count stays at 0, quorum_reached = false
        assert!(!resp.quorum_reached);
        assert_eq!(resp.reproduced_count, 0);
        assert_eq!(resp.status, "submitted");
    }

    /// Supplying an unknown outcome string returns UnknownOutcome.
    #[tokio::test]
    async fn unknown_outcome_rejected() {
        let (_db, engine, task_id, result_id) = setup_with_submitted_result(1).await;

        let err = engine
            .record_verification(
                &task_id,
                VerifyRequest {
                    result_id,
                    verifier_id:          "verifier_q".to_string(),
                    outcome:              "maybe".to_string(),
                    verifier_content_hash: "x".to_string(),
                    signature:             None,
                    workload_version:      None,
                    submission_nonce:      None,
                    verifier_receipt_id:  None,
                    notes:                None,
                },
            )
            .await
            .unwrap_err();

        assert!(
            matches!(err, VerificationError::UnknownOutcome(_)),
            "unknown outcome must return UnknownOutcome; got {err:?}"
        );
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

    // ── Change Set P — Adversarial Tests (P5) ────────────────────────────────
    //
    // 14 adversarial cases covering P1 (registry), P2 (signed submissions),
    // and P3 (controller-independence quorum enforcement).
    //
    // All tests run in legacy or authenticated mode depending on whether a
    // VerifierRegistry is attached to the VerificationEngine.

    use crate::verifier_registry::{
        RegisterVerifierRequest, VerifierRegistry,
    };

    // ── P5 helper: build a VerifyRequest with signature fields populated ──────

    fn make_verify_req(
        result_id:  uuid::Uuid,
        verifier_id: &str,
        content_hash: &str,
    ) -> VerifyRequest {
        // Sentinel values: non-empty strings accepted by the test stub.
        VerifyRequest {
            result_id,
            verifier_id:           verifier_id.to_owned(),
            outcome:               "reproduced".to_owned(),
            verifier_content_hash: content_hash.to_owned(),
            signature:             Some(hex::encode(vec![0x01u8, 0x02, 0x03])),
            workload_version:      Some("test-1.0".to_owned()),
            submission_nonce:      Some("nonce-0001".to_owned()),
            verifier_receipt_id:   None,
            notes:                 None,
        }
    }

    fn make_verifier_req(id: &str, controller: &str) -> RegisterVerifierRequest {
        RegisterVerifierRequest {
            verifier_id:       id.to_owned(),
            public_key_hex:    hex::encode(vec![0xAAu8; 32]),
            controller_id:     controller.to_owned(),
            independence_group: None,
            pop_signature_hex: hex::encode(vec![0x01u8, 0x02, 0x03]),
        }
    }

    /// Build an authenticated engine + seeded registry, returning the engine
    /// and the registry for direct manipulation.
    async fn setup_authenticated(
        n_tasks: u64,
    ) -> (MemResearchDb, VerificationEngine, VerifierRegistry, String, uuid::Uuid, String) {
        let (db, sched, obj_id) = setup(n_tasks).await;

        let registry = VerifierRegistry::new();
        let engine = VerificationEngine::with_registry(
            Arc::new(db.clone()),
            registry.clone(),
            "qcb-devnet",
        );

        let row = sched.assign_task(&obj_id, "cpu", "miner_a").await.unwrap();
        let gen = row.lease_generation;
        let winning_hash = "cc".repeat(32);

        sched
            .submit_result(
                &row.task_id,
                "miner_a",
                gen,
                make_result_with_hash(&row.task_id, "miner_a", gen, &winning_hash),
            )
            .await
            .unwrap();

        let results = db.list_results_for_task(&row.task_id).await.unwrap();
        let result_id = results[0].result_id;
        let content_hash = results[0].content_hash.clone();

        (db, engine, registry, row.task_id, result_id, content_hash)
    }

    // ── P5 Test 1: Unregistered verifier is rejected ──────────────────────────

    #[tokio::test]
    async fn p5_01_unregistered_verifier_rejected() {
        let (_db, engine, _registry, task_id, result_id, content_hash) =
            setup_authenticated(1).await;

        let req = make_verify_req(result_id, "ghost_verifier", &content_hash);
        let err = engine.record_verification(&task_id, req).await.unwrap_err();

        assert!(
            matches!(err, VerificationError::UnregisteredVerifier(_)),
            "unregistered verifier must be rejected; got {err:?}"
        );
    }

    // ── P5 Test 2: Revoked verifier is rejected ───────────────────────────────

    #[tokio::test]
    async fn p5_02_revoked_verifier_rejected() {
        let (_db, engine, registry, task_id, result_id, content_hash) =
            setup_authenticated(1).await;

        // Register then immediately revoke
        registry.register(make_verifier_req("revoked_v", "org-r")).unwrap();
        registry.revoke("revoked_v").unwrap();

        let req = make_verify_req(result_id, "revoked_v", &content_hash);
        let err = engine.record_verification(&task_id, req).await.unwrap_err();

        assert!(
            matches!(err, VerificationError::UnauthorizedVerifier(_)),
            "revoked verifier must be rejected; got {err:?}"
        );
    }

    // ── P5 Test 3: Missing signature fields are rejected ──────────────────────

    #[tokio::test]
    async fn p5_03_missing_signature_fields_rejected() {
        let (_db, engine, registry, task_id, result_id, content_hash) =
            setup_authenticated(1).await;

        registry.register(make_verifier_req("v_nosig", "org-nosig")).unwrap();

        // Omit all three P2 fields
        let req = VerifyRequest {
            result_id,
            verifier_id:           "v_nosig".to_owned(),
            outcome:               "reproduced".to_owned(),
            verifier_content_hash: content_hash.clone(),
            signature:             None, // missing
            workload_version:      None, // missing
            submission_nonce:      None, // missing
            verifier_receipt_id:   None,
            notes:                 None,
        };

        let err = engine.record_verification(&task_id, req).await.unwrap_err();
        assert!(
            matches!(err, VerificationError::SignatureRequired),
            "missing signature fields must return SignatureRequired; got {err:?}"
        );
    }

    // ── P5 Test 4: Partial signature fields (only sig, no nonce) rejected ─────

    #[tokio::test]
    async fn p5_04_partial_signature_fields_rejected() {
        let (_db, engine, registry, task_id, result_id, content_hash) =
            setup_authenticated(1).await;

        registry.register(make_verifier_req("v_partial", "org-partial")).unwrap();

        // Supply signature but omit workload_version
        let req = VerifyRequest {
            result_id,
            verifier_id:           "v_partial".to_owned(),
            outcome:               "reproduced".to_owned(),
            verifier_content_hash: content_hash.clone(),
            signature:             Some(hex::encode(vec![0x01u8, 0x02, 0x03])),
            workload_version:      None, // missing
            submission_nonce:      Some("nonce-x".to_owned()),
            verifier_receipt_id:   None,
            notes:                 None,
        };

        let err = engine.record_verification(&task_id, req).await.unwrap_err();
        assert!(
            matches!(err, VerificationError::SignatureRequired),
            "partial P2 fields must return SignatureRequired; got {err:?}"
        );
    }

    // ── P5 Test 5: Invalid hex in signature rejected ──────────────────────────

    #[tokio::test]
    async fn p5_05_invalid_hex_signature_rejected() {
        let (_db, engine, registry, task_id, result_id, content_hash) =
            setup_authenticated(1).await;

        registry.register(make_verifier_req("v_badsig", "org-badsig")).unwrap();

        let req = VerifyRequest {
            result_id,
            verifier_id:           "v_badsig".to_owned(),
            outcome:               "reproduced".to_owned(),
            verifier_content_hash: content_hash.clone(),
            signature:             Some("NOT_VALID_HEX!@#$".to_owned()),
            workload_version:      Some("1.0".to_owned()),
            submission_nonce:      Some("nonce-y".to_owned()),
            verifier_receipt_id:   None,
            notes:                 None,
        };

        let err = engine.record_verification(&task_id, req).await.unwrap_err();
        assert!(
            matches!(err, VerificationError::InvalidSignature),
            "malformed hex in signature must return InvalidSignature; got {err:?}"
        );
    }

    // ── P5 Test 6: Sybil quorum blocked by same controller ───────────────────
    //
    // Two distinct verifier_ids but same controller_id — the second's
    // "reproduced" vote must not trigger canonical acceptance.

    #[tokio::test]
    async fn p5_06_sybil_quorum_same_controller_blocked() {
        let (_db, engine, registry, task_id, result_id, content_hash) =
            setup_authenticated(1).await;

        // Both verifiers controlled by the same entity
        registry.register(make_verifier_req("sybil_v1", "attacker-org")).unwrap();
        registry.register(make_verifier_req("sybil_v2", "attacker-org")).unwrap();

        // First verifier submits — no quorum yet (need 2)
        let req1 = make_verify_req(result_id, "sybil_v1", &content_hash);
        let resp1 = engine.record_verification(&task_id, req1).await.unwrap();
        assert!(!resp1.quorum_reached, "below quorum after first verifier");

        // Second verifier (same controller) submits — P3 must block
        let req2 = make_verify_req(result_id, "sybil_v2", &content_hash);
        let err = engine.record_verification(&task_id, req2).await.unwrap_err();

        assert!(
            matches!(err, VerificationError::ControllerOverlap(_)),
            "Sybil quorum (same controller) must be blocked; got {err:?}"
        );
    }

    // ── P5 Test 7: Independence-group overlap rejected ────────────────────────

    #[tokio::test]
    async fn p5_07_independence_group_overlap_rejected() {
        let (_db, engine, registry, task_id, result_id, content_hash) =
            setup_authenticated(1).await;

        // Two verifiers with different controllers but same independence_group
        let mut req_a = make_verifier_req("ig_v1", "org-c");
        req_a.independence_group = Some("lab-x".to_owned());
        let mut req_b = make_verifier_req("ig_v2", "org-d");
        req_b.independence_group = Some("lab-x".to_owned());

        registry.register(req_a).unwrap();
        registry.register(req_b).unwrap();

        // First verifier — below quorum
        let resp1 = engine
            .record_verification(&task_id, make_verify_req(result_id, "ig_v1", &content_hash))
            .await
            .unwrap();
        assert!(!resp1.quorum_reached);

        // Second verifier — same group, must be blocked by P3
        let err = engine
            .record_verification(&task_id, make_verify_req(result_id, "ig_v2", &content_hash))
            .await
            .unwrap_err();

        assert!(
            matches!(err, VerificationError::IndependenceGroupOverlap(_)),
            "independence-group overlap must be blocked; got {err:?}"
        );
    }

    // ── P5 Test 8: Miner-controller overlap rejected (verifier owns miner) ────

    #[tokio::test]
    async fn p5_08_miner_controller_overlap_rejected() {
        let (_db, engine, registry, task_id, result_id, content_hash) =
            setup_authenticated(1).await;

        // Verifier whose controller_id matches the miner's miner_id ("miner_a")
        // — simulates miner registering a verifier identity under its own controller
        let req = make_verifier_req("miner_verifier", "miner_a");
        // controller_id = "miner_a" matches result.miner_id
        registry.register(req).unwrap();

        let verify_req = make_verify_req(result_id, "miner_verifier", &content_hash);
        let err = engine.record_verification(&task_id, verify_req).await.unwrap_err();

        assert!(
            matches!(err, VerificationError::MinerVerifierOverlap { .. }),
            "verifier sharing controller with miner must be rejected; got {err:?}"
        );
    }

    // ── P5 Test 9: Legacy mode accepts submission without P2 fields ───────────
    //
    // When no registry is attached (legacy / Change Set M behaviour), the engine
    // must NOT require signature fields.

    #[tokio::test]
    async fn p5_09_legacy_mode_accepts_unsigned_submission() {
        let (db, sched, obj_id) = setup(1).await;
        // Legacy engine — no registry
        let engine = VerificationEngine::new(Arc::new(db.clone()));

        let row = sched.assign_task(&obj_id, "cpu", "miner_a").await.unwrap();
        let gen = row.lease_generation;
        let winning_hash = "dd".repeat(32);

        sched
            .submit_result(
                &row.task_id,
                "miner_a",
                gen,
                make_result_with_hash(&row.task_id, "miner_a", gen, &winning_hash),
            )
            .await
            .unwrap();

        let results = db.list_results_for_task(&row.task_id).await.unwrap();
        let result_id = results[0].result_id;
        let content_hash = results[0].content_hash.clone();

        // No signature fields — legacy engine must accept
        let req = VerifyRequest {
            result_id,
            verifier_id:           "legacy_verifier".to_owned(),
            outcome:               "reproduced".to_owned(),
            verifier_content_hash: content_hash,
            signature:             None,
            workload_version:      None,
            submission_nonce:      None,
            verifier_receipt_id:   None,
            notes:                 None,
        };

        let resp = engine.record_verification(&row.task_id, req).await.unwrap();
        assert!(!resp.quorum_reached, "below quorum after first verifier in legacy mode");
    }

    // ── P5 Test 10: Double-registration of same verifier_id rejected ──────────

    #[tokio::test]
    async fn p5_10_double_registration_rejected() {
        let registry = VerifierRegistry::new();
        registry.register(make_verifier_req("dup_v", "org-dup")).unwrap();
        let err = registry.register(make_verifier_req("dup_v", "org-other")).unwrap_err();
        assert!(
            matches!(err, crate::verifier_registry::RegistryError::AlreadyRegistered(_)),
            "double registration must be rejected; got {err:?}"
        );
    }

    // ── P5 Test 11: Empty public key in registration rejected ─────────────────

    #[tokio::test]
    async fn p5_11_empty_public_key_rejected() {
        let registry = VerifierRegistry::new();
        let req = RegisterVerifierRequest {
            verifier_id:       "v_empty_key".to_owned(),
            public_key_hex:    "".to_owned(), // invalid — empty after decode
            controller_id:     "org-x".to_owned(),
            independence_group: None,
            pop_signature_hex: hex::encode(vec![0x01u8, 0x02, 0x03]),
        };
        let err = registry.register(req).unwrap_err();
        // Empty hex decodes to empty bytes; the stub rejects empty public key
        assert!(
            matches!(
                err,
                crate::verifier_registry::RegistryError::InvalidPoP
                    | crate::verifier_registry::RegistryError::KeyDecode(_)
            ),
            "empty public key must be rejected; got {err:?}"
        );
    }

    // ── P5 Test 12: Empty signature in registration rejected ──────────────────

    #[tokio::test]
    async fn p5_12_empty_pop_signature_rejected() {
        let registry = VerifierRegistry::new();
        let req = RegisterVerifierRequest {
            verifier_id:       "v_empty_sig".to_owned(),
            public_key_hex:    hex::encode(vec![0xBBu8; 32]),
            controller_id:     "org-y".to_owned(),
            independence_group: None,
            pop_signature_hex: "".to_owned(), // empty signature
        };
        let err = registry.register(req).unwrap_err();
        assert!(
            matches!(
                err,
                crate::verifier_registry::RegistryError::InvalidPoP
                    | crate::verifier_registry::RegistryError::SigDecode(_)
            ),
            "empty PoP signature must be rejected; got {err:?}"
        );
    }

    // ── P5 Test 13: Revoked verifier re-registration is blocked ──────────────
    //
    // After revocation, the same verifier_id must not be re-registerable.
    // The controller must issue a new identity.

    #[tokio::test]
    async fn p5_13_revoked_verifier_cannot_reregister() {
        let registry = VerifierRegistry::new();
        registry.register(make_verifier_req("old_v", "org-old")).unwrap();
        registry.revoke("old_v").unwrap();

        // Attempt to re-register the same verifier_id
        let err = registry.register(make_verifier_req("old_v", "org-old")).unwrap_err();
        assert!(
            matches!(err, crate::verifier_registry::RegistryError::AlreadyRegistered(_)),
            "revoked verifier must not be re-registerable; got {err:?}"
        );
    }

    // ── P5 Test 14: Three-verifier quorum, two same controller — still blocked ──
    //
    // Even when there are more than `quorum` reproduced votes, if the set
    // that puts the count over threshold contains a controller overlap, the
    // engine must refuse canonical acceptance.

    #[tokio::test]
    async fn p5_14_three_verifiers_two_same_controller_blocked() {
        // Use a fresh objective with quorum=2 (the default from make_objective).
        let (_db, engine, registry, task_id, result_id, content_hash) =
            setup_authenticated(1).await;

        // v_good is independent; v_bad1 and v_bad2 share a controller.
        registry.register(make_verifier_req("v_good", "org-independent")).unwrap();
        registry.register(make_verifier_req("v_bad1", "attacker2")).unwrap();
        registry.register(make_verifier_req("v_bad2", "attacker2")).unwrap();

        // v_bad1 submits first — below quorum
        let r1 = engine
            .record_verification(&task_id, make_verify_req(result_id, "v_bad1", &content_hash))
            .await
            .unwrap();
        assert!(!r1.quorum_reached);

        // v_bad2 submits second (same controller as v_bad1) — P3 must block
        let err = engine
            .record_verification(&task_id, make_verify_req(result_id, "v_bad2", &content_hash))
            .await
            .unwrap_err();

        assert!(
            matches!(err, VerificationError::ControllerOverlap(_)),
            "two same-controller verifiers must not satisfy quorum; got {err:?}"
        );
    }
} // end mod tests

// ── ResearchScheduler private helper (test only) ──────────────────────────────

impl crate::scheduler::ResearchScheduler {
    /// Expose the `Arc<dyn ResearchDb>` for test helpers that need to build
    /// a second scheduler pointing at the same in-memory state.
    pub(crate) fn db_ref(&self) -> &std::sync::Arc<dyn chain_forge_research_db::ResearchDb> {
        &self.db
    }
}
