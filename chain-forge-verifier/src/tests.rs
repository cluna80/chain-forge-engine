//! Change Set F unit tests — VerificationEngine
//!
//! All tests use `MemResearchDb` (no PostgreSQL required).

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_json::json;
    use uuid::Uuid;

    use chain_forge_research_db::{
        MemResearchDb, ResearchDb,
        models::{NewExperimentResult, NewObjective, NewTask},
    };

    use crate::{
        engine::VerificationEngine,
        error::VerifierError,
    };

    // ── helpers ───────────────────────────────────────────────────────────────

    /// Build an objective with the given quorum requirement.
    fn make_objective(slug: &str, quorum: u32) -> NewObjective {
        NewObjective {
            objective_id:        format!("ch::obj::{slug}"),
            challenge_id:        "ch".to_string(),
            slug:                slug.to_string(),
            track:               "hash".to_string(),
            algorithm_version:   "sha256_v1".to_string(),
            range_start:         0,
            range_end:           1_000,
            workload_class:      "cpu".to_string(),
            verification_spec:   json!({ "method": "sha256_preimage" }),
            verification_quorum: quorum,
        }
    }

    fn make_task(objective_id: &str) -> NewTask {
        NewTask {
            task_id:        format!("{objective_id}::task::0000000000000000-0000000000000001"),
            objective_id:   objective_id.to_string(),
            range_start:    0,
            range_end:      1_000,
            workload_class: "cpu".to_string(),
            input_seed:     42,
        }
    }

    fn make_result(task_id: &str, miner: &str) -> NewExperimentResult {
        NewExperimentResult {
            task_id:           task_id.to_string(),
            receipt_id:        format!("rcpt_{miner}"),
            miner_id:          miner.to_string(),
            content_hash:      format!("hash_{miner}"),
            result_payload:    json!({ "nonce": 1 }),
            algorithm_version: "sha256_v1".to_string(),
            workload_version:  "1.0".to_string(),
            seal_nonce:        Some(1),
        }
    }

    /// Sets up a db + engine with one objective (quorum=`q`), one task in
    /// 'submitted' status, and one submitted result.
    ///
    /// Returns `(db, engine, objective_id, task_id, result_id, submitter_miner_id)`.
    async fn setup(quorum: u32) -> (MemResearchDb, VerificationEngine, String, String, Uuid, String) {
        let db  = MemResearchDb::new();
        let obj = make_objective("test_obj", quorum);
        let obj_id = obj.objective_id.clone();
        db.insert_objective(obj).await.unwrap();

        let task    = make_task(&obj_id);
        let task_id = task.task_id.clone();
        db.upsert_tasks(vec![task]).await.unwrap();

        // Assign, then submit (mimicking the scheduler path)
        let lease = chrono::Utc::now() + chrono::Duration::seconds(120);
        let assigned = db
            .assign_task(&obj_id, "cpu", "miner_submitter", lease)
            .await
            .unwrap()
            .unwrap();
        db.submit_task_result(&assigned.task_id, "miner_submitter")
            .await
            .unwrap();

        // Insert a result row for the submitted task
        let result_row = db
            .insert_result(make_result(&task_id, "miner_submitter"))
            .await
            .unwrap();
        let result_id = result_row.result_id;

        let engine = VerificationEngine::new(Arc::new(db.clone()));
        (db, engine, obj_id, task_id, result_id, "miner_submitter".to_string())
    }

    // ── submit_verification — happy path (quorum=1) ───────────────────────────

    #[tokio::test]
    async fn single_verifier_meets_quorum_of_one() {
        let (db, engine, _obj_id, task_id, result_id, _submitter) = setup(1).await;

        let accepted = engine
            .submit_verification(
                &task_id, result_id, "verifier_a",
                "reproduced", "hash_verifier_a", None, None,
            )
            .await
            .unwrap();

        assert!(accepted, "quorum=1 should be met after one 'reproduced' verification");

        // Verify the task and result are now 'accepted' in the DB
        let t = db.get_task(&task_id).await.unwrap().unwrap();
        assert_eq!(t.status, "accepted");

        let r = db.get_result(result_id).await.unwrap().unwrap();
        assert_eq!(r.result_status, "accepted");
    }

    // ── submit_verification — quorum=2 requires two reproducers ──────────────

    #[tokio::test]
    async fn two_verifiers_meet_quorum_of_two() {
        let (db, engine, _obj_id, task_id, result_id, _submitter) = setup(2).await;

        // First verifier: quorum not yet met
        let first = engine
            .submit_verification(
                &task_id, result_id, "verifier_a",
                "reproduced", "hash_v_a", None, None,
            )
            .await
            .unwrap();
        assert!(!first, "first verification should not yet meet quorum=2");

        // Task still 'submitted'
        assert_eq!(
            db.get_task(&task_id).await.unwrap().unwrap().status,
            "submitted"
        );

        // Second verifier: quorum met
        let second = engine
            .submit_verification(
                &task_id, result_id, "verifier_b",
                "reproduced", "hash_v_b", None, None,
            )
            .await
            .unwrap();
        assert!(second, "second 'reproduced' verification should meet quorum=2");

        assert_eq!(
            db.get_task(&task_id).await.unwrap().unwrap().status,
            "accepted"
        );
    }

    // ── diverged votes do NOT count toward quorum ─────────────────────────────

    #[tokio::test]
    async fn diverged_vote_does_not_advance_quorum() {
        let (db, engine, _obj_id, task_id, result_id, _submitter) = setup(2).await;

        // One diverged + one reproduced: quorum=2 not met
        engine
            .submit_verification(
                &task_id, result_id, "verifier_a",
                "diverged", "hash_v_a", None, None,
            )
            .await
            .unwrap();

        let accepted = engine
            .submit_verification(
                &task_id, result_id, "verifier_b",
                "reproduced", "hash_v_b", None, None,
            )
            .await
            .unwrap();

        assert!(!accepted, "1 reproduced + 1 diverged should not meet quorum=2");
        assert_eq!(
            db.get_task(&task_id).await.unwrap().unwrap().status,
            "submitted"
        );
    }

    // ── self-verification is rejected ─────────────────────────────────────────

    #[tokio::test]
    async fn self_verification_returns_error() {
        let (_db, engine, _obj_id, task_id, result_id, submitter) = setup(2).await;

        let err = engine
            .submit_verification(
                &task_id, result_id, &submitter,
                "reproduced", "hash_self", None, None,
            )
            .await
            .unwrap_err();

        assert!(
            matches!(err, VerifierError::SelfVerification(_)),
            "submitter verifying own result must return SelfVerification; got {err:?}"
        );
    }

    // ── duplicate verification from same verifier ─────────────────────────────

    #[tokio::test]
    async fn duplicate_verifier_submission_rejected() {
        let (_db, engine, _obj_id, task_id, result_id, _submitter) = setup(2).await;

        engine
            .submit_verification(
                &task_id, result_id, "verifier_a",
                "reproduced", "hash_v_a", None, None,
            )
            .await
            .unwrap();

        let err = engine
            .submit_verification(
                &task_id, result_id, "verifier_a",
                "reproduced", "hash_v_a_again", None, None,
            )
            .await
            .unwrap_err();

        assert!(
            matches!(err, VerifierError::DuplicateVerification { .. }),
            "second submission from same verifier must return DuplicateVerification; got {err:?}"
        );
    }

    // ── invalid outcome string ────────────────────────────────────────────────

    #[tokio::test]
    async fn invalid_outcome_returns_error() {
        let (_db, engine, _obj_id, task_id, result_id, _submitter) = setup(2).await;

        let err = engine
            .submit_verification(
                &task_id, result_id, "verifier_a",
                "CONFIRMED", // invalid
                "hash_v_a", None, None,
            )
            .await
            .unwrap_err();

        assert!(
            matches!(err, VerifierError::InvalidOutcome(_)),
            "unrecognised outcome must return InvalidOutcome; got {err:?}"
        );
    }

    // ── already accepted task ─────────────────────────────────────────────────

    #[tokio::test]
    async fn verification_on_already_accepted_task_returns_error() {
        let (_db, engine, _obj_id, task_id, result_id, _submitter) = setup(1).await;

        // Accept with first verifier
        engine
            .submit_verification(
                &task_id, result_id, "verifier_a",
                "reproduced", "hash_v_a", None, None,
            )
            .await
            .unwrap();

        // Try a second verification on the now-accepted task
        let err = engine
            .submit_verification(
                &task_id, result_id, "verifier_b",
                "reproduced", "hash_v_b", None, None,
            )
            .await
            .unwrap_err();

        assert!(
            matches!(err, VerifierError::AlreadyAccepted { .. }),
            "verifying an accepted task must return AlreadyAccepted; got {err:?}"
        );
    }

    // ── task not in submitted status ──────────────────────────────────────────

    #[tokio::test]
    async fn verification_on_unsubmitted_task_returns_error() {
        let db  = MemResearchDb::new();
        let obj = make_objective("not_submitted_obj", 2);
        let obj_id = obj.objective_id.clone();
        db.insert_objective(obj).await.unwrap();
        let task = make_task(&obj_id);
        let task_id = task.task_id.clone();
        db.upsert_tasks(vec![task]).await.unwrap();
        // Task is still 'available' — no assignment done

        let result_row = db
            .insert_result(make_result(&task_id, "miner_submitter"))
            .await
            .unwrap();

        let engine = VerificationEngine::new(Arc::new(db));
        let err = engine
            .submit_verification(
                &task_id, result_row.result_id, "verifier_a",
                "reproduced", "hash_v_a", None, None,
            )
            .await
            .unwrap_err();

        assert!(
            matches!(err, VerifierError::TaskNotSubmitted { .. }),
            "verifying an available task must return TaskNotSubmitted; got {err:?}"
        );
    }

    // ── list_submitted_tasks ──────────────────────────────────────────────────

    #[tokio::test]
    async fn list_submitted_shows_pending_tasks() {
        let (_db, engine, obj_id, task_id, _result_id, _submitter) = setup(2).await;

        let pending = engine.list_submitted_tasks(&obj_id).await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].task_id, task_id);
    }

    #[tokio::test]
    async fn list_submitted_is_empty_after_acceptance() {
        let (_db, engine, obj_id, task_id, result_id, _submitter) = setup(1).await;

        engine
            .submit_verification(
                &task_id, result_id, "verifier_a",
                "reproduced", "hash_v_a", None, None,
            )
            .await
            .unwrap();

        let pending = engine.list_submitted_tasks(&obj_id).await.unwrap();
        assert!(pending.is_empty(), "accepted task must not appear in submitted list");
    }

    // ── verification_quorum is per-objective ──────────────────────────────────

    #[tokio::test]
    async fn quorum_is_read_from_objective() {
        // Two objectives with different quorums sharing the same engine+db.
        let db = MemResearchDb::new();

        // Objective A: quorum=1
        let obj_a = make_objective("obj_a", 1);
        let obj_a_id = obj_a.objective_id.clone();
        db.insert_objective(obj_a).await.unwrap();
        let task_a = make_task(&obj_a_id);
        let task_a_id = task_a.task_id.clone();
        db.upsert_tasks(vec![task_a]).await.unwrap();

        // Objective B: quorum=3
        let obj_b = make_objective("obj_b", 3);
        let obj_b_id = obj_b.objective_id.clone();
        db.insert_objective(obj_b).await.unwrap();
        let task_b = make_task(&obj_b_id);
        let task_b_id = task_b.task_id.clone();
        db.upsert_tasks(vec![task_b]).await.unwrap();

        // Submit both tasks
        let lease = chrono::Utc::now() + chrono::Duration::seconds(120);
        let a_assigned = db.assign_task(&obj_a_id, "cpu", "miner_a", lease).await.unwrap().unwrap();
        db.submit_task_result(&a_assigned.task_id, "miner_a").await.unwrap();
        let result_a = db.insert_result(make_result(&task_a_id, "miner_a")).await.unwrap();

        let b_assigned = db.assign_task(&obj_b_id, "cpu", "miner_b", lease).await.unwrap().unwrap();
        db.submit_task_result(&b_assigned.task_id, "miner_b").await.unwrap();
        let result_b = db.insert_result(make_result(&task_b_id, "miner_b")).await.unwrap();

        let engine = VerificationEngine::new(Arc::new(db.clone()));

        // One reproduced verification on A → accepted (quorum=1)
        let a_accepted = engine
            .submit_verification(&task_a_id, result_a.result_id, "v1", "reproduced", "h1", None, None)
            .await
            .unwrap();
        assert!(a_accepted, "objective A (quorum=1) should be accepted after 1 reproduced");

        // Two reproduced verifications on B → still not accepted (quorum=3)
        let b1 = engine
            .submit_verification(&task_b_id, result_b.result_id, "v1", "reproduced", "h1", None, None)
            .await
            .unwrap();
        assert!(!b1);
        let b2 = engine
            .submit_verification(&task_b_id, result_b.result_id, "v2", "reproduced", "h2", None, None)
            .await
            .unwrap();
        assert!(!b2, "objective B (quorum=3) should not be accepted after 2 reproduced");
        assert_eq!(
            db.get_task(&task_b_id).await.unwrap().unwrap().status,
            "submitted"
        );
    }
}

// ── VerificationEngine private helper (test only) ─────────────────────────────

impl crate::engine::VerificationEngine {
    /// Expose the `Arc<dyn ResearchDb>` for test helpers that need to build
    /// a second engine pointing at the same in-memory state.
    pub(crate) fn db_ref(&self) -> &std::sync::Arc<dyn chain_forge_research_db::ResearchDb> {
        &self.db
    }
}
