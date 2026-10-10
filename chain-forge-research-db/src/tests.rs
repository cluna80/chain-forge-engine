//! Change Set D unit tests — Research Persistence Memory
//!
//! All tests use `MemResearchDb` (no PostgreSQL required).
//! Integration tests against a real PostgreSQL instance are gated
//! behind `--features integration` and require `TEST_DATABASE_URL`.
//!
//! ## Coverage
//! - Objective CRUD and dedup
//! - Task upsert (idempotent), status transitions, listing
//! - 200-result persistence (OptiPlex + main computer simulation)
//! - Restart/recovery: objectives_with_pending_work()
//! - Deduplication: identical (task, miner, hash) rejected; different miner allowed
//! - Verification: self-verification rejected, independent verifier accepted
//! - Finding insertion (positive and negative)
//! - Artifact insertion and retrieval
//! - Full provenance chain
//! - bridge conversions: ResearchObjective → NewObjective, ResearchMicrotask → NewTask
//! - All 29 Change Set C in-memory tests still pass (verified by cargo test -p chain-forge-pocd)

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::{
        db::ResearchDb,
        mem_db::MemResearchDb,
        models::*,
    };

    // ── helpers ───────────────────────────────────────────────────────────────

    fn make_objective(challenge: &str, slug: &str, start: u64, end: u64) -> NewObjective {
        NewObjective {
            objective_id:      format!("{challenge}::obj::{slug}"),
            challenge_id:      challenge.to_string(),
            slug:              slug.to_string(),
            track:             "hash".to_string(),
            algorithm_version: "sha256_v1".to_string(),
            range_start:       start,
            range_end:         end,
            workload_class:    "cpu".to_string(),
            verification_spec: json!({ "method": "sha256_preimage" }),
        }
    }

    fn make_task(objective_id: &str, start: u64, end: u64) -> NewTask {
        NewTask {
            task_id:        format!("{objective_id}::task::{start:016x}-{end:016x}"),
            objective_id:   objective_id.to_string(),
            range_start:    start,
            range_end:      end,
            workload_class: "cpu".to_string(),
            input_seed:     start ^ end,
        }
    }

    fn make_result(task_id: &str, miner: &str, hash: &str) -> NewExperimentResult {
        NewExperimentResult {
            task_id:           task_id.to_string(),
            receipt_id:        format!("receipt_{miner}_{hash}"),
            miner_id:          miner.to_string(),
            content_hash:      hash.to_string(),
            result_payload:    json!({ "output_hash": hash }),
            algorithm_version: "sha256_v1".to_string(),
            workload_version:  "1".to_string(),
            seal_nonce:        Some(42),
        }
    }

    // ── objectives ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn insert_and_get_objective() {
        let db = MemResearchDb::new();
        let obj = make_objective("qcb::hash::HASH-001", "sha256-v1", 0, 1_000_000);
        let row = db.insert_objective(obj.clone()).await.unwrap();
        assert_eq!(row.objective_id, obj.objective_id);
        assert_eq!(row.status, "active");

        let fetched = db.get_objective(&obj.objective_id).await.unwrap().unwrap();
        assert_eq!(fetched.range_start, 0);
        assert_eq!(fetched.range_end, 1_000_000);
    }

    #[tokio::test]
    async fn duplicate_objective_rejected() {
        let db = MemResearchDb::new();
        let obj = make_objective("qcb::hash::HASH-001", "sha256-v1", 0, 1_000_000);
        db.insert_objective(obj.clone()).await.unwrap();
        let err = db.insert_objective(obj).await.unwrap_err();
        assert!(matches!(err, crate::error::ResearchDbError::Duplicate(_)));
    }

    #[tokio::test]
    async fn list_objectives_for_challenge() {
        let db = MemResearchDb::new();
        let challenge = "qcb::hash::HASH-001";
        db.insert_objective(make_objective(challenge, "slug-a", 0, 500_000)).await.unwrap();
        db.insert_objective(make_objective(challenge, "slug-b", 500_000, 1_000_000)).await.unwrap();
        db.insert_objective(make_objective("other::obj", "slug-c", 0, 100)).await.unwrap();

        let rows = db.list_objectives_for_challenge(challenge).await.unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| r.challenge_id == challenge));
    }

    #[tokio::test]
    async fn update_objective_status() {
        let db = MemResearchDb::new();
        let obj = make_objective("qcb::hash::HASH-001", "sha256-v1", 0, 1_000);
        db.insert_objective(obj.clone()).await.unwrap();
        db.update_objective_status(&obj.objective_id, "completed").await.unwrap();
        let row = db.get_objective(&obj.objective_id).await.unwrap().unwrap();
        assert_eq!(row.status, "completed");
    }

    #[tokio::test]
    async fn update_nonexistent_objective_errors() {
        let db = MemResearchDb::new();
        let err = db.update_objective_status("no-such-obj", "completed").await.unwrap_err();
        assert!(matches!(err, crate::error::ResearchDbError::NotFound(_)));
    }

    // ── tasks ─────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn upsert_tasks_idempotent() {
        let db = MemResearchDb::new();
        let obj_id = "qcb::hash::HASH-001::obj::sha256-v1";
        let tasks = vec![
            make_task(obj_id, 0, 1_000),
            make_task(obj_id, 1_000, 2_000),
        ];
        let inserted = db.upsert_tasks(tasks.clone()).await.unwrap();
        assert_eq!(inserted, 2);

        // Second upsert is a no-op
        let inserted2 = db.upsert_tasks(tasks).await.unwrap();
        assert_eq!(inserted2, 0);
    }

    #[tokio::test]
    async fn list_tasks_for_objective_ordered_by_range() {
        let db = MemResearchDb::new();
        let obj_id = "obj::test";
        let tasks = vec![
            make_task(obj_id, 2_000, 3_000),
            make_task(obj_id, 0, 1_000),
            make_task(obj_id, 1_000, 2_000),
        ];
        db.upsert_tasks(tasks).await.unwrap();
        let rows = db.list_tasks_for_objective(obj_id).await.unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].range_start, 0);
        assert_eq!(rows[1].range_start, 1_000);
        assert_eq!(rows[2].range_start, 2_000);
    }

    #[tokio::test]
    async fn update_task_status_transitions() {
        let db = MemResearchDb::new();
        let obj_id = "obj::test";
        db.upsert_tasks(vec![make_task(obj_id, 0, 1_000)]).await.unwrap();
        let task_id = make_task(obj_id, 0, 1_000).task_id;

        db.update_task_status(&task_id, "assigned", Some("miner-a"), None).await.unwrap();
        let row = db.get_task(&task_id).await.unwrap().unwrap();
        assert_eq!(row.status, "assigned");
        assert_eq!(row.assigned_to.as_deref(), Some("miner-a"));

        db.update_task_status(&task_id, "submitted", None, None).await.unwrap();
        db.update_task_status(&task_id, "accepted", None, Some("receipt-001")).await.unwrap();
        let row = db.get_task(&task_id).await.unwrap().unwrap();
        assert_eq!(row.status, "accepted");
        assert_eq!(row.settled_receipt_id.as_deref(), Some("receipt-001"));
    }

    #[tokio::test]
    async fn list_tasks_by_status() {
        let db = MemResearchDb::new();
        let obj_id = "obj::status-test";
        let tasks = (0u64..5).map(|i| make_task(obj_id, i * 1_000, (i + 1) * 1_000)).collect();
        db.upsert_tasks(tasks).await.unwrap();

        // Accept the first 3
        for i in 0u64..3 {
            let tid = make_task(obj_id, i * 1_000, (i + 1) * 1_000).task_id;
            db.update_task_status(&tid, "accepted", None, Some(&format!("r-{i}"))).await.unwrap();
        }

        let available = db.list_tasks_by_status(obj_id, "available").await.unwrap();
        assert_eq!(available.len(), 2);
        let accepted = db.list_tasks_by_status(obj_id, "accepted").await.unwrap();
        assert_eq!(accepted.len(), 3);
    }

    // ── 200-result simulation (OptiPlex + main computer) ─────────────────────

    #[tokio::test]
    async fn two_hundred_results_persist_correctly() {
        let db = MemResearchDb::new();
        let obj = make_objective("qcb::hash::HASH-001", "sha256-v1", 0, 200_000);
        db.insert_objective(obj.clone()).await.unwrap();

        // 200 tasks of 1000 units each
        let tasks: Vec<_> = (0u64..200)
            .map(|i| make_task(&obj.objective_id, i * 1_000, (i + 1) * 1_000))
            .collect();
        db.upsert_tasks(tasks.clone()).await.unwrap();

        // OptiPlex completes tasks 0-99; main computer completes tasks 100-199
        for (i, task) in tasks.iter().enumerate() {
            let miner = if i < 100 { "miner-optiplex-990" } else { "miner-main-computer" };
            let hash = format!("hash_{i:04x}");
            let result = make_result(&task.task_id, miner, &hash);
            db.insert_result(result).await.unwrap();
            db.update_task_status(&task.task_id, "accepted", Some(miner), Some(&format!("receipt-{i}"))).await.unwrap();
        }

        // Verify counts
        let total = db.count_tasks(&obj.objective_id).await.unwrap();
        let accepted = db.count_accepted_tasks(&obj.objective_id).await.unwrap();
        assert_eq!(total, 200);
        assert_eq!(accepted, 200);

        // OptiPlex submitted 100 results
        let optiplex_results = db.list_results_for_miner("miner-optiplex-990").await.unwrap();
        assert_eq!(optiplex_results.len(), 100);

        // Main computer submitted 100 results
        let main_results = db.list_results_for_miner("miner-main-computer").await.unwrap();
        assert_eq!(main_results.len(), 100);

        // No pending work remaining
        let pending = db.objectives_with_pending_work().await.unwrap();
        assert!(pending.is_empty(), "expected no pending work, got: {:?}", pending);
    }

    // ── restart/recovery ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn restart_recovery_identifies_pending_work() {
        let db = MemResearchDb::new();
        let obj_a = make_objective("qcb::hash::HASH-001", "obj-a", 0, 5_000);
        let obj_b = make_objective("qcb::hash::HASH-001", "obj-b", 0, 3_000);
        db.insert_objective(obj_a.clone()).await.unwrap();
        db.insert_objective(obj_b.clone()).await.unwrap();

        // obj_a: 5 tasks, 3 accepted, 2 still available
        let tasks_a: Vec<_> = (0u64..5).map(|i| make_task(&obj_a.objective_id, i * 1_000, (i+1)*1_000)).collect();
        db.upsert_tasks(tasks_a.clone()).await.unwrap();
        for task in &tasks_a[..3] {
            db.update_task_status(&task.task_id, "accepted", None, Some("r")).await.unwrap();
        }

        // obj_b: 3 tasks, all accepted
        let tasks_b: Vec<_> = (0u64..3).map(|i| make_task(&obj_b.objective_id, i * 1_000, (i+1)*1_000)).collect();
        db.upsert_tasks(tasks_b.clone()).await.unwrap();
        for task in &tasks_b {
            db.update_task_status(&task.task_id, "accepted", None, Some("r")).await.unwrap();
        }

        // Simulate restart: ask which objectives still have work
        let pending = db.objectives_with_pending_work().await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0], obj_a.objective_id);
    }

    #[tokio::test]
    async fn all_200_records_survive_simulated_restart() {
        // Build state in one db instance, move state to another (simulates process restart
        // with the same in-memory state — full PostgreSQL restart tested via integration feature)
        let db = std::sync::Arc::new(MemResearchDb::new());
        let obj = make_objective("qcb::hash::HASH-001", "sha256-v1", 0, 200_000);
        db.insert_objective(obj.clone()).await.unwrap();

        let tasks: Vec<_> = (0u64..200).map(|i| make_task(&obj.objective_id, i * 1_000, (i+1)*1_000)).collect();
        db.upsert_tasks(tasks.clone()).await.unwrap();
        for (i, task) in tasks.iter().enumerate() {
            let miner = if i < 100 { "miner-optiplex" } else { "miner-main" };
            db.insert_result(make_result(&task.task_id, miner, &format!("h{i}"))).await.unwrap();
            db.update_task_status(&task.task_id, "accepted", Some(miner), Some(&format!("r-{i}"))).await.unwrap();
        }

        // "Restart" — clone the Arc (same backing state; for PostgreSQL the pool reconnects)
        let db2 = db.clone();

        // All 200 records still accessible
        let total   = db2.count_tasks(&obj.objective_id).await.unwrap();
        let accepted = db2.count_accepted_tasks(&obj.objective_id).await.unwrap();
        assert_eq!(total,    200);
        assert_eq!(accepted, 200);
    }

    // ── deduplication ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn duplicate_result_same_miner_same_hash_rejected() {
        let db = MemResearchDb::new();
        let obj = make_objective("qcb::hash::HASH-001", "dedup-obj", 0, 1_000);
        db.insert_objective(obj.clone()).await.unwrap();
        let task = make_task(&obj.objective_id, 0, 1_000);
        db.upsert_tasks(vec![task.clone()]).await.unwrap();

        let r = make_result(&task.task_id, "miner-a", "deadbeef");
        db.insert_result(r.clone()).await.unwrap();

        // Same (task_id, miner_id, content_hash) → rejected
        let err = db.insert_result(r).await.unwrap_err();
        assert!(
            matches!(err, crate::error::ResearchDbError::DuplicateResult { .. }),
            "expected DuplicateResult, got {:?}", err
        );
    }

    #[tokio::test]
    async fn result_exists_probe_matches_insert() {
        let db = MemResearchDb::new();
        let obj = make_objective("qcb::hash::HASH-001", "probe-obj", 0, 1_000);
        db.insert_objective(obj.clone()).await.unwrap();
        let task = make_task(&obj.objective_id, 0, 1_000);
        db.upsert_tasks(vec![task.clone()]).await.unwrap();

        assert!(!db.result_exists(&task.task_id, "miner-a", "abc123").await.unwrap());
        db.insert_result(make_result(&task.task_id, "miner-a", "abc123")).await.unwrap();
        assert!(db.result_exists(&task.task_id, "miner-a", "abc123").await.unwrap());
    }

    #[tokio::test]
    async fn different_miner_same_hash_allowed_replication() {
        // Intentional replication: same task, same hash, different miner is PERMITTED
        let db = MemResearchDb::new();
        let obj = make_objective("qcb::hash::HASH-001", "replication-obj", 0, 1_000);
        db.insert_objective(obj.clone()).await.unwrap();
        let task = make_task(&obj.objective_id, 0, 1_000);
        db.upsert_tasks(vec![task.clone()]).await.unwrap();

        db.insert_result(make_result(&task.task_id, "miner-a", "cafebabe")).await.unwrap();
        // Different miner, same content_hash → allowed (same result, independent derivation)
        db.insert_result(make_result(&task.task_id, "miner-b", "cafebabe")).await.unwrap();

        let results = db.list_results_for_task(&task.task_id).await.unwrap();
        assert_eq!(results.len(), 2);
    }

    // ── verification records ──────────────────────────────────────────────────

    #[tokio::test]
    async fn self_verification_rejected() {
        let db = MemResearchDb::new();
        let obj = make_objective("qcb::hash::HASH-001", "self-verify-obj", 0, 1_000);
        db.insert_objective(obj.clone()).await.unwrap();
        let task = make_task(&obj.objective_id, 0, 1_000);
        db.upsert_tasks(vec![task.clone()]).await.unwrap();

        let result = db.insert_result(make_result(&task.task_id, "miner-a", "hash-x")).await.unwrap();

        let err = db.insert_verification(NewVerificationRecord {
            result_id:             result.result_id,
            task_id:               task.task_id.clone(),
            verifier_id:           "miner-a".to_string(), // same as original miner
            outcome:               "reproduced".to_string(),
            verifier_content_hash: "hash-x".to_string(),
            notes:                 None,
            verifier_receipt_id:   None,
        }).await.unwrap_err();

        assert!(
            matches!(err, crate::error::ResearchDbError::SelfVerification(_)),
            "expected SelfVerification, got {:?}", err
        );
    }

    #[tokio::test]
    async fn independent_verification_accepted() {
        let db = MemResearchDb::new();
        let obj = make_objective("qcb::hash::HASH-001", "verify-obj", 0, 1_000);
        db.insert_objective(obj.clone()).await.unwrap();
        let task = make_task(&obj.objective_id, 0, 1_000);
        db.upsert_tasks(vec![task.clone()]).await.unwrap();

        let result = db.insert_result(make_result(&task.task_id, "miner-a", "hash-y")).await.unwrap();

        let vr = db.insert_verification(NewVerificationRecord {
            result_id:             result.result_id,
            task_id:               task.task_id.clone(),
            verifier_id:           "miner-b".to_string(), // different miner
            outcome:               "reproduced".to_string(),
            verifier_content_hash: "hash-y".to_string(),
            notes:                 Some("independent reproduction confirmed".to_string()),
            verifier_receipt_id:   Some("receipt-verify-001".to_string()),
        }).await.unwrap();

        assert_eq!(vr.outcome, "reproduced");
        assert_eq!(vr.verifier_id, "miner-b");

        let verifications = db.list_verifications_for_result(result.result_id).await.unwrap();
        assert_eq!(verifications.len(), 1);
    }

    // ── findings ──────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn negative_finding_recorded() {
        let db = MemResearchDb::new();
        let obj = make_objective("qcb::hash::HASH-001", "finding-obj", 0, 10_000);
        db.insert_objective(obj.clone()).await.unwrap();

        let f = db.insert_finding(NewResearchFinding {
            objective_id: obj.objective_id.clone(),
            task_id:      None,
            finding_type: "negative_finding".to_string(),
            summary:      "Range 0-10000: no SHA-256 preimage collisions detected".to_string(),
            confidence:   Some(0.95),
            evidence_refs: serde_json::json!(["result-uuid-abc"]),
        }).await.unwrap();

        assert_eq!(f.finding_type, "negative_finding");
        assert!(!f.applied_to_objective);

        let findings = db.list_findings_for_objective(&obj.objective_id).await.unwrap();
        assert_eq!(findings.len(), 1);
    }

    #[tokio::test]
    async fn positive_discovery_recorded() {
        let db = MemResearchDb::new();
        let obj = make_objective("qcb::hash::HASH-001", "discovery-obj", 0, 10_000);
        db.insert_objective(obj.clone()).await.unwrap();

        let f = db.insert_finding(NewResearchFinding {
            objective_id: obj.objective_id.clone(),
            task_id:      None,
            finding_type: "positive_discovery".to_string(),
            summary:      "Anomalous hash distribution detected at offset 7_334".to_string(),
            confidence:   Some(0.72),
            evidence_refs: serde_json::json!([]),
        }).await.unwrap();

        assert_eq!(f.finding_type, "positive_discovery");
    }

    // ── artifacts ─────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn artifact_insert_and_retrieve() {
        let db = MemResearchDb::new();
        let obj = make_objective("qcb::hash::HASH-001", "artifact-obj", 0, 1_000);
        db.insert_objective(obj.clone()).await.unwrap();
        let task = make_task(&obj.objective_id, 0, 1_000);
        db.upsert_tasks(vec![task.clone()]).await.unwrap();
        let result = db.insert_result(make_result(&task.task_id, "miner-a", "hash-z")).await.unwrap();

        let art = db.insert_artifact(NewResearchArtifact {
            result_id:              Some(result.result_id),
            finding_id:             None,
            artifact_type:          "application/octet-stream".to_string(),
            label:                  "output_hash_array.bin".to_string(),
            content_hash:           "sha256-of-blob".to_string(),
            size_bytes:             4096,
            storage_uri:            "file:///data/research/output_hash_array.bin".to_string(),
            supersedes_artifact_id: None,
        }).await.unwrap();

        let fetched = db.get_artifact(art.artifact_id).await.unwrap().unwrap();
        assert_eq!(fetched.label, "output_hash_array.bin");
        assert_eq!(fetched.size_bytes, 4096);
    }

    // ── provenance chain ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn full_provenance_chain() {
        let db = MemResearchDb::new();
        let obj = make_objective("qcb::hash::HASH-001", "prov-obj", 0, 1_000);
        db.insert_objective(obj.clone()).await.unwrap();
        let task = make_task(&obj.objective_id, 0, 1_000);
        db.upsert_tasks(vec![task.clone()]).await.unwrap();

        let result = db.insert_result(make_result(&task.task_id, "miner-a", "hash-prov")).await.unwrap();

        db.insert_verification(NewVerificationRecord {
            result_id:             result.result_id,
            task_id:               task.task_id.clone(),
            verifier_id:           "miner-b".to_string(),
            outcome:               "reproduced".to_string(),
            verifier_content_hash: "hash-prov".to_string(),
            notes:                 None,
            verifier_receipt_id:   None,
        }).await.unwrap();

        db.insert_finding(NewResearchFinding {
            objective_id: obj.objective_id.clone(),
            task_id:      Some(task.task_id.clone()),
            finding_type: "negative_finding".to_string(),
            summary:      "No collision in range".to_string(),
            confidence:   None,
            evidence_refs: serde_json::json!([]),
        }).await.unwrap();

        db.insert_artifact(NewResearchArtifact {
            result_id:              Some(result.result_id),
            finding_id:             None,
            artifact_type:          "application/json".to_string(),
            label:                  "result.json".to_string(),
            content_hash:           "abc".to_string(),
            size_bytes:             512,
            storage_uri:            "file:///data/result.json".to_string(),
            supersedes_artifact_id: None,
        }).await.unwrap();

        let provenance = db.task_provenance(&task.task_id).await.unwrap();
        assert_eq!(provenance.objective.objective_id, obj.objective_id);
        assert_eq!(provenance.task.task_id, task.task_id);
        assert_eq!(provenance.results.len(), 1);
        assert_eq!(provenance.verifications.len(), 1);
        assert_eq!(provenance.findings.len(), 1);
        assert_eq!(provenance.artifacts.len(), 1);
    }

    #[tokio::test]
    async fn provenance_for_unknown_task_errors() {
        let db = MemResearchDb::new();
        let err = db.task_provenance("no-such-task").await.unwrap_err();
        assert!(matches!(err, crate::error::ResearchDbError::NotFound(_)));
    }

    // ── bridge: PoCD → DB DTO conversion ──────────────────────────────────────

    #[tokio::test]
    async fn bridge_research_objective_conversion() {
        use chain_forge_pocd::{ObjectiveStatus, ResearchObjective};
        use crate::models::NewObjective;

        let obj = ResearchObjective {
            objective_id:      "qcb::hash::HASH-001::obj::sha256-v1".to_string(),
            challenge_id:      "qcb::hash::HASH-001".to_string(),
            name:              "SHA-256 Collision Search".to_string(),
            algorithm_version: "sha256_v1".to_string(),
            range_start:       0,
            range_end:         1_000_000,
            verification_spec: "sha256_preimage_check".to_string(),
            status:            ObjectiveStatus::Active,
        };

        let dto = NewObjective::from(&obj);
        assert_eq!(dto.objective_id, obj.objective_id);
        assert_eq!(dto.challenge_id, obj.challenge_id);
        assert_eq!(dto.algorithm_version, obj.algorithm_version);
        assert_eq!(dto.range_start, 0);
        assert_eq!(dto.range_end, 1_000_000);
        assert_eq!(dto.slug, "sha256-v1");
    }

    #[tokio::test]
    async fn bridge_research_microtask_conversion() {
        use chain_forge_pocd::{MicrotaskStatus, ResearchMicrotask, WorkloadClass};
        use crate::models::NewTask;

        let task = ResearchMicrotask {
            task_id:           "obj::task::00000000000000-000003e8".to_string(),
            objective_id:      "qcb::hash::HASH-001::obj::sha256-v1".to_string(),
            challenge_id:      "qcb::hash::HASH-001".to_string(),
            task_start:        0,
            task_end:          1_000,
            workload_class:    WorkloadClass::Cpu,
            input_seed:        0xdeadbeef,
            verification_spec: "sha256_v1".to_string(),
            status:            MicrotaskStatus::Available,
            settled_receipt_id: None,
            assigned_to:       None,
        };

        let dto = NewTask::from(&task);
        assert_eq!(dto.task_id, task.task_id);
        assert_eq!(dto.objective_id, task.objective_id);
        assert_eq!(dto.range_start, 0);
        assert_eq!(dto.range_end, 1_000);
        assert_eq!(dto.workload_class, "cpu");
        assert_eq!(dto.input_seed, 0xdeadbeef);
    }

    // ── Change Set C still passes ─────────────────────────────────────────────

    #[tokio::test]
    async fn change_set_c_decomposition_still_deterministic() {
        // Sanity-check that adding the persistence layer hasn't broken anything in
        // chain-forge-pocd.  Full test coverage is in chain-forge-pocd's own suite.
        use chain_forge_pocd::{
            decompose_objective, DecompositionConfig, ObjectiveStatus, ResearchObjective,
            WorkloadClass,
        };

        let obj = ResearchObjective {
            objective_id:      "qcb::hash::HASH-001::obj::cs-c-check".to_string(),
            challenge_id:      "qcb::hash::HASH-001".to_string(),
            name:              "CS-C check".to_string(),
            algorithm_version: "v1".to_string(),
            range_start:       0,
            range_end:         10_000,
            verification_spec: "v1".to_string(),
            status:            ObjectiveStatus::Active,
        };

        let cfg = DecompositionConfig {
            workload_class:    WorkloadClass::Cpu,
            chunk_size_override: None,
        };
        let tasks1 = decompose_objective(&obj, &cfg).unwrap();
        let tasks2 = decompose_objective(&obj, &cfg).unwrap();
        assert_eq!(tasks1.len(), 10);
        assert_eq!(tasks1.len(), tasks2.len());
        for (a, b) in tasks1.iter().zip(tasks2.iter()) {
            assert_eq!(a.task_id, b.task_id);
            assert_eq!(a.task_start, b.task_start);
            assert_eq!(a.task_end, b.task_end);
        }
    }
}
