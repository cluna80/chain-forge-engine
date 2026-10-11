//! Change Set G unit tests — AnalysisEngine + AnomalyDetector
//!
//! All tests use `MemResearchDb` (no PostgreSQL required).

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_json::json;
    use uuid::Uuid;

    use chain_forge_research_db::{
        MemResearchDb, ResearchDb,
        models::{NewExperimentResult, NewObjective, NewResearchFinding, NewTask, NewVerificationRecord},
    };

    use crate::{
        AnalysisEngine, AnomalyConfig,
        report::Anomaly,
    };

    // ── helpers ───────────────────────────────────────────────────────────────

    fn make_objective(slug: &str) -> NewObjective {
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
            verification_quorum: 2,
        }
    }

    fn make_task(objective_id: &str, idx: u64) -> NewTask {
        NewTask {
            task_id:         format!("{objective_id}::task::{idx:016x}-{:016x}", idx + 1),
            objective_id:    objective_id.to_string(),
            range_start:     idx * 100,
            range_end:       idx * 100 + 100,
            workload_class:  "cpu".to_string(),
            input_seed:      idx,
            phase:           1,
            parent_hash:     None,
            phase1_miner_id: None,
        }
    }

    fn make_result(task_id: &str, miner: &str, hash: &str) -> NewExperimentResult {
        NewExperimentResult {
            task_id:           task_id.to_string(),
            receipt_id:        format!("rcpt_{miner}"),
            miner_id:          miner.to_string(),
            content_hash:      hash.to_string(),
            result_payload:    json!({ "nonce": 1 }),
            algorithm_version: "sha256_v1".to_string(),
            workload_version:  "1.0".to_string(),
            seal_nonce:        Some(1),
        }
    }

    fn make_verification(result_id: Uuid, task_id: &str, verifier: &str, outcome: &str) -> NewVerificationRecord {
        NewVerificationRecord {
            result_id,
            task_id:             task_id.to_string(),
            verifier_id:         verifier.to_string(),
            outcome:             outcome.to_string(),
            verifier_content_hash: format!("vh_{verifier}"),
            notes:               None,
            verifier_receipt_id: None,
        }
    }

    /// Set up a fully accepted task (available → assigned → submitted → accepted).
    async fn setup_accepted_task(
        db:           &MemResearchDb,
        objective_id: &str,
        miner:        &str,
    ) -> (String, Uuid) {
        let task = make_task(objective_id, 0);
        let task_id = task.task_id.clone();
        db.upsert_tasks(vec![task]).await.unwrap();

        let lease = chrono::Utc::now() + chrono::Duration::seconds(120);
        let assigned = db
            .assign_task(objective_id, "cpu", miner, lease, None)
            .await
            .unwrap()
            .unwrap();
        db.submit_task_result(&assigned.task_id, miner).await.unwrap();

        let result = db.insert_result(make_result(&task_id, miner, &format!("hash_{miner}"))).await.unwrap();
        let result_id = result.result_id;

        // Two reproduced verifications → quorum=2 → accepted
        db.insert_verification(make_verification(result_id, &task_id, "v1", "reproduced")).await.unwrap();
        db.insert_verification(make_verification(result_id, &task_id, "v2", "reproduced")).await.unwrap();
        db.accept_task(&task_id, result_id).await.unwrap();

        (task_id, result_id)
    }

    // ── generate_report — basic shape ─────────────────────────────────────────

    #[tokio::test]
    async fn generate_report_returns_correct_counts() {
        let db = MemResearchDb::new();
        let obj = make_objective("basic");
        let obj_id = obj.objective_id.clone();
        db.insert_objective(obj).await.unwrap();

        setup_accepted_task(&db, &obj_id, "miner_a").await;

        let engine = AnalysisEngine::new(Arc::new(db));
        let report = engine.generate_report(&obj_id).await.unwrap();

        assert_eq!(report.total_tasks, 1);
        assert_eq!(report.accepted_tasks, 1);
        assert_eq!(report.completion_rate, Some(1.0));
        assert_eq!(report.total_results, 1);
        assert_eq!(report.reproduced_count, 2);
        assert_eq!(report.diverged_count, 0);
        assert_eq!(report.unique_miners, 1);
    }

    // ── get_report — round-trip through persistence ───────────────────────────

    #[tokio::test]
    async fn get_report_round_trips_persisted_data() {
        let db = MemResearchDb::new();
        let obj = make_objective("persist");
        let obj_id = obj.objective_id.clone();
        db.insert_objective(obj).await.unwrap();
        setup_accepted_task(&db, &obj_id, "miner_b").await;

        let engine = AnalysisEngine::new(Arc::new(db));
        let generated = engine.generate_report(&obj_id).await.unwrap();
        let fetched   = engine.get_report(&obj_id).await.unwrap();

        assert_eq!(generated.objective_id, fetched.objective_id);
        assert_eq!(generated.accepted_tasks, fetched.accepted_tasks);
        assert_eq!(generated.total_results, fetched.total_results);
    }

    // ── get_report — not found before analyze ────────────────────────────────

    #[tokio::test]
    async fn get_report_errors_before_first_analyze() {
        let db = MemResearchDb::new();
        let obj = make_objective("noreport");
        let obj_id = obj.objective_id.clone();
        db.insert_objective(obj).await.unwrap();

        let engine = AnalysisEngine::new(Arc::new(db));
        let err = engine.get_report(&obj_id).await.unwrap_err();
        assert!(
            matches!(err, crate::IntelligenceError::ReportNotFound(_)),
            "expected ReportNotFound before first analyze; got {err:?}"
        );
    }

    // ── completion_rate edge case: zero tasks ─────────────────────────────────

    #[tokio::test]
    async fn completion_rate_is_none_when_no_tasks() {
        let db = MemResearchDb::new();
        let obj = make_objective("empty");
        let obj_id = obj.objective_id.clone();
        db.insert_objective(obj).await.unwrap();

        let engine = AnalysisEngine::new(Arc::new(db));
        let report = engine.generate_report(&obj_id).await.unwrap();

        assert_eq!(report.total_tasks, 0);
        assert!(report.completion_rate.is_none(), "no tasks → completion_rate must be None");
        assert!(report.verifier_agreement.is_none());
    }

    // ── miner_contributions ordering ──────────────────────────────────────────

    #[tokio::test]
    async fn miner_contributions_ordered_by_accepted_desc() {
        let db = MemResearchDb::new();
        let obj = make_objective("miners");
        let obj_id = obj.objective_id.clone();
        db.insert_objective(obj).await.unwrap();

        // miner_a gets 1 accepted task
        let task_a = make_task(&obj_id, 0);
        let task_a_id = task_a.task_id.clone();
        db.upsert_tasks(vec![task_a]).await.unwrap();
        let lease = chrono::Utc::now() + chrono::Duration::seconds(120);
        let a_assigned = db.assign_task(&obj_id, "cpu", "miner_a", lease, None).await.unwrap().unwrap();
        db.submit_task_result(&a_assigned.task_id, "miner_a").await.unwrap();
        let r_a = db.insert_result(make_result(&task_a_id, "miner_a", "hash_a")).await.unwrap();
        db.insert_verification(make_verification(r_a.result_id, &task_a_id, "v1", "reproduced")).await.unwrap();
        db.insert_verification(make_verification(r_a.result_id, &task_a_id, "v2", "reproduced")).await.unwrap();
        db.accept_task(&task_a_id, r_a.result_id).await.unwrap();

        // miner_b submits but never gets accepted (submitted only)
        let task_b = make_task(&obj_id, 1);
        let task_b_id = task_b.task_id.clone();
        db.upsert_tasks(vec![task_b]).await.unwrap();
        let b_assigned = db.assign_task(&obj_id, "cpu", "miner_b", lease, None).await.unwrap().unwrap();
        db.submit_task_result(&b_assigned.task_id, "miner_b").await.unwrap();
        db.insert_result(make_result(&task_b_id, "miner_b", "hash_b")).await.unwrap();

        let engine = AnalysisEngine::new(Arc::new(db));
        let report = engine.generate_report(&obj_id).await.unwrap();

        assert_eq!(report.miner_contributions.len(), 2);
        // miner_a has 1 accepted → should be first
        assert_eq!(report.miner_contributions[0].miner_id, "miner_a");
        assert_eq!(report.miner_contributions[0].results_accepted, 1);
        assert_eq!(report.miner_contributions[1].miner_id, "miner_b");
        assert_eq!(report.miner_contributions[1].results_accepted, 0);
    }

    // ── high-confidence findings ──────────────────────────────────────────────

    #[tokio::test]
    async fn high_confidence_findings_filtered_correctly() {
        let db = MemResearchDb::new();
        let obj = make_objective("findings");
        let obj_id = obj.objective_id.clone();
        db.insert_objective(obj).await.unwrap();

        // Insert three findings: high (0.9), medium (0.6), none (null)
        db.insert_finding(chain_forge_research_db::models::NewResearchFinding {
            objective_id:  obj_id.clone(),
            task_id:       None,
            finding_type:  "positive".to_string(),
            summary:       "High confidence find".to_string(),
            confidence:    Some(0.9),
            evidence_refs: json!([]),
        }).await.unwrap();
        db.insert_finding(chain_forge_research_db::models::NewResearchFinding {
            objective_id:  obj_id.clone(),
            task_id:       None,
            finding_type:  "positive".to_string(),
            summary:       "Medium confidence find".to_string(),
            confidence:    Some(0.6),
            evidence_refs: json!([]),
        }).await.unwrap();
        db.insert_finding(chain_forge_research_db::models::NewResearchFinding {
            objective_id:  obj_id.clone(),
            task_id:       None,
            finding_type:  "negative".to_string(),
            summary:       "No confidence".to_string(),
            confidence:    None,
            evidence_refs: json!([]),
        }).await.unwrap();

        let engine = AnalysisEngine::new(Arc::new(db));
        let report = engine.generate_report(&obj_id).await.unwrap();

        // Only the 0.9 finding should appear in high_confidence_findings
        assert_eq!(report.high_confidence_findings.len(), 1);
        assert_eq!(report.high_confidence_findings[0].summary, "High confidence find");
        // But total_findings counts all 3
        assert_eq!(report.total_findings, 3);
    }

    // ── anomaly: hash collision ───────────────────────────────────────────────

    #[tokio::test]
    async fn anomaly_detects_hash_collision() {
        let db = MemResearchDb::new();
        let obj = make_objective("collision");
        let obj_id = obj.objective_id.clone();
        db.insert_objective(obj).await.unwrap();

        let task = make_task(&obj_id, 0);
        let task_id = task.task_id.clone();
        db.upsert_tasks(vec![task]).await.unwrap();

        // Two different miners submit the same content_hash
        let lease = chrono::Utc::now() + chrono::Duration::seconds(120);
        let assigned = db.assign_task(&obj_id, "cpu", "miner_a", lease, None).await.unwrap().unwrap();
        db.submit_task_result(&assigned.task_id, "miner_a").await.unwrap();
        db.insert_result(make_result(&task_id, "miner_a", "SAME_HASH")).await.unwrap();

        // miner_b submits same hash for the same task (simulate direct insert)
        db.insert_result(NewExperimentResult {
            task_id:           task_id.clone(),
            receipt_id:        "rcpt_miner_b".to_string(),
            miner_id:          "miner_b".to_string(),
            content_hash:      "SAME_HASH".to_string(),
            result_payload:    json!({ "nonce": 1 }),
            algorithm_version: "sha256_v1".to_string(),
            workload_version:  "1.0".to_string(),
            seal_nonce:        Some(1),
        }).await.unwrap();

        let engine = AnalysisEngine::new(Arc::new(db));
        let anomalies = engine.detect_anomalies(&obj_id).await.unwrap();

        let collision = anomalies.iter().find(|a| matches!(a, Anomaly::HashCollision { .. }));
        assert!(collision.is_some(), "expected HashCollision anomaly");
        if let Some(Anomaly::HashCollision { miner_ids, content_hash, .. }) = collision {
            assert_eq!(content_hash, "SAME_HASH");
            assert!(miner_ids.contains(&"miner_a".to_string()));
            assert!(miner_ids.contains(&"miner_b".to_string()));
        }
    }

    // ── anomaly: divergence storm ─────────────────────────────────────────────

    #[tokio::test]
    async fn anomaly_detects_divergence_storm() {
        let db = MemResearchDb::new();
        let obj = make_objective("diverge");
        let obj_id = obj.objective_id.clone();
        db.insert_objective(obj).await.unwrap();

        let task = make_task(&obj_id, 0);
        let task_id = task.task_id.clone();
        db.upsert_tasks(vec![task]).await.unwrap();

        let lease = chrono::Utc::now() + chrono::Duration::seconds(120);
        let assigned = db.assign_task(&obj_id, "cpu", "miner_a", lease, None).await.unwrap().unwrap();
        db.submit_task_result(&assigned.task_id, "miner_a").await.unwrap();
        let result = db.insert_result(make_result(&task_id, "miner_a", "hash_a")).await.unwrap();

        // 1 reproduced, 2 diverged → storm
        db.insert_verification(make_verification(result.result_id, &task_id, "v1", "reproduced")).await.unwrap();
        db.insert_verification(make_verification(result.result_id, &task_id, "v2", "diverged")).await.unwrap();
        db.insert_verification(make_verification(result.result_id, &task_id, "v3", "diverged")).await.unwrap();

        let engine = AnalysisEngine::new(Arc::new(db));
        let anomalies = engine.detect_anomalies(&obj_id).await.unwrap();

        let storm = anomalies.iter().find(|a| matches!(a, Anomaly::DivergenceStorm { .. }));
        assert!(storm.is_some(), "expected DivergenceStorm anomaly");
        if let Some(Anomaly::DivergenceStorm { diverged_count, reproduced_count, .. }) = storm {
            assert_eq!(*diverged_count, 2);
            assert_eq!(*reproduced_count, 1);
        }
    }

    // ── anomaly: low verifier agreement ──────────────────────────────────────

    #[tokio::test]
    async fn anomaly_detects_low_verifier_agreement() {
        let db = MemResearchDb::new();
        let obj = make_objective("low_agree");
        let obj_id = obj.objective_id.clone();
        db.insert_objective(obj).await.unwrap();

        let task = make_task(&obj_id, 0);
        let task_id = task.task_id.clone();
        db.upsert_tasks(vec![task]).await.unwrap();

        let lease = chrono::Utc::now() + chrono::Duration::seconds(120);
        let assigned = db.assign_task(&obj_id, "cpu", "miner_a", lease, None).await.unwrap().unwrap();
        db.submit_task_result(&assigned.task_id, "miner_a").await.unwrap();
        let result = db.insert_result(make_result(&task_id, "miner_a", "hash_a")).await.unwrap();

        // 0 reproduced, 2 diverged → agreement = 0.0 < 0.5 threshold
        db.insert_verification(make_verification(result.result_id, &task_id, "v1", "diverged")).await.unwrap();
        db.insert_verification(make_verification(result.result_id, &task_id, "v2", "diverged")).await.unwrap();

        let engine = AnalysisEngine::new(Arc::new(db));
        let anomalies = engine.detect_anomalies(&obj_id).await.unwrap();

        let low = anomalies.iter().find(|a| matches!(a, Anomaly::LowVerifierAgreement { .. }));
        assert!(low.is_some(), "expected LowVerifierAgreement anomaly");
    }

    // ── anomaly: stall detected ───────────────────────────────────────────────

    #[tokio::test]
    async fn anomaly_detects_stall() {
        let db = MemResearchDb::new();
        let obj = make_objective("stall");
        let obj_id = obj.objective_id.clone();
        db.insert_objective(obj).await.unwrap();

        // Add tasks but never accept any
        let task = make_task(&obj_id, 0);
        db.upsert_tasks(vec![task]).await.unwrap();
        // Task stays 'available' — no assignment done

        let engine = AnalysisEngine::new(Arc::new(db));
        let anomalies = engine.detect_anomalies(&obj_id).await.unwrap();

        let stall = anomalies.iter().find(|a| matches!(a, Anomaly::StallDetected { .. }));
        assert!(stall.is_some(), "expected StallDetected anomaly for objective with no accepted tasks");
    }

    // ── no anomalies on healthy objective ─────────────────────────────────────

    #[tokio::test]
    async fn no_anomalies_on_clean_objective() {
        let db = MemResearchDb::new();
        let obj = make_objective("clean");
        let obj_id = obj.objective_id.clone();
        db.insert_objective(obj).await.unwrap();
        setup_accepted_task(&db, &obj_id, "miner_a").await;

        let engine = AnalysisEngine::new(Arc::new(db));
        let anomalies = engine.detect_anomalies(&obj_id).await.unwrap();

        assert!(
            anomalies.is_empty(),
            "expected no anomalies on a healthy objective; got: {anomalies:?}"
        );
    }

    // ── objective not found ───────────────────────────────────────────────────

    #[tokio::test]
    async fn generate_report_on_unknown_objective_errors() {
        let db = MemResearchDb::new();
        let engine = AnalysisEngine::new(Arc::new(db));
        let err = engine.generate_report("does::not::exist").await.unwrap_err();
        assert!(
            matches!(err, crate::IntelligenceError::ObjectiveNotFound(_)),
            "expected ObjectiveNotFound; got {err:?}"
        );
    }

    // ── verifier_agreement calculation ───────────────────────────────────────

    #[tokio::test]
    async fn verifier_agreement_is_correct() {
        let db = MemResearchDb::new();
        let obj = make_objective("agreement");
        let obj_id = obj.objective_id.clone();
        db.insert_objective(obj).await.unwrap();

        let task = make_task(&obj_id, 0);
        let task_id = task.task_id.clone();
        db.upsert_tasks(vec![task]).await.unwrap();

        let lease = chrono::Utc::now() + chrono::Duration::seconds(120);
        let assigned = db.assign_task(&obj_id, "cpu", "miner_a", lease, None).await.unwrap().unwrap();
        db.submit_task_result(&assigned.task_id, "miner_a").await.unwrap();
        let result = db.insert_result(make_result(&task_id, "miner_a", "hash_a")).await.unwrap();

        // 2 reproduced, 2 diverged → agreement for this result = 0.5
        db.insert_verification(make_verification(result.result_id, &task_id, "v1", "reproduced")).await.unwrap();
        db.insert_verification(make_verification(result.result_id, &task_id, "v2", "reproduced")).await.unwrap();
        db.insert_verification(make_verification(result.result_id, &task_id, "v3", "diverged")).await.unwrap();
        db.insert_verification(make_verification(result.result_id, &task_id, "v4", "diverged")).await.unwrap();

        let engine = AnalysisEngine::new(Arc::new(db));
        let report = engine.generate_report(&obj_id).await.unwrap();

        let agreement = report.verifier_agreement.expect("should have verifier_agreement");
        // 2/4 = 0.5 exactly
        assert!(
            (agreement - 0.5).abs() < 1e-9,
            "expected verifier_agreement=0.5, got {agreement}"
        );
    }

    // ── report is regenerated (upsert) ───────────────────────────────────────

    #[tokio::test]
    async fn report_is_updated_on_re_analyze() {
        let db = MemResearchDb::new();
        let obj = make_objective("regen");
        let obj_id = obj.objective_id.clone();
        db.insert_objective(obj).await.unwrap();

        // First pass: no tasks
        let engine = AnalysisEngine::new(Arc::new(db.clone()));
        let r1 = engine.generate_report(&obj_id).await.unwrap();
        assert_eq!(r1.total_tasks, 0);

        // Add a task and accept it
        setup_accepted_task(&db, &obj_id, "miner_a").await;

        // Second pass: should reflect the new accepted task
        let r2 = engine.generate_report(&obj_id).await.unwrap();
        assert_eq!(r2.total_tasks, 1);
        assert_eq!(r2.accepted_tasks, 1);
    }
}
