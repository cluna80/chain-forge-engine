//! Tests for Change Set C — Research Microtask Decomposition
//!
//! Covers:
//! - Deterministic decomposition (identical inputs → identical outputs)
//! - Exact range coverage (union of tasks = objective range, no gaps, no overlaps)
//! - Small and large task sizes (CPU / GPU / Accelerator defaults)
//! - Boundary conditions (empty range, range_end == u64::MAX, single-unit tasks)
//! - Integer overflow safety
//! - Duplicate task ID rejection
//! - Invalid objective references
//! - Duplicate acceptance / double-reward guard
//! - Unauthorized / invalid state transitions
//! - Objective completion tracking
//! - Two miners working the same objective (acceptance criterion)
//! - MicrotaskCommitment canonical bytes and content hash stability
//! - PoCD receipt compatibility (task IDs embed challenge_id / objective_id)

#[cfg(test)]
mod tests {
    use crate::types::microtask::{
        decompose_objective, DecompositionConfig, MicrotaskCommitment, MicrotaskRegistry,
        MicrotaskStatus, ObjectiveStatus, ResearchMicrotask, ResearchObjective, WorkloadClass,
    };

    // ── helpers ───────────────────────────────────────────────────────────

    fn make_objective(challenge_id: &str, slug: &str, start: u64, end: u64) -> ResearchObjective {
        ResearchObjective {
            objective_id:       ResearchObjective::make_id(challenge_id, slug),
            challenge_id:       challenge_id.to_string(),
            name:               format!("Test objective {slug}"),
            algorithm_version:  "test_algo_v1".to_string(),
            range_start:        start,
            range_end:          end,
            verification_spec:  "sha256(output) starts with 0".to_string(),
            status:             ObjectiveStatus::Active,
        }
    }

    fn cpu_config() -> DecompositionConfig {
        DecompositionConfig { workload_class: WorkloadClass::Cpu, chunk_size_override: None }
    }

    fn config_with_size(class: WorkloadClass, size: u64) -> DecompositionConfig {
        DecompositionConfig { workload_class: class, chunk_size_override: Some(size) }
    }

    fn dummy_commitment(receipt_id: &str, task: &ResearchMicrotask, block: u64) -> MicrotaskCommitment {
        MicrotaskCommitment {
            receipt_id:          receipt_id.to_string(),
            task_id:             task.task_id.clone(),
            objective_id:        task.objective_id.clone(),
            challenge_id:        task.challenge_id.clone(),
            machine_id:          "machine:test".to_string(),
            task_start:          task.task_start,
            task_end:            task.task_end,
            committed_at_block:  block,
        }
    }

    // ── Determinism ───────────────────────────────────────────────────────

    #[test]
    fn decomposition_is_deterministic() {
        let obj = make_objective("qcb-test::Cryptography::hash-001", "det-test", 0, 10_000);
        let cfg = config_with_size(WorkloadClass::Cpu, 1_000);
        let tasks1 = decompose_objective(&obj, &cfg).expect("first decomposition failed");
        let tasks2 = decompose_objective(&obj, &cfg).expect("second decomposition failed");
        assert_eq!(tasks1.len(), tasks2.len(), "task counts differ");
        for (a, b) in tasks1.iter().zip(tasks2.iter()) {
            assert_eq!(a.task_id,   b.task_id,   "task_id differs");
            assert_eq!(a.task_start, b.task_start, "task_start differs");
            assert_eq!(a.task_end,   b.task_end,   "task_end differs");
            assert_eq!(a.input_seed, b.input_seed,  "input_seed differs");
        }
    }

    // ── Exact range coverage ──────────────────────────────────────────────

    #[test]
    fn tasks_cover_full_range_exactly() {
        let obj = make_objective("qcb-test::Mathematics::exact-001", "range-exact", 500, 5_500);
        let cfg = config_with_size(WorkloadClass::Cpu, 1_000);
        let tasks = decompose_objective(&obj, &cfg).unwrap();
        assert_eq!(tasks.len(), 5, "expected 5 tasks for range [500, 5500) with chunk=1000");

        // Sort by start (should already be sorted, but verify).
        let mut sorted = tasks.clone();
        sorted.sort_by_key(|t| t.task_start);

        // First task starts at objective range_start.
        assert_eq!(sorted[0].task_start, 500);
        // Last task ends at objective range_end.
        assert_eq!(sorted.last().unwrap().task_end, 5_500);

        // No gaps, no overlaps.
        for window in sorted.windows(2) {
            assert_eq!(
                window[0].task_end, window[1].task_start,
                "gap or overlap between tasks {:?} and {:?}",
                window[0].task_id, window[1].task_id
            );
        }
    }

    #[test]
    fn tail_task_correct_when_range_not_evenly_divisible() {
        // 1003 units, chunk=100 → 10 full tasks + 1 tail of 3.
        let obj = make_objective("qcb-test::Cryptography::tail-001", "tail", 0, 1_003);
        let cfg = config_with_size(WorkloadClass::Cpu, 100);
        let tasks = decompose_objective(&obj, &cfg).unwrap();
        assert_eq!(tasks.len(), 11);
        let last = tasks.last().unwrap();
        assert_eq!(last.task_start, 1_000);
        assert_eq!(last.task_end,   1_003);
        assert_eq!(last.size(), 3);
    }

    // ── Empty range ───────────────────────────────────────────────────────

    #[test]
    fn empty_range_produces_no_tasks() {
        let obj = make_objective("qcb-test::Cryptography::empty-001", "empty", 42, 42);
        let tasks = decompose_objective(&obj, &cpu_config()).unwrap();
        assert!(tasks.is_empty(), "expected no tasks for empty range");
    }

    #[test]
    fn inverted_range_produces_no_tasks() {
        let obj = make_objective("qcb-test::Cryptography::inv-001", "inverted", 100, 50);
        let tasks = decompose_objective(&obj, &cpu_config()).unwrap();
        assert!(tasks.is_empty());
    }

    // ── Zero chunk size ───────────────────────────────────────────────────

    #[test]
    fn zero_chunk_size_returns_error() {
        let obj = make_objective("qcb-test::Cryptography::zero-001", "zero", 0, 1000);
        let cfg = config_with_size(WorkloadClass::Cpu, 0);
        assert!(
            decompose_objective(&obj, &cfg).is_err(),
            "expected error for chunk_size=0"
        );
    }

    // ── Single-unit tasks ─────────────────────────────────────────────────

    #[test]
    fn single_unit_tasks() {
        let obj = make_objective("qcb-test::Mathematics::single-001", "single", 0, 5);
        let cfg = config_with_size(WorkloadClass::Cpu, 1);
        let tasks = decompose_objective(&obj, &cfg).unwrap();
        assert_eq!(tasks.len(), 5);
        for (i, t) in tasks.iter().enumerate() {
            assert_eq!(t.task_start, i as u64);
            assert_eq!(t.task_end,   i as u64 + 1);
            assert_eq!(t.size(), 1);
        }
    }

    // ── u64::MAX boundary ─────────────────────────────────────────────────

    #[test]
    fn near_u64_max_no_overflow() {
        // Range ending two steps before u64::MAX, chunk=1.
        let end = u64::MAX - 1;
        let start = u64::MAX - 3;
        let obj = make_objective("qcb-test::Cryptography::max-001", "maxbnd", start, end);
        let cfg = config_with_size(WorkloadClass::Cpu, 1);
        let tasks = decompose_objective(&obj, &cfg).unwrap();
        assert_eq!(tasks.len(), 2, "expected 2 tasks near u64::MAX");
        assert_eq!(tasks.last().unwrap().task_end, end);
    }

    #[test]
    fn range_end_at_u64_max() {
        let start = u64::MAX - 5;
        let end   = u64::MAX;
        let obj = make_objective("qcb-test::Cryptography::max2-001", "maxend", start, end);
        let cfg = config_with_size(WorkloadClass::Cpu, 2);
        // 5 units, chunk=2 → 2 full + 1 tail of 1.
        let tasks = decompose_objective(&obj, &cfg).unwrap();
        assert_eq!(tasks.len(), 3);
        let last = tasks.last().unwrap();
        assert_eq!(last.task_end, u64::MAX);
    }

    // ── Default chunk sizes ───────────────────────────────────────────────

    #[test]
    fn default_chunk_sizes_are_sensible() {
        assert_eq!(WorkloadClass::Cpu.default_chunk_size(),         1_000);
        assert_eq!(WorkloadClass::Gpu.default_chunk_size(),       100_000);
        assert_eq!(WorkloadClass::Accelerator.default_chunk_size(), 5_000_000);
    }

    #[test]
    fn gpu_tasks_are_100x_cpu_tasks_in_size() {
        let obj = make_objective("qcb-test::Cryptography::size-001", "sizecmp", 0, 1_000_000);
        let cpu_tasks = decompose_objective(&obj, &cpu_config()).unwrap();
        let gpu_tasks = decompose_objective(
            &obj, &DecompositionConfig { workload_class: WorkloadClass::Gpu, chunk_size_override: None }
        ).unwrap();
        assert_eq!(cpu_tasks.len(), 1_000);
        assert_eq!(gpu_tasks.len(),    10);
    }

    // ── Task ID stability ─────────────────────────────────────────────────

    #[test]
    fn task_ids_embed_objective_and_range() {
        let obj = make_objective("qcb-test::Cryptography::id-001", "idtest", 0, 1_000);
        let cfg = config_with_size(WorkloadClass::Cpu, 1_000);
        let tasks = decompose_objective(&obj, &cfg).unwrap();
        assert_eq!(tasks.len(), 1);
        let t = &tasks[0];
        // Task ID must contain the objective_id.
        assert!(t.task_id.contains(&obj.objective_id), "task_id must embed objective_id");
        // And the range bounds as hex.
        assert!(t.task_id.contains(&format!("{:016x}", 0u64)));
        assert!(t.task_id.contains(&format!("{:016x}", 1_000u64)));
    }

    // ── Input seed stability ──────────────────────────────────────────────

    #[test]
    fn input_seed_is_stable_across_calls() {
        let obj = make_objective("qcb-test::Cryptography::seed-001", "seedtest", 0, 5_000);
        let cfg = config_with_size(WorkloadClass::Cpu, 1_000);
        let t1 = decompose_objective(&obj, &cfg).unwrap();
        let t2 = decompose_objective(&obj, &cfg).unwrap();
        for (a, b) in t1.iter().zip(t2.iter()) {
            assert_eq!(a.input_seed, b.input_seed);
        }
    }

    #[test]
    fn different_ranges_produce_different_seeds() {
        let obj = make_objective("qcb-test::Cryptography::seed2-001", "sdiff", 0, 2_000);
        let cfg = config_with_size(WorkloadClass::Cpu, 1_000);
        let tasks = decompose_objective(&obj, &cfg).unwrap();
        assert_eq!(tasks.len(), 2);
        assert_ne!(tasks[0].input_seed, tasks[1].input_seed,
            "tasks covering different ranges must have different seeds");
    }

    // ── MicrotaskRegistry ─────────────────────────────────────────────────

    #[test]
    fn registry_rejects_duplicate_objective() {
        let mut reg = MicrotaskRegistry::new();
        let obj = make_objective("qcb-test::Cryptography::dup-001", "dup", 0, 1_000);
        reg.add_objective(obj.clone()).unwrap();
        assert!(reg.add_objective(obj).is_err(), "duplicate objective should be rejected");
    }

    #[test]
    fn registry_rejects_task_for_unknown_objective() {
        let mut reg = MicrotaskRegistry::new();
        let fake_obj = make_objective("qcb-test::Cryptography::fake-001", "fake", 0, 1_000);
        // Don't add fake_obj to registry.
        let cfg   = config_with_size(WorkloadClass::Cpu, 1_000);
        let tasks = decompose_objective(&fake_obj, &cfg).unwrap();
        assert!(reg.add_tasks(tasks).is_err(), "tasks for unknown objective should be rejected");
    }

    #[test]
    fn registry_rejects_duplicate_task_id() {
        let mut reg = MicrotaskRegistry::new();
        let obj = make_objective("qcb-test::Cryptography::dupid-001", "dupid", 0, 1_000);
        reg.add_objective(obj.clone()).unwrap();
        let cfg   = config_with_size(WorkloadClass::Cpu, 1_000);
        let tasks = decompose_objective(&obj, &cfg).unwrap();
        reg.add_tasks(tasks.clone()).unwrap();
        assert!(reg.add_tasks(tasks).is_err(), "duplicate task_id should be rejected");
    }

    #[test]
    fn assign_reject_available_only() {
        let mut reg = MicrotaskRegistry::new();
        let obj = make_objective("qcb-test::Cryptography::assign-001", "assign", 0, 3_000);
        reg.add_objective(obj.clone()).unwrap();
        let cfg   = config_with_size(WorkloadClass::Cpu, 1_000);
        let tasks = decompose_objective(&obj, &cfg).unwrap();
        reg.add_tasks(tasks).unwrap();

        let task_ids: Vec<String> = reg
            .tasks_for_objective(&obj.objective_id)
            .iter()
            .map(|t| t.task_id.clone())
            .collect();

        // Assign task 0 to miner A.
        reg.assign_task(&task_ids[0], "miner:A").unwrap();
        // Assigning again (to miner B) should fail — it's no longer Available.
        assert!(
            reg.assign_task(&task_ids[0], "miner:B").is_err(),
            "assigning an already-assigned task should fail"
        );
    }

    #[test]
    fn double_acceptance_is_rejected() {
        let mut reg = MicrotaskRegistry::new();
        let obj = make_objective("qcb-test::Cryptography::dblaccept-001", "dblac", 0, 1_000);
        reg.add_objective(obj.clone()).unwrap();
        let cfg   = config_with_size(WorkloadClass::Cpu, 1_000);
        let tasks = decompose_objective(&obj, &cfg).unwrap();
        reg.add_tasks(tasks).unwrap();

        let task = reg.tasks_for_objective(&obj.objective_id)[0].clone();
        reg.assign_task(&task.task_id, "miner:A").unwrap();
        reg.mark_submitted(&task.task_id).unwrap();

        let commit1 = dummy_commitment("receipt-001", &task, 10);
        reg.accept_task(&task.task_id, commit1).unwrap();

        let commit2 = dummy_commitment("receipt-002", &task, 11);
        assert!(
            reg.accept_task(&task.task_id, commit2).is_err(),
            "second acceptance of same task must be rejected (double-reward guard)"
        );
    }

    // ── Acceptance criterion: two miners, one objective ───────────────────

    #[test]
    fn two_miners_contribute_to_same_objective_without_overlap() {
        let challenge_id = "qcb-devnet-3node::Cryptography::devnet-crypto-1";
        let obj = make_objective(challenge_id, "two-miner-test", 0, 200_000);
        let cfg = config_with_size(WorkloadClass::Gpu, 100_000);

        let mut reg = MicrotaskRegistry::new();
        reg.add_objective(obj.clone()).unwrap();
        let tasks = decompose_objective(&obj, &cfg).unwrap();
        assert_eq!(tasks.len(), 2, "expected 2 tasks for two miners");
        reg.add_tasks(tasks).unwrap();

        let task_ids: Vec<String> = {
            let mut v = reg.tasks_for_objective(&obj.objective_id)
                .iter()
                .map(|t| t.task_id.clone())
                .collect::<Vec<_>>();
            v.sort();
            v
        };

        // Miner A claims task 0, Miner B claims task 1.
        reg.assign_task(&task_ids[0], "miner:A").unwrap();
        reg.assign_task(&task_ids[1], "miner:B").unwrap();

        // Both complete and submit.
        reg.mark_submitted(&task_ids[0]).unwrap();
        reg.mark_submitted(&task_ids[1]).unwrap();

        // Retrieve tasks for building commitments.
        let t0 = reg.tasks.get(&task_ids[0]).unwrap().clone();
        let t1 = reg.tasks.get(&task_ids[1]).unwrap().clone();

        // Verify ranges are disjoint.
        assert!(
            t0.task_end <= t1.task_start || t1.task_end <= t0.task_start,
            "tasks must not overlap: [{}, {}) and [{}, {})",
            t0.task_start, t0.task_end, t1.task_start, t1.task_end
        );

        // Both get accepted with different receipts.
        let c0 = dummy_commitment("receipt-A-001", &t0, 100);
        let c1 = dummy_commitment("receipt-B-001", &t1, 101);
        reg.accept_task(&task_ids[0], c0).unwrap();
        reg.accept_task(&task_ids[1], c1).unwrap();

        // Objective should now be complete.
        assert!(
            reg.objective_complete(&obj.objective_id),
            "objective should be complete after both tasks accepted"
        );
        assert_eq!(
            reg.get_objective(&obj.objective_id).unwrap().status,
            ObjectiveStatus::Completed
        );

        // Verify no ranges overlap by checking all task bounds.
        let all_tasks: Vec<_> = {
            let mut v: Vec<_> = reg.tasks_for_objective(&obj.objective_id)
                .into_iter()
                .collect();
            v.sort_by_key(|t| t.task_start);
            v
        };
        for window in all_tasks.windows(2) {
            assert_eq!(
                window[0].task_end, window[1].task_start,
                "tasks must be contiguous without overlap"
            );
        }
    }

    // ── Progress tracking ─────────────────────────────────────────────────

    #[test]
    fn objective_progress_updates_correctly() {
        let obj = make_objective("qcb-test::Cryptography::prog-001", "progress", 0, 3_000);
        let cfg = config_with_size(WorkloadClass::Cpu, 1_000);
        let mut reg = MicrotaskRegistry::new();
        reg.add_objective(obj.clone()).unwrap();
        let tasks = decompose_objective(&obj, &cfg).unwrap();
        reg.add_tasks(tasks).unwrap();

        let (accepted, total) = reg.objective_progress(&obj.objective_id);
        assert_eq!(total,    3, "expected 3 tasks");
        assert_eq!(accepted, 0, "expected 0 accepted initially");

        // Accept first task.
        let task_ids: Vec<String> = reg
            .tasks_for_objective(&obj.objective_id)
            .iter()
            .map(|t| t.task_id.clone())
            .collect();
        let t0 = reg.tasks.get(&task_ids[0]).unwrap().clone();
        reg.assign_task(&task_ids[0], "miner:X").unwrap();
        let c = dummy_commitment("receipt-x-001", &t0, 1);
        reg.accept_task(&task_ids[0], c).unwrap();

        let (accepted2, total2) = reg.objective_progress(&obj.objective_id);
        assert_eq!(total2,    3);
        assert_eq!(accepted2, 1);
        assert!(!reg.objective_complete(&obj.objective_id));
    }

    // ── MicrotaskCommitment ───────────────────────────────────────────────

    #[test]
    fn commitment_canonical_bytes_and_hash_are_stable() {
        let obj  = make_objective("qcb-test::Cryptography::commit-001", "cmt", 0, 1_000);
        let cfg  = config_with_size(WorkloadClass::Cpu, 1_000);
        let tasks = decompose_objective(&obj, &cfg).unwrap();
        let t    = &tasks[0];
        let c    = dummy_commitment("receipt-stable-001", t, 42);

        let bytes1 = c.canonical_bytes();
        let bytes2 = c.canonical_bytes();
        assert_eq!(bytes1, bytes2, "canonical_bytes must be stable");

        let hash1 = c.content_hash();
        let hash2 = c.content_hash();
        assert_eq!(hash1, hash2, "content_hash must be stable");
        assert_eq!(hash1.len(), 64, "expected 64-char hex SHA-256");
    }

    #[test]
    fn different_receipts_produce_different_commitment_hashes() {
        let obj  = make_objective("qcb-test::Cryptography::cmthash-001", "chash", 0, 2_000);
        let cfg  = config_with_size(WorkloadClass::Cpu, 1_000);
        let tasks = decompose_objective(&obj, &cfg).unwrap();

        let c1 = dummy_commitment("receipt-hash-001", &tasks[0], 10);
        let c2 = dummy_commitment("receipt-hash-002", &tasks[1], 11);
        assert_ne!(c1.content_hash(), c2.content_hash());
    }

    // ── PoCD integration / challenge_id propagation ───────────────────────

    #[test]
    fn task_challenge_id_matches_parent_objective() {
        let challenge_id = "qcb-devnet-3node::Mathematics::devnet-pilot-1";
        let obj = make_objective(challenge_id, "pocd-compat", 0, 10_000);
        let cfg = config_with_size(WorkloadClass::Cpu, 1_000);
        let tasks = decompose_objective(&obj, &cfg).unwrap();
        for t in &tasks {
            assert_eq!(
                t.challenge_id, challenge_id,
                "task.challenge_id must match the parent objective's challenge_id"
            );
        }
    }

    #[test]
    fn task_id_is_unique_per_objective_even_with_same_range() {
        // Two objectives with the same range but different IDs must produce different task IDs.
        let obj_a = make_objective("qcb-test::Cryptography::unique-a", "same-range", 0, 1_000);
        let obj_b = make_objective("qcb-test::Cryptography::unique-b", "same-range", 0, 1_000);
        let cfg   = config_with_size(WorkloadClass::Cpu, 1_000);
        let tasks_a = decompose_objective(&obj_a, &cfg).unwrap();
        let tasks_b = decompose_objective(&obj_b, &cfg).unwrap();
        assert_ne!(
            tasks_a[0].task_id, tasks_b[0].task_id,
            "same range on different objectives must produce different task IDs"
        );
    }

    // ── Reject-then-reassign ──────────────────────────────────────────────

    #[test]
    fn rejected_task_status_updates() {
        let mut reg = MicrotaskRegistry::new();
        let obj = make_objective("qcb-test::Cryptography::rej-001", "rej", 0, 1_000);
        reg.add_objective(obj.clone()).unwrap();
        let cfg   = config_with_size(WorkloadClass::Cpu, 1_000);
        let tasks = decompose_objective(&obj, &cfg).unwrap();
        reg.add_tasks(tasks).unwrap();

        let task_id = reg.tasks_for_objective(&obj.objective_id)[0].task_id.clone();
        reg.assign_task(&task_id, "miner:bad").unwrap();
        reg.mark_submitted(&task_id).unwrap();
        reg.reject_task(&task_id).unwrap();

        let t = reg.tasks.get(&task_id).unwrap();
        assert_eq!(t.status, MicrotaskStatus::Rejected);
        // assigned_to cleared on rejection.
        assert!(t.assigned_to.is_none());
    }

    // ── ResearchObjective helpers ─────────────────────────────────────────

    #[test]
    fn objective_total_range_is_correct() {
        let obj = make_objective("qcb-test::Cryptography::range-001", "rng", 1_000, 6_000);
        assert_eq!(obj.total_range(), 5_000);
    }

    #[test]
    fn objective_derive_slug_is_stable() {
        let slug1 = ResearchObjective::derive_slug("challenge::x", "v1", 0, 1_000);
        let slug2 = ResearchObjective::derive_slug("challenge::x", "v1", 0, 1_000);
        assert_eq!(slug1, slug2, "slug must be deterministic");
        assert_eq!(slug1.len(), 16, "slug must be 16 hex chars");

        let slug3 = ResearchObjective::derive_slug("challenge::x", "v1", 0, 2_000);
        assert_ne!(slug1, slug3, "different ranges must produce different slugs");
    }

    // ── Sample: CPU-sized and GPU-sized tasks from one objective ──────────

    #[test]
    fn sample_objective_decomposed_for_cpu_and_gpu() {
        // Simulates a real QCB objective: HASH-001 for a hash avalanche study.
        let challenge_id = "qcb-devnet-3node::Cryptography::devnet-crypto-1";
        let slug = ResearchObjective::derive_slug(challenge_id, "avalanche_v1", 0, 1_000_000);
        let obj = ResearchObjective {
            objective_id:      ResearchObjective::make_id(challenge_id, &slug),
            challenge_id:      challenge_id.to_string(),
            name:              "HASH-001 Avalanche Property Investigation".to_string(),
            algorithm_version: "avalanche_v1".to_string(),
            range_start:       0,
            range_end:         1_000_000,
            verification_spec: "mean_changed_bit_fraction within [0.48, 0.52] for 1000 samples".to_string(),
            status:            ObjectiveStatus::Active,
        };

        let cpu_tasks = decompose_objective(
            &obj,
            &DecompositionConfig { workload_class: WorkloadClass::Cpu, chunk_size_override: None },
        ).unwrap();

        let gpu_tasks = decompose_objective(
            &obj,
            &DecompositionConfig { workload_class: WorkloadClass::Gpu, chunk_size_override: None },
        ).unwrap();

        // CPU: 1_000_000 / 1_000 = 1_000 tasks.
        assert_eq!(cpu_tasks.len(), 1_000,
            "CPU decomposition should yield 1 000 tasks");
        // GPU: 1_000_000 / 100_000 = 10 tasks.
        assert_eq!(gpu_tasks.len(), 10,
            "GPU decomposition should yield 10 tasks");

        // Each GPU task covers the same work as 100 CPU tasks.
        assert_eq!(gpu_tasks[0].size(), 100_000);
        assert_eq!(cpu_tasks[0].size(),   1_000);

        // All CPU tasks together cover the same range as all GPU tasks.
        let cpu_total: u64 = cpu_tasks.iter().map(|t| t.size()).sum();
        let gpu_total: u64 = gpu_tasks.iter().map(|t| t.size()).sum();
        assert_eq!(cpu_total, gpu_total);
        assert_eq!(cpu_total, 1_000_000);

        // First and last bounds match.
        assert_eq!(cpu_tasks.first().unwrap().task_start, 0);
        assert_eq!(cpu_tasks.last().unwrap().task_end,    1_000_000);
        assert_eq!(gpu_tasks.first().unwrap().task_start, 0);
        assert_eq!(gpu_tasks.last().unwrap().task_end,    1_000_000);
    }
}
