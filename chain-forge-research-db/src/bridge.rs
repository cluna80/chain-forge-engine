//! Conversion helpers from `chain-forge-pocd` in-memory types into database
//! insertion DTOs.
//!
//! This module is the only place that imports from `chain-forge-pocd`.
//! The rest of the crate is independent so the persistence layer can be
//! tested with hand-crafted DTOs without spinning up the full PoCD stack.

use chain_forge_pocd::{ResearchMicrotask, ResearchObjective, WorkloadClass};

use crate::models::{NewObjective, NewTask};

impl From<&ResearchObjective> for NewObjective {
    fn from(obj: &ResearchObjective) -> Self {
        // ResearchObjective fields (from microtask.rs):
        //   objective_id, challenge_id, name, algorithm_version,
        //   range_start, range_end, verification_spec (String), status
        //
        // slug is derived from objective_id by stripping the
        // "{challenge_id}::obj::" prefix.
        let slug = obj
            .objective_id
            .strip_prefix(&format!("{}::obj::", obj.challenge_id))
            .unwrap_or(&obj.objective_id)
            .to_string();

        NewObjective {
            objective_id:      obj.objective_id.clone(),
            challenge_id:      obj.challenge_id.clone(),
            slug,
            // track is not stored on ResearchObjective yet; use "unknown"
            // until Change Set E adds it.
            track:             "unknown".to_string(),
            algorithm_version: obj.algorithm_version.clone(),
            range_start:       obj.range_start,
            range_end:         obj.range_end,
            // ResearchObjective has no workload_class field; default to "cpu".
            // The field on ResearchMicrotask carries the real value per task.
            workload_class:    "cpu".to_string(),
            verification_spec: serde_json::Value::String(obj.verification_spec.clone()),
        }
    }
}

impl From<&ResearchMicrotask> for NewTask {
    fn from(t: &ResearchMicrotask) -> Self {
        // ResearchMicrotask fields (from microtask.rs):
        //   task_id, objective_id, challenge_id,
        //   task_start, task_end,       ← NOT range_start / range_end
        //   workload_class, input_seed,
        //   verification_spec, status, settled_receipt_id, assigned_to
        NewTask {
            task_id:        t.task_id.clone(),
            objective_id:   t.objective_id.clone(),
            range_start:    t.task_start,
            range_end:      t.task_end,
            workload_class: workload_class_str(t.workload_class),
            input_seed:     t.input_seed,
        }
    }
}

fn workload_class_str(wc: WorkloadClass) -> String {
    match wc {
        WorkloadClass::Cpu         => "cpu".to_string(),
        WorkloadClass::Gpu         => "gpu".to_string(),
        WorkloadClass::Accelerator => "accelerator".to_string(),
    }
}
