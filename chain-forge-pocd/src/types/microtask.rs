//! Research Microtask Decomposition — Change Set C
//!
//! A `ResearchObjective` is a bounded computational research goal linked to a
//! `DiscoveryChallenge`.  It defines the total work scope and the rules for
//! dividing that scope into independently verifiable pieces.
//!
//! A `ResearchMicrotask` is one atomic unit of that scope — a non-overlapping
//! range assigned to a single miner.  Miners submit work through the existing
//! `DiscoveryProof` / `DiscoveryReceipt` pipeline; microtasks extend that
//! pipeline with range attribution and completion tracking without touching
//! consensus, monetary policy, or treasury rewards.
//!
//! ## Decomposition guarantee
//!
//! `decompose_objective` is deterministic and pure: identical inputs always
//! produce identical task IDs and ranges, and the union of all produced ranges
//! exactly covers `[range_start, range_end)` with no gaps or overlaps.
//!
//! ## Change Set D note
//!
//! All state here lives in memory (`MicrotaskRegistry`).  Change Set D will
//! add a PostgreSQL persistence layer underneath the same API surface; callers
//! need not change.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::PoCDError;

// ── WorkloadClass ─────────────────────────────────────────────────────────────

/// The class of compute resource best suited to execute this microtask.
///
/// Task sizes are informational — the chain does not enforce hardware
/// requirements.  Miners self-select by capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadClass {
    /// Short tasks (≈1 000 iterations).  Suitable for any CPU.
    Cpu,
    /// Medium tasks (≈100 000 iterations).  Suited to multi-core CPUs or GPUs.
    Gpu,
    /// Large tasks (≈5 000 000 iterations).  Suited to AI accelerators.
    Accelerator,
}

impl WorkloadClass {
    /// Default task-range width (number of work units) for this class.
    pub fn default_chunk_size(self) -> u64 {
        match self {
            WorkloadClass::Cpu         =>     1_000,
            WorkloadClass::Gpu         =>   100_000,
            WorkloadClass::Accelerator => 5_000_000,
        }
    }
}

// ── MicrotaskStatus ───────────────────────────────────────────────────────────

/// Lifecycle state of a single `ResearchMicrotask`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MicrotaskStatus {
    /// Not yet assigned to any miner.
    Available,
    /// Claimed by a miner; work is in progress.
    Assigned,
    /// Miner has submitted a result (proof submitted; awaiting acceptance).
    Submitted,
    /// Result accepted; a `DiscoveryReceipt` was issued for this task.
    Accepted,
    /// Result rejected (seal invalid, out-of-range, or duplicate).
    Rejected,
}

// ── ObjectiveStatus ───────────────────────────────────────────────────────────

/// Lifecycle state of a `ResearchObjective`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectiveStatus {
    /// Pending governance activation of the parent challenge.
    Pending,
    /// Decomposed and ready for miner assignment.
    Active,
    /// All microtasks accepted; objective fully covered.
    Completed,
    /// Retired by governance before completion.
    Retired,
}

// ── ResearchObjective ─────────────────────────────────────────────────────────

/// A versioned, bounded research goal derived from a `DiscoveryChallenge`.
///
/// One challenge can spawn multiple objectives (e.g. different algorithm
/// versions or parameter spaces), but each objective covers a disjoint portion
/// of that challenge's search space.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResearchObjective {
    /// Globally unique: `"{challenge_id}::obj::{slug}"`.
    pub objective_id: String,

    /// Parent `DiscoveryChallenge` ID.
    pub challenge_id: String,

    /// Human-readable goal description.
    pub name: String,

    /// Algorithm or experiment identifier (e.g. `"avalanche_test_v1"`).
    pub algorithm_version: String,

    /// Inclusive lower bound of the computational range.
    pub range_start: u64,

    /// Exclusive upper bound of the computational range.
    /// Invariant: `range_end > range_start`.
    pub range_end: u64,

    /// How to verify a submitted result for this objective.
    pub verification_spec: String,

    pub status: ObjectiveStatus,
}

impl ResearchObjective {
    /// Total number of work units this objective covers.
    pub fn total_range(&self) -> u64 {
        self.range_end.saturating_sub(self.range_start)
    }

    /// Canonical objective ID from its components.
    pub fn make_id(challenge_id: &str, slug: &str) -> String {
        format!("{challenge_id}::obj::{slug}")
    }

    /// Derive a deterministic slug from the range and algorithm version.
    ///
    /// Used when no explicit slug is provided, ensuring that two independent
    /// callers constructing the same objective always agree on the ID.
    pub fn derive_slug(challenge_id: &str, algorithm_version: &str, range_start: u64, range_end: u64) -> String {
        let mut h = Sha256::new();
        h.update(challenge_id.as_bytes());
        h.update(b"::");
        h.update(algorithm_version.as_bytes());
        h.update(b"::");
        h.update(range_start.to_be_bytes());
        h.update(b"-");
        h.update(range_end.to_be_bytes());
        let digest = hex::encode(h.finalize());
        digest[..16].to_string()
    }
}

// ── ResearchMicrotask ─────────────────────────────────────────────────────────

/// One atomic, independently verifiable unit of a `ResearchObjective`.
///
/// The assigned range `[task_start, task_end)` is non-overlapping with all
/// other tasks in the same objective and is fully contained within the
/// objective's range.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResearchMicrotask {
    /// Unique task ID: deterministic from objective and range.
    /// Format: `"{objective_id}::task::{start_hex}-{end_hex}"`.
    pub task_id: String,

    /// Parent objective this task belongs to.
    pub objective_id: String,

    /// Parent challenge (denormalized for quick lookup).
    pub challenge_id: String,

    /// Inclusive start of this task's computational range.
    pub task_start: u64,

    /// Exclusive end of this task's computational range.
    pub task_end: u64,

    /// Class of workload (CPU / GPU / Accelerator).
    pub workload_class: WorkloadClass,

    /// Deterministic per-task seed for parameterised experiments.
    ///
    /// Derived from `SHA256(objective_id || task_start_be8 || task_end_be8)`.
    /// Ensures independent miners working the same range always use the same
    /// random seed, making results reproducible and comparable.
    pub input_seed: u64,

    /// Reference to the verification method for this specific task.
    pub verification_spec: String,

    pub status: MicrotaskStatus,

    /// The `DiscoveryReceipt` ID that settled this task, once accepted.
    pub settled_receipt_id: Option<String>,

    /// Machine ID that claimed this task (set when status → Assigned).
    pub assigned_to: Option<String>,
}

impl ResearchMicrotask {
    /// Canonical task ID from objective ID and range bounds.
    pub fn make_id(objective_id: &str, task_start: u64, task_end: u64) -> String {
        format!(
            "{objective_id}::task::{:016x}-{:016x}",
            task_start, task_end
        )
    }

    /// Derive the deterministic per-task input seed.
    ///
    /// Uses `SHA256(objective_id || task_start_be8 || task_end_be8)` and
    /// takes the first 8 bytes as a `u64`.  Two tasks with the same bounds
    /// from the same objective always receive the same seed.
    pub fn derive_seed(objective_id: &str, task_start: u64, task_end: u64) -> u64 {
        let mut h = Sha256::new();
        h.update(objective_id.as_bytes());
        h.update(task_start.to_be_bytes());
        h.update(task_end.to_be_bytes());
        let digest = h.finalize();
        u64::from_be_bytes(digest[..8].try_into().expect("sha256 >= 8 bytes"))
    }

    /// Number of work units in this task.
    pub fn size(&self) -> u64 {
        self.task_end.saturating_sub(self.task_start)
    }

    /// True when this task can be assigned to a miner.
    pub fn is_available(&self) -> bool {
        self.status == MicrotaskStatus::Available
    }
}

// ── Decomposition ─────────────────────────────────────────────────────────────

/// Configuration for a single decomposition run.
#[derive(Debug, Clone)]
pub struct DecompositionConfig {
    /// Class of workload to generate tasks for.
    pub workload_class: WorkloadClass,
    /// Override the default chunk size for this class.
    /// If `None`, `workload_class.default_chunk_size()` is used.
    pub chunk_size_override: Option<u64>,
}

impl DecompositionConfig {
    /// Effective chunk size for this configuration.
    pub fn effective_chunk_size(&self) -> u64 {
        self.chunk_size_override
            .unwrap_or_else(|| self.workload_class.default_chunk_size())
    }
}

/// Decompose a `ResearchObjective` into microtasks.
///
/// ## Guarantees
/// * Deterministic: identical inputs → identical output (same IDs, same ranges).
/// * Complete: union of all `[task_start, task_end)` equals `[range_start, range_end)`.
/// * Non-overlapping: no two tasks share a work unit.
/// * Stable IDs: IDs are derived from the objective ID and range bounds only.
///
/// ## Edge cases
/// * If `range_start >= range_end`, returns an empty `Vec`.
/// * If `chunk_size` is 0, returns an error.
/// * The final chunk may be smaller than `chunk_size` (tail handling).
/// * Handles `range_end == u64::MAX` safely via saturating arithmetic.
pub fn decompose_objective(
    objective: &ResearchObjective,
    config: &DecompositionConfig,
) -> Result<Vec<ResearchMicrotask>, PoCDError> {
    let chunk_size = config.effective_chunk_size();
    if chunk_size == 0 {
        return Err(PoCDError::Other(
            "DecompositionConfig: chunk_size must be > 0".to_string(),
        ));
    }

    let start = objective.range_start;
    let end   = objective.range_end;

    if start >= end {
        // Empty range → no tasks (not an error; objective may be a no-op).
        return Ok(Vec::new());
    }

    // Pre-allocate: ceil((end - start) / chunk_size)
    let total = end - start;
    let count = (total + chunk_size - 1) / chunk_size;
    let mut tasks = Vec::with_capacity(count as usize);

    let mut cursor = start;
    while cursor < end {
        // Saturating add handles cursor + chunk_size overflowing u64::MAX.
        let task_end = cursor.saturating_add(chunk_size).min(end);

        let task_id    = ResearchMicrotask::make_id(&objective.objective_id, cursor, task_end);
        let input_seed = ResearchMicrotask::derive_seed(&objective.objective_id, cursor, task_end);

        tasks.push(ResearchMicrotask {
            task_id,
            objective_id:      objective.objective_id.clone(),
            challenge_id:      objective.challenge_id.clone(),
            task_start:        cursor,
            task_end,
            workload_class:    config.workload_class,
            input_seed,
            verification_spec: objective.verification_spec.clone(),
            status:            MicrotaskStatus::Available,
            settled_receipt_id: None,
            assigned_to:       None,
        });

        if task_end == end {
            break;
        }
        cursor = task_end;
    }

    Ok(tasks)
}

// ── MicrotaskCommitment ───────────────────────────────────────────────────────

/// A binding commitment that associates an accepted `DiscoveryReceipt` with
/// the specific microtask it covers.
///
/// Stored alongside receipts to allow the QCB Discovery Engine (Change Set G)
/// to query "which range did this receipt cover?" without scanning all tasks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MicrotaskCommitment {
    /// The receipt that was accepted.
    pub receipt_id: String,
    /// The task that was settled.
    pub task_id: String,
    /// The objective the task belongs to.
    pub objective_id: String,
    /// The challenge the objective belongs to.
    pub challenge_id: String,
    /// Machine that submitted the work.
    pub machine_id: String,
    /// Range covered (denormalised from the task for quick querying).
    pub task_start: u64,
    pub task_end:   u64,
    /// Block at which the receipt was committed.
    pub committed_at_block: u64,
}

impl MicrotaskCommitment {
    /// Canonical commitment ID: `"commit::{receipt_id}"`.
    pub fn make_id(receipt_id: &str) -> String {
        format!("commit::{receipt_id}")
    }

    /// Serialise to a canonical byte string for hashing / signing.
    ///
    /// Format (all big-endian): `receipt_id || 0x00 || task_id || 0x00 || start_be8 || end_be8 || block_be8`
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(self.receipt_id.as_bytes());
        v.push(0x00);
        v.extend_from_slice(self.task_id.as_bytes());
        v.push(0x00);
        v.extend_from_slice(&self.task_start.to_be_bytes());
        v.extend_from_slice(&self.task_end.to_be_bytes());
        v.extend_from_slice(&self.committed_at_block.to_be_bytes());
        v
    }

    /// SHA-256 of the canonical byte representation.
    pub fn content_hash(&self) -> String {
        let mut h = Sha256::new();
        h.update(&self.canonical_bytes());
        hex::encode(h.finalize())
    }
}

// ── MicrotaskRegistry ─────────────────────────────────────────────────────────

/// In-memory registry of objectives, microtasks, and commitments.
///
/// **Persistence note (Change Set D):** This struct holds all state in `HashMap`s.
/// Change Set D will introduce a PostgreSQL-backed implementation of the same
/// logical API.  The field names here map directly to the six database tables
/// defined in the Change Set D design (`research_objectives`, `research_tasks`,
/// `verification_records`, `research_findings`, `research_artifacts`).
#[derive(Debug, Default)]
pub struct MicrotaskRegistry {
    /// All registered objectives, keyed by `objective_id`.
    pub objectives: HashMap<String, ResearchObjective>,

    /// All microtasks, keyed by `task_id`.
    pub tasks: HashMap<String, ResearchMicrotask>,

    /// Tasks indexed by `objective_id` → `Vec<task_id>` for fast lookup.
    tasks_by_objective: HashMap<String, Vec<String>>,

    /// Accepted commitments, keyed by `receipt_id`.
    pub commitments: HashMap<String, MicrotaskCommitment>,

    /// Set of `task_id`s that have already been accepted (double-reward guard).
    accepted_task_ids: std::collections::HashSet<String>,
}

impl MicrotaskRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    // ── Objective management ──────────────────────────────────────────────

    /// Register a new objective.  Returns an error if the ID already exists.
    pub fn add_objective(&mut self, objective: ResearchObjective) -> Result<(), PoCDError> {
        if self.objectives.contains_key(&objective.objective_id) {
            return Err(PoCDError::Other(format!(
                "objective already registered: {}",
                objective.objective_id
            )));
        }
        self.tasks_by_objective
            .entry(objective.objective_id.clone())
            .or_default();
        self.objectives.insert(objective.objective_id.clone(), objective);
        Ok(())
    }

    /// Add pre-decomposed tasks for an objective (e.g. from `decompose_objective`).
    ///
    /// Rejects if any `task_id` already exists in the registry (duplicate guard).
    pub fn add_tasks(&mut self, tasks: Vec<ResearchMicrotask>) -> Result<(), PoCDError> {
        // Validate all IDs first — reject the whole batch on any duplicate.
        for t in &tasks {
            if self.tasks.contains_key(&t.task_id) {
                return Err(PoCDError::Other(format!(
                    "duplicate task_id: {}",
                    t.task_id
                )));
            }
            if !self.objectives.contains_key(&t.objective_id) {
                return Err(PoCDError::Other(format!(
                    "task {} references unknown objective: {}",
                    t.task_id, t.objective_id
                )));
            }
        }
        // Insert all tasks.
        for t in tasks {
            self.tasks_by_objective
                .entry(t.objective_id.clone())
                .or_default()
                .push(t.task_id.clone());
            self.tasks.insert(t.task_id.clone(), t);
        }
        Ok(())
    }

    /// Look up an objective by ID.
    pub fn get_objective(&self, objective_id: &str) -> Option<&ResearchObjective> {
        self.objectives.get(objective_id)
    }

    // ── Task queries ──────────────────────────────────────────────────────

    /// All tasks belonging to a given objective.
    pub fn tasks_for_objective(&self, objective_id: &str) -> Vec<&ResearchMicrotask> {
        self.tasks_by_objective
            .get(objective_id)
            .map(|ids| ids.iter().filter_map(|id| self.tasks.get(id)).collect())
            .unwrap_or_default()
    }

    /// All available tasks for an objective, sorted by `task_start` ascending.
    pub fn available_tasks(&self, objective_id: &str) -> Vec<&ResearchMicrotask> {
        let mut v: Vec<&ResearchMicrotask> = self
            .tasks_for_objective(objective_id)
            .into_iter()
            .filter(|t| t.is_available())
            .collect();
        v.sort_by_key(|t| t.task_start);
        v
    }

    // ── State transitions ─────────────────────────────────────────────────

    /// Assign a task to a miner.  Returns an error if the task is not `Available`.
    pub fn assign_task(&mut self, task_id: &str, machine_id: &str) -> Result<(), PoCDError> {
        let task = self.tasks.get_mut(task_id).ok_or_else(|| {
            PoCDError::Other(format!("task not found: {task_id}"))
        })?;
        if task.status != MicrotaskStatus::Available {
            return Err(PoCDError::Other(format!(
                "task {task_id} is not Available (current: {:?})",
                task.status
            )));
        }
        task.status      = MicrotaskStatus::Assigned;
        task.assigned_to = Some(machine_id.to_string());
        Ok(())
    }

    /// Mark a task as submitted (miner posted a proof).
    pub fn mark_submitted(&mut self, task_id: &str) -> Result<(), PoCDError> {
        let task = self.tasks.get_mut(task_id).ok_or_else(|| {
            PoCDError::Other(format!("task not found: {task_id}"))
        })?;
        if task.status != MicrotaskStatus::Assigned {
            return Err(PoCDError::Other(format!(
                "task {task_id} is not Assigned (current: {:?}); cannot mark Submitted",
                task.status
            )));
        }
        task.status = MicrotaskStatus::Submitted;
        Ok(())
    }

    /// Accept a task after its receipt is confirmed.
    ///
    /// Records the commitment and guards against double-acceptance.
    pub fn accept_task(
        &mut self,
        task_id: &str,
        commitment: MicrotaskCommitment,
    ) -> Result<(), PoCDError> {
        // Double-acceptance guard.
        if self.accepted_task_ids.contains(task_id) {
            return Err(PoCDError::Other(format!(
                "task {task_id} has already been accepted (duplicate reward attempt)"
            )));
        }
        let task = self.tasks.get_mut(task_id).ok_or_else(|| {
            PoCDError::Other(format!("task not found: {task_id}"))
        })?;
        // Allow Submitted → Accepted or Assigned → Accepted (for same-turn fast-path).
        if task.status != MicrotaskStatus::Submitted && task.status != MicrotaskStatus::Assigned {
            return Err(PoCDError::Other(format!(
                "task {task_id} cannot be accepted from state {:?}",
                task.status
            )));
        }
        task.status             = MicrotaskStatus::Accepted;
        task.settled_receipt_id = Some(commitment.receipt_id.clone());
        let objective_id = task.objective_id.clone();
        self.accepted_task_ids.insert(task_id.to_string());
        self.commitments.insert(commitment.receipt_id.clone(), commitment);

        // Check whether the objective is now fully covered.
        // `objective_id` was cloned above to release the mutable borrow on `self.tasks`.
        self.maybe_complete_objective(&objective_id);
        Ok(())
    }

    /// Reject a task (invalid proof, out-of-range, etc.).
    ///
    /// The task returns to `Available` so another miner can claim it.
    pub fn reject_task(&mut self, task_id: &str) -> Result<(), PoCDError> {
        let task = self.tasks.get_mut(task_id).ok_or_else(|| {
            PoCDError::Other(format!("task not found: {task_id}"))
        })?;
        task.status      = MicrotaskStatus::Rejected;
        task.assigned_to = None;
        Ok(())
    }

    // ── Completion tracking ───────────────────────────────────────────────

    fn maybe_complete_objective(&mut self, objective_id: &str) {
        let all_accepted = self
            .tasks_for_objective(objective_id)
            .iter()
            .all(|t| t.status == MicrotaskStatus::Accepted);
        if all_accepted {
            if let Some(obj) = self.objectives.get_mut(objective_id) {
                obj.status = ObjectiveStatus::Completed;
            }
        }
    }

    /// Progress summary for an objective: `(accepted, total)`.
    pub fn objective_progress(&self, objective_id: &str) -> (usize, usize) {
        let tasks = self.tasks_for_objective(objective_id);
        let total    = tasks.len();
        let accepted = tasks.iter().filter(|t| t.status == MicrotaskStatus::Accepted).count();
        (accepted, total)
    }

    /// True when every task in the objective has been accepted.
    pub fn objective_complete(&self, objective_id: &str) -> bool {
        let (accepted, total) = self.objective_progress(objective_id);
        total > 0 && accepted == total
    }
}

