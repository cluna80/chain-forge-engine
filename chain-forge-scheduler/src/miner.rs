//! Miner registry — tracks which miners are online and what workloads they accept.
//!
//! The registry is purely in-memory.  It is re-populated from `POST
//! /scheduler/miners/register` calls after a scheduler restart.  Miners that
//! do not re-register after restart are simply not offered new tasks; their
//! in-flight tasks (if any) are handled by the lease-expiry sweep.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};

/// A single registered miner.
#[derive(Debug, Clone)]
pub struct MinerInfo {
    pub miner_id:      String,
    pub workload_class: String,
    /// Wall-clock time of the most recent registration (or heartbeat).
    pub last_seen:     DateTime<Utc>,
}

/// Thread-safe registry of online miners.
#[derive(Clone, Default)]
pub struct MinerRegistry {
    inner: Arc<Mutex<HashMap<String, MinerInfo>>>,
}

impl MinerRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register (or refresh) a miner.  Idempotent — a second registration
    /// from the same `miner_id` updates `last_seen` and `workload_class`.
    pub fn register(&self, miner_id: impl Into<String>, workload_class: impl Into<String>) {
        let miner_id      = miner_id.into();
        let workload_class = workload_class.into();
        let mut map = self.inner.lock().unwrap();
        map.insert(
            miner_id.clone(),
            MinerInfo {
                miner_id,
                workload_class,
                last_seen: Utc::now(),
            },
        );
    }

    /// Return a snapshot of all registered miners.
    pub fn all(&self) -> Vec<MinerInfo> {
        self.inner.lock().unwrap().values().cloned().collect()
    }

    /// Return miners that accept a given workload class.
    pub fn for_workload(&self, workload_class: &str) -> Vec<MinerInfo> {
        self.inner
            .lock()
            .unwrap()
            .values()
            .filter(|m| m.workload_class == workload_class)
            .cloned()
            .collect()
    }

    /// Remove a miner from the registry.
    pub fn deregister(&self, miner_id: &str) {
        self.inner.lock().unwrap().remove(miner_id);
    }

    pub fn count(&self) -> usize {
        self.inner.lock().unwrap().len()
    }
}
