//! Resource capability descriptor.
//!
//! A `ResourceCapabilityDescriptor` is the machine's self-declaration of
//! what hardware it offers and how much it charges.  Agents query the
//! marketplace to find machines whose descriptor satisfies the job's
//! resource requirements.

use serde::{Deserialize, Serialize};

/// Broad category of compute this machine offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComputeClass {
    /// General-purpose CPU work.
    Cpu,
    /// GPU-accelerated work (ML, simulation, rendering).
    Gpu,
    /// Tensor-Processing-Unit accelerated work.
    Tpu,
    /// Quantum Processing Unit (experimental).
    Qpu,
}

/// Memory tier, expressed as a rough bracket rather than an exact byte
/// count — exact figures vary too much between machines to be useful for
/// matchmaking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum MemoryTier {
    /// < 16 GiB
    Small,
    /// 16–63 GiB
    Medium,
    /// 64–255 GiB
    Large,
    /// ≥ 256 GiB
    XLarge,
}

/// Storage tier (RAM disk, NVMe, spinning disk, network-attached).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StorageTier {
    RamDisk,
    Nvme,
    Ssd,
    Hdd,
    NetworkAttached,
}

/// QRC price model for this machine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PriceModel {
    /// Flat QRC per second of wall-clock time.
    PerSecond { qrc_per_second: u64 },
    /// Flat QRC per job regardless of duration.
    PerJob { qrc_flat: u64 },
    /// Dynamic: set at job match time via sealed-bid auction.
    Auction,
}

/// Full capability advertisement broadcast by a resource node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceCapabilityDescriptor {
    /// Type of compute offered.
    pub compute_class: ComputeClass,
    /// Number of logical cores / shader units / etc.
    pub compute_units: u32,
    /// Rough memory bracket.
    pub memory_tier: MemoryTier,
    /// Rough storage type.
    pub storage_tier: StorageTier,
    /// Supported instruction-set tags (e.g. `["AVX512", "CUDA12"]`).
    pub isa_tags: Vec<String>,
    /// How this machine bills for its work.
    pub price_model: PriceModel,
    /// Semantic version of the machine daemon software.
    pub daemon_version: String,
    /// Arbitrary metadata the operator wants to advertise.
    pub extra: std::collections::HashMap<String, String>,
}
