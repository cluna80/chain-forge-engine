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

impl ResourceCapabilityDescriptor {
    /// Returns `true` if this machine satisfies the minimum requirements
    /// expressed in `requirement`.
    ///
    /// Rules:
    /// - `compute_class` must match exactly.
    /// - Provider must offer at least as many `compute_units`.
    /// - Provider's `memory_tier` must be ≥ required tier.
    /// - All required `isa_tags` must be present in the provider's list
    ///   (provider may advertise more tags than required).
    ///
    /// `storage_tier`, `price_model`, `daemon_version`, and `extra` are
    /// intentionally not checked here — matchmaking policy for those lives
    /// in the marketplace layer, not in the descriptor itself.
    pub fn satisfies(&self, requirement: &ResourceCapabilityDescriptor) -> bool {
        self.compute_class == requirement.compute_class
            && self.compute_units >= requirement.compute_units
            && self.memory_tier  >= requirement.memory_tier
            && requirement.isa_tags.iter().all(|tag| self.isa_tags.contains(tag))
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn desc(
        class: ComputeClass,
        units: u32,
        mem: MemoryTier,
        tags: &[&str],
    ) -> ResourceCapabilityDescriptor {
        ResourceCapabilityDescriptor {
            compute_class:  class,
            compute_units:  units,
            memory_tier:    mem,
            storage_tier:   StorageTier::Ssd,
            isa_tags:       tags.iter().map(|s| s.to_string()).collect(),
            price_model:    PriceModel::PerJob { qrc_flat: 1_000 },
            daemon_version: "0.1.0".into(),
            extra:          Default::default(),
        }
    }

    #[test]
    fn satisfies_exact_match() {
        let provider = desc(ComputeClass::Cpu, 8, MemoryTier::Medium, &["AVX2"]);
        let req      = desc(ComputeClass::Cpu, 8, MemoryTier::Medium, &["AVX2"]);
        assert!(provider.satisfies(&req));
    }

    #[test]
    fn satisfies_superset_units_and_memory() {
        let provider = desc(ComputeClass::Gpu, 64, MemoryTier::XLarge, &["CUDA12"]);
        let req      = desc(ComputeClass::Gpu,  8, MemoryTier::Large,  &["CUDA12"]);
        assert!(provider.satisfies(&req));
    }

    #[test]
    fn satisfies_superset_isa_tags() {
        // Provider advertises more tags than required — still satisfies.
        let provider = desc(ComputeClass::Cpu, 16, MemoryTier::Large, &["AVX2", "AVX512", "AMX"]);
        let req      = desc(ComputeClass::Cpu, 16, MemoryTier::Large, &["AVX2"]);
        assert!(provider.satisfies(&req));
    }

    #[test]
    fn rejects_wrong_compute_class() {
        let provider = desc(ComputeClass::Cpu, 8, MemoryTier::Medium, &[]);
        let req      = desc(ComputeClass::Gpu, 8, MemoryTier::Medium, &[]);
        assert!(!provider.satisfies(&req));
    }

    #[test]
    fn rejects_insufficient_units() {
        let provider = desc(ComputeClass::Cpu, 4, MemoryTier::Large, &[]);
        let req      = desc(ComputeClass::Cpu, 8, MemoryTier::Large, &[]);
        assert!(!provider.satisfies(&req));
    }

    #[test]
    fn rejects_insufficient_memory() {
        let provider = desc(ComputeClass::Cpu, 8, MemoryTier::Small, &[]);
        let req      = desc(ComputeClass::Cpu, 8, MemoryTier::Medium, &[]);
        assert!(!provider.satisfies(&req));
    }

    #[test]
    fn rejects_missing_isa_tag() {
        let provider = desc(ComputeClass::Cpu, 8, MemoryTier::Large, &["AVX2"]);
        let req      = desc(ComputeClass::Cpu, 8, MemoryTier::Large, &["AVX2", "AVX512"]);
        assert!(!provider.satisfies(&req));
    }

    #[test]
    fn no_required_isa_tags_always_ok() {
        let provider = desc(ComputeClass::Gpu, 32, MemoryTier::Medium, &[]);
        let req      = desc(ComputeClass::Gpu, 16, MemoryTier::Small,  &[]);
        assert!(provider.satisfies(&req));
    }
}
