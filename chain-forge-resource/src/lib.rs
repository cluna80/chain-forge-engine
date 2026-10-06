//! # chain-forge-resource
//!
//! Resource market layer for QCB Chain.
//!
//! ## What this crate provides
//!
//! | Module | Contents |
//! |--------|----------|
//! | `types::machine`     | `MachineRecord`, `MachineId`, `MachineMode`, `ProviderOwner` |
//! | `types::capability`  | `ResourceCapabilityDescriptor` — hardware advertisement |
//! | `types::job`         | `ResourceJob` + full `CREATED→SETTLED` state machine |
//! | `types::receipt`     | `ResourceExecutionReceipt`, `UsefulWorkReceipt` |
//! | `types::escrow`      | `LockQrcForJob`, `ReleaseQrcForJob`, `RefundQrcForJob` |
//! | `error`              | `ResourceError` — typed error enum |
//!
//! ## Phase 0 goal
//!
//! One end-to-end resource purchase: Alice's agent locks QRC, Carol's
//! machine runs the job, an independent verifier signs the output, escrow
//! releases to Carol, the receipt is committed on-chain.  All 10 Phase-0
//! attack scenarios must be handled by the state machine and escrow types
//! defined here.
//!
//! ## What is NOT here yet
//!
//! * Matchmaking engine (will live in `chain-forge-agents`)
//! * Persistence / storage (will live in `chain-forge-state`)
//! * On-chain transaction submission (will live in `chain-forge-execution`)
//! * Real Ed25519 signing (will live in `chain-forge-crypto` / `chain-forge-identity`)

pub mod error;
pub mod types;

// Convenience re-exports so downstream crates can write
// `chain_forge_resource::MachineRecord` instead of the full path.
pub use error::ResourceError;
pub use types::capability::{ComputeClass, MemoryTier, PriceModel, ResourceCapabilityDescriptor, StorageTier};
pub use types::escrow::{LockQrcForJob, RefundQrcForJob, RefundReason, ReleaseQrcForJob};
pub use types::job::{AgentId, JobId, JobSpec, JobState, ResourceJob, StateTransition};
pub use types::machine::{
    EnterpriseId, MachineAttestationKey, MachineId, MachineMode, MachineRecord, MachineStatus,
    ProviderOwner, SponsorId,
};
pub use types::receipt::{ResourceExecutionReceipt, UsefulWorkReceipt, WorkType};
