//! PQ-HotStuff-2 consensus engine (docs/pq-hotstuff-001-spec.md).
//!
//! Phase 0 step 1: the canonical byte layouts of section 3.2 (`wire`). Phase 1 step 1: the crash-safe safety-state
//! persistence of section 7 (`safety`). No engine, no network activation.
pub mod wire;
pub mod safety;
