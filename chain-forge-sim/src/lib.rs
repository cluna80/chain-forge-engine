//! chain-forge-sim -- a live integration-test harness for the identity and
//! agent systems, driving a set of scripted personas against a REAL running
//! chain-forge-node over its actual HTTP API.
//!
//! # Scope -- read this before using any output from this crate
//!
//! This is a mechanical integration test. It is explicitly NOT a test of
//! sybil resistance, and its output must never be represented as evidence
//! that the identity layer resists real adversarial pressure. The Identity
//! Pilot Design document (Section 2, "What the Pilot Is Not") names exactly
//! why: "the pilot tests whether the humans feeding the identity layer are
//! real humans" -- and a persona in this crate is software whose every
//! action was written by the same person who wrote the code being tested.
//! A "fault injection" persona here can only execute the exact failure
//! mode its author anticipated; it cannot probe for a weakness nobody
//! thought to test, which is the entire point of needing real adversarial
//! pressure. See the pilot doc for the real Phase 1 (10-50 known human
//! participants) and Phase 2 (larger real-world adversarial pilot).
//!
//! What this crate IS good for, honestly:
//! - Confirming the mechanical loop (register -> attest -> quorum -> tier
//!   upgrade -> UBI claim) works correctly against the live API, not just
//!   in isolated unit tests
//! - Exercising liveness/epoch logic over real, sustained time rather than
//!   synthetic epoch jumps
//! - Fault-injection / negative-path testing: does the live node correctly
//!   reject a duplicate registration, a self-attestation, a rate-limit
//!   violation, a malformed request -- without crashing or corrupting state
//!
//! Run its output through your own judgment. It belongs in an internal
//! engineering log, not the whitepaper.

pub mod context;
pub mod persona;
pub mod report;
pub mod personas;

pub use context::SimContext;
pub use persona::{Persona, CheckResult};
pub use report::{SimReport, EpochReport};

use anyhow::Result;

/// Runs a fixed set of personas for a fixed number of simulated epochs
/// against a live node, producing a SimReport.
pub struct SimRunner {
    personas: Vec<Box<dyn Persona>>,
    ctx:      SimContext,
    epochs:   u64,
    /// How long to wait between epochs, giving the real testnet underneath
    /// time to actually commit the blocks a persona's transactions from
    /// this epoch depend on before the next epoch's checks run.
    epoch_pause: std::time::Duration,
}

impl SimRunner {
    pub fn new(
        base_url: impl Into<String>,
        epochs: u64,
        epoch_pause: std::time::Duration,
    ) -> Self {
        Self {
            personas: Vec::new(),
            ctx: SimContext::new(base_url.into()),
            epochs,
            epoch_pause,
        }
    }

    /// Connect to the node (chain_id) and load named-account key files.
    /// Must be called once before run().
    pub async fn init(&mut self, keys_dir: Option<&std::path::Path>) -> Result<()> {
        self.ctx.init(keys_dir).await
    }

    pub fn add_persona(&mut self, p: Box<dyn Persona>) -> &mut Self {
        self.personas.push(p);
        self
    }

    pub async fn run(&mut self) -> Result<SimReport> {
        let mut report = SimReport::new(self.personas.iter().map(|p| p.id().to_string()).collect());

        // Collect all persona IDs upfront so we can check registration
        // landed before proceeding past epoch 0.
        let persona_ids: Vec<String> = self.personas.iter()
            .filter(|p| p.registers_on_chain())
            .map(|p| p.id().to_string())
            .collect();

        for epoch in 0..self.epochs {
            tracing::info!(epoch, personas = self.personas.len(), "epoch starting");
            let mut epoch_report = EpochReport::new(epoch);

            for persona in self.personas.iter_mut() {
                match persona.run_epoch(epoch, &mut self.ctx).await {
                    Ok(()) => {}
                    Err(e) => {
                        tracing::warn!(persona = persona.id(), error = %e, "persona run_epoch errored");
                        epoch_report.persona_errors.push((persona.id().to_string(), e.to_string()));
                    }
                }
            }

            // Give the live testnet time to actually process what just
            // happened before checking expectations against it.
            tokio::time::sleep(self.epoch_pause).await;

            // After epoch 0 specifically, wait until all persona accounts
            // actually appear on-chain before proceeding. If registrations
            // were slow to commit (still queued at end of epoch 0), epoch 1
            // attestations will fail with "identity not found" and cascade
            // failures through the rest of the run. This barrier prevents
            // that without changing epoch_pause globally.
            if epoch == 0 {
                tracing::info!("epoch 0 complete -- waiting for all registrations to confirm on-chain");
                for id in &persona_ids {
                    let confirmed = self.ctx.wait_for_account(
                        id,
                        30,
                        std::time::Duration::from_secs(1),
                    ).await;
                    if !confirmed {
                        tracing::warn!(persona_id = id, "registration still not confirmed after barrier -- proceeding anyway");
                    }
                }
                tracing::info!("registration barrier passed");
            }

            for persona in self.personas.iter() {
                let checks = persona.check_expectations(epoch, &self.ctx).await;
                epoch_report.checks.extend(
                    checks.into_iter().map(|c| (persona.id().to_string(), c))
                );
            }

            epoch_report.tx_log = self.ctx.drain_epoch_log();
            report.epochs.push(epoch_report);
        }

        Ok(report)
    }
}
