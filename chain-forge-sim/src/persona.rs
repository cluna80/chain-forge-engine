//! The Persona trait -- every simulated participant implements this.

use crate::context::SimContext;
use anyhow::Result;

/// The result of one persona checking whether something it expected to be
/// true about the live chain actually is, after an epoch's actions have
/// had time to settle.
#[derive(Debug, Clone)]
pub struct CheckResult {
    /// A short, human-readable description of what was being checked.
    pub description: String,
    pub passed:       bool,
    /// Optional extra detail -- e.g. the actual value found, if it
    /// differed from what was expected.
    pub detail:        Option<String>,
}

impl CheckResult {
    pub fn pass(description: impl Into<String>) -> Self {
        Self { description: description.into(), passed: true, detail: None }
    }

    pub fn fail(description: impl Into<String>, detail: impl Into<String>) -> Self {
        Self { description: description.into(), passed: false, detail: Some(detail.into()) }
    }
}

#[async_trait::async_trait]
pub trait Persona: Send + Sync {
    /// A short, stable identifier for this persona (used as the sender
    /// address for its transactions, and as the report's row key).
    fn id(&self) -> &str;

    /// Take whatever action this persona is scripted to take during this
    /// epoch. Not every persona acts every epoch -- a dormant persona's
    /// run_epoch may be a no-op most of the time.
    async fn run_epoch(&mut self, epoch: u64, ctx: &mut SimContext) -> Result<()>;

    /// After this epoch's actions have had time to settle (SimRunner
    /// pauses before calling this), assert whatever this persona expects
    /// to be true about its own on-chain state right now. Returns an
    /// empty Vec for epochs where this persona has nothing to check yet.
    async fn check_expectations(&self, epoch: u64, ctx: &SimContext) -> Vec<CheckResult>;
}
