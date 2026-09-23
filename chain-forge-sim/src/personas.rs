//! Concrete personas. See lib.rs for the scope caveat that applies to
//! every one of these -- including the ones named "fault injection" below,
//! which test robustness and negative paths, not sybil resistance.

use crate::context::{SimContext, TxOutcome};
use crate::persona::{CheckResult, Persona};
use anyhow::Result;
use chain_forge_execution::Transaction;

/// The genesis validator addresses, seeded as Verified at Node startup
/// specifically so there is a root for the web-of-trust to grow from
/// (see the regression test in chain-forge-node:
/// genesis_validators_are_seeded_as_verified_identities). Personas that
/// need to become Verified draw their first attestations from this pool.
pub const SEED_ATTESTERS: [&str; 3] = ["qcb1alice", "qcb1bob", "qcb1carol"];

/// Shared bootstrap step: submit an attest transaction from each of the
/// given seed addresses, vouching for `claimant_id`. Used by every persona
/// that needs to reach Verified tier without waiting on organic peer
/// attestations that may not exist yet this early in a short sim run.
async fn bootstrap_via_seeds(
    claimant_id: &str,
    seeds: &[&str],
    ctx: &mut SimContext,
) -> Result<()> {
    for seed in seeds {
        let nonce = ctx.next_nonce(seed);
        let tx = Transaction::attest(
            &format!("bootstrap-{seed}-{claimant_id}"),
            seed, claimant_id, nonce,
        );
        ctx.submit_tx(seed, "attest_bootstrap", tx).await?;
    }
    Ok(())
}

fn tier_check(actual: Option<String>, expected: &str, label: &str) -> CheckResult {
    match &actual {
        Some(t) if t == expected =>
            CheckResult::pass(format!("{label}: tier is {expected}")),
        Some(t) =>
            CheckResult::fail(format!("{label}: expected tier {expected}"), format!("actual: {t}")),
        None =>
            CheckResult::fail(format!("{label}: expected tier {expected}"), "account not found or no tier".to_string()),
    }
}

// -- 1. Happy path: full registration -> quorum -> UBI claim ------------------

pub struct HonestEarlyAdopter;

#[async_trait::async_trait]
impl Persona for HonestEarlyAdopter {
    fn id(&self) -> &str { "sim-alice" }

    async fn run_epoch(&mut self, epoch: u64, ctx: &mut SimContext) -> Result<()> {
        match epoch {
            0 => {
                let nonce = ctx.next_nonce(self.id());
                let tx = Transaction::register_identity("sim-alice-reg", self.id(), nonce);
                ctx.submit_tx(self.id(), "register_identity", tx).await?;
            }
            1 => {
                bootstrap_via_seeds(self.id(), &SEED_ATTESTERS, ctx).await?;
            }
            3 => {
                let nonce = ctx.next_nonce(self.id());
                let tx = Transaction::claim_ubi("sim-alice-ubi", self.id(), self.id(), nonce);
                ctx.submit_tx(self.id(), "claim_ubi", tx).await?;
            }
            _ => {}
        }
        Ok(())
    }

    async fn check_expectations(&self, epoch: u64, ctx: &SimContext) -> Vec<CheckResult> {
        let mut checks = Vec::new();
        if epoch == 1 {
            let acct = ctx.get_account(self.id()).await.ok().flatten();
            checks.push(tier_check(acct.and_then(|a| a.tier), "Provisional", "sim-alice pre-quorum"));
        }
        if epoch == 2 {
            let acct = ctx.get_account(self.id()).await.ok().flatten();
            checks.push(tier_check(acct.and_then(|a| a.tier), "Verified", "sim-alice post-quorum"));
        }
        if epoch == 4 {
            if let Ok(Some(acct)) = ctx.get_account(self.id()).await {
                let has_cirfi = acct.balances.get("ucirfi").copied().unwrap_or(0) > 0;
                checks.push(if has_cirfi {
                    CheckResult::pass("sim-alice: UBI claim credited ucirfi balance")
                } else {
                    CheckResult::fail("sim-alice: UBI claim credited ucirfi balance", "balance is zero")
                });
            }
        }
        checks
    }
}

// -- 2. Reliable attester: bootstrapped, then attests a newcomer organically --

pub struct ReliableAttester;

#[async_trait::async_trait]
impl Persona for ReliableAttester {
    fn id(&self) -> &str { "sim-bob" }

    async fn run_epoch(&mut self, epoch: u64, ctx: &mut SimContext) -> Result<()> {
        match epoch {
            0 => {
                let nonce = ctx.next_nonce(self.id());
                let tx = Transaction::register_identity("sim-bob-reg", self.id(), nonce);
                ctx.submit_tx(self.id(), "register_identity", tx).await?;
            }
            1 => {
                bootstrap_via_seeds(self.id(), &SEED_ATTESTERS, ctx).await?;
            }
            // By epoch 3, sim-bob is Verified and can attest organically --
            // this exercises peer-to-peer (non-seed) attestation, alongside
            // Newcomer's other two attesters (see Newcomer below).
            3 => {
                let nonce = ctx.next_nonce(self.id());
                let tx = Transaction::attest("sim-bob-attests-newcomer", self.id(), "sim-newcomer", nonce);
                ctx.submit_tx(self.id(), "attest_organic", tx).await?;
            }
            _ => {}
        }
        Ok(())
    }

    async fn check_expectations(&self, epoch: u64, ctx: &SimContext) -> Vec<CheckResult> {
        let mut checks = Vec::new();
        if epoch == 2 {
            let acct = ctx.get_account(self.id()).await.ok().flatten();
            checks.push(tier_check(acct.and_then(|a| a.tier), "Verified", "sim-bob post-quorum"));
        }
        checks
    }
}

// -- Newcomer: verified via a MIX of seed + peer attestation ------------------

pub struct Newcomer;

#[async_trait::async_trait]
impl Persona for Newcomer {
    fn id(&self) -> &str { "sim-newcomer" }

    async fn run_epoch(&mut self, epoch: u64, ctx: &mut SimContext) -> Result<()> {
        if epoch == 0 {
            let nonce = ctx.next_nonce(self.id());
            let tx = Transaction::register_identity("sim-newcomer-reg", self.id(), nonce);
            ctx.submit_tx(self.id(), "register_identity", tx).await?;
        }
        // No self-driven attestation collection -- Newcomer's quorum is
        // completed by sim-bob (peer) at epoch 3 plus two seed attesters
        // submitted here at epoch 2, deliberately mixing the two paths.
        if epoch == 2 {
            for seed in &SEED_ATTESTERS[..2] {
                let nonce = ctx.next_nonce(seed);
                let tx = Transaction::attest(&format!("seed-{seed}-newcomer"), seed, self.id(), nonce);
                ctx.submit_tx(seed, "attest_bootstrap", tx).await?;
            }
        }
        Ok(())
    }

    async fn check_expectations(&self, epoch: u64, ctx: &SimContext) -> Vec<CheckResult> {
        let mut checks = Vec::new();
        if epoch == 4 {
            let acct = ctx.get_account(self.id()).await.ok().flatten();
            checks.push(tier_check(acct.and_then(|a| a.tier), "Verified",
                "sim-newcomer (2 seed + 1 peer attestation)"));
        }
        checks
    }
}

// -- 3. Dormant participant: verified, then goes inactive ---------------------

pub struct DormantParticipant;

#[async_trait::async_trait]
impl Persona for DormantParticipant {
    fn id(&self) -> &str { "sim-carol" }

    async fn run_epoch(&mut self, epoch: u64, ctx: &mut SimContext) -> Result<()> {
        match epoch {
            0 => {
                let nonce = ctx.next_nonce(self.id());
                let tx = Transaction::register_identity("sim-carol-reg", self.id(), nonce);
                ctx.submit_tx(self.id(), "register_identity", tx).await?;
            }
            1 => {
                bootstrap_via_seeds(self.id(), &SEED_ATTESTERS, ctx).await?;
            }
            // Deliberately nothing after this -- the point is to go dark.
            _ => {}
        }
        Ok(())
    }

    async fn check_expectations(&self, epoch: u64, ctx: &SimContext) -> Vec<CheckResult> {
        let mut checks = Vec::new();
        if epoch == 2 {
            let acct = ctx.get_account(self.id()).await.ok().flatten();
            checks.push(tier_check(acct.and_then(|a| a.tier), "Verified", "sim-carol before going dormant"));
        }
        // Informational only, not a hard pass/fail: a real liveness lapse
        // needs epochs >= the identity module's liveness window, which is
        // far longer than a short demo run. A long-run configuration can
        // extend epochs past that window to turn this into a real check.
        if epoch >= 5 {
            let acct = ctx.get_account(self.id()).await.ok().flatten();
            let tier = acct.and_then(|a| a.tier).unwrap_or_else(|| "unknown".into());
            checks.push(CheckResult::pass(format!(
                "sim-carol dormant since epoch 1 -- tier currently {tier} (informational; \
                 liveness lapse requires more epochs than a short run covers)"
            )));
        }
        checks
    }
}

// -- 4. Fault injection: duplicate registration --------------------------------

pub struct DuplicateRegistrationAttempt {
    second_attempt_rejected: Option<bool>,
}

impl DuplicateRegistrationAttempt {
    pub fn new() -> Self { Self { second_attempt_rejected: None } }
}

#[async_trait::async_trait]
impl Persona for DuplicateRegistrationAttempt {
    fn id(&self) -> &str { "sim-duptest" }

    async fn run_epoch(&mut self, epoch: u64, ctx: &mut SimContext) -> Result<()> {
        match epoch {
            0 => {
                let nonce = ctx.next_nonce(self.id());
                let tx = Transaction::register_identity("sim-duptest-reg1", self.id(), nonce);
                ctx.submit_tx(self.id(), "register_identity", tx).await?;
            }
            1 => {
                // Same identity id, fresh nonce -- the live node must
                // reject this as a duplicate, not silently overwrite or
                // create a second record.
                let nonce = ctx.next_nonce(self.id());
                let tx = Transaction::register_identity("sim-duptest-reg2", self.id(), nonce);
                let outcome = ctx.submit_tx(self.id(), "register_identity_duplicate", tx).await?;
                self.second_attempt_rejected = Some(matches!(
                    outcome,
                    TxOutcome::Confirmed { success: false, .. } | TxOutcome::RejectedAtSubmission { .. }
                ));
            }
            _ => {}
        }
        Ok(())
    }

    async fn check_expectations(&self, epoch: u64, _ctx: &SimContext) -> Vec<CheckResult> {
        if epoch != 1 { return Vec::new(); }
        match self.second_attempt_rejected {
            Some(true)  => vec![CheckResult::pass("duplicate registration correctly rejected")],
            Some(false) => vec![CheckResult::fail("duplicate registration correctly rejected",
                "second attempt was NOT rejected -- possible state corruption")],
            None => vec![CheckResult::fail("duplicate registration correctly rejected",
                "second attempt outcome unknown -- submit_tx may have errored at the transport level")],
        }
    }
}

// -- 5. Fault injection: self-attestation --------------------------------------

pub struct SelfAttestationAttempt {
    rejected: Option<bool>,
}

impl SelfAttestationAttempt {
    pub fn new() -> Self { Self { rejected: None } }
}

#[async_trait::async_trait]
impl Persona for SelfAttestationAttempt {
    fn id(&self) -> &str { "sim-selfattest" }

    async fn run_epoch(&mut self, epoch: u64, ctx: &mut SimContext) -> Result<()> {
        match epoch {
            0 => {
                let nonce = ctx.next_nonce(self.id());
                let tx = Transaction::register_identity("sim-selfattest-reg", self.id(), nonce);
                ctx.submit_tx(self.id(), "register_identity", tx).await?;
            }
            1 => {
                // self-attestation is rejected before the attester-tier
                // check even runs, so this persona never needs to become
                // Verified first -- attempting it as Provisional is fine
                // and is in fact the more realistic attack shape.
                let nonce = ctx.next_nonce(self.id());
                let tx = Transaction::attest("sim-selfattest-tx", self.id(), self.id(), nonce);
                let outcome = ctx.submit_tx(self.id(), "self_attest", tx).await?;
                self.rejected = Some(matches!(
                    outcome,
                    TxOutcome::Confirmed { success: false, .. } | TxOutcome::RejectedAtSubmission { .. }
                ));
            }
            _ => {}
        }
        Ok(())
    }

    async fn check_expectations(&self, epoch: u64, _ctx: &SimContext) -> Vec<CheckResult> {
        if epoch != 1 { return Vec::new(); }
        match self.rejected {
            Some(true)  => vec![CheckResult::pass("self-attestation correctly rejected")],
            Some(false) => vec![CheckResult::fail("self-attestation correctly rejected",
                "was NOT rejected -- real bug, identity could vouch for itself")],
            None => vec![CheckResult::fail("self-attestation correctly rejected", "outcome unknown")],
        }
    }
}

// -- 6. Fault injection: per-epoch attestation rate limit ----------------------

pub struct RateLimitProber {
    sixth_rejected: Option<bool>,
}

impl RateLimitProber {
    pub fn new() -> Self { Self { sixth_rejected: None } }
}

#[async_trait::async_trait]
impl Persona for RateLimitProber {
    fn id(&self) -> &str { "sim-ratelimit" }

    async fn run_epoch(&mut self, epoch: u64, ctx: &mut SimContext) -> Result<()> {
        match epoch {
            0 => {
                let nonce = ctx.next_nonce(self.id());
                let tx = Transaction::register_identity("sim-ratelimit-reg", self.id(), nonce);
                ctx.submit_tx(self.id(), "register_identity", tx).await?;
                // Also register 6 disposable claimants for this persona to
                // (attempt to) vouch for once it's Verified.
                for i in 0..6 {
                    let claimant = format!("sim-ratelimit-claimant{i}");
                    let nonce = ctx.next_nonce(&claimant);
                    let tx = Transaction::register_identity(&format!("{claimant}-reg"), &claimant, nonce);
                    ctx.submit_tx(&claimant, "register_identity", tx).await?;
                }
            }
            1 => {
                bootstrap_via_seeds(self.id(), &SEED_ATTESTERS, ctx).await?;
            }
            // MAX_ATTESTATIONS_PER_EPOCH is 5 -- attempt all 6 in one epoch.
            3 => {
                let mut last_outcome = None;
                for i in 0..6 {
                    let claimant = format!("sim-ratelimit-claimant{i}");
                    let nonce = ctx.next_nonce(self.id());
                    let tx = Transaction::attest(
                        &format!("sim-ratelimit-attest{i}"), self.id(), &claimant, nonce,
                    );
                    last_outcome = Some(ctx.submit_tx(self.id(), "attest_ratelimit_probe", tx).await?);
                }
                self.sixth_rejected = last_outcome.map(|o| matches!(
                    o,
                    TxOutcome::Confirmed { success: false, .. } | TxOutcome::RejectedAtSubmission { .. }
                ));
            }
            _ => {}
        }
        Ok(())
    }

    async fn check_expectations(&self, epoch: u64, _ctx: &SimContext) -> Vec<CheckResult> {
        if epoch != 3 { return Vec::new(); }
        match self.sixth_rejected {
            Some(true)  => vec![CheckResult::pass("6th attestation in one epoch correctly rate-limited")],
            Some(false) => vec![CheckResult::fail("6th attestation in one epoch correctly rate-limited",
                "was NOT rejected -- rate limit not enforced end-to-end")],
            None => vec![CheckResult::fail("6th attestation in one epoch correctly rate-limited", "outcome unknown")],
        }
    }
}

// -- 7. Fault injection / robustness: malformed request -----------------------

pub struct MalformedTransactionSender {
    got_client_error: Option<bool>,
}

impl MalformedTransactionSender {
    pub fn new() -> Self { Self { got_client_error: None } }
}

#[async_trait::async_trait]
impl Persona for MalformedTransactionSender {
    fn id(&self) -> &str { "sim-malformed" }

    async fn run_epoch(&mut self, epoch: u64, ctx: &mut SimContext) -> Result<()> {
        if epoch == 0 {
            let status = ctx.submit_raw_malformed(self.id(), "{ this is not valid json at all").await?;
            self.got_client_error = Some((400..500).contains(&status));
        }
        Ok(())
    }

    async fn check_expectations(&self, epoch: u64, _ctx: &SimContext) -> Vec<CheckResult> {
        if epoch != 0 { return Vec::new(); }
        match self.got_client_error {
            Some(true)  => vec![CheckResult::pass("malformed transaction correctly rejected with 4xx, node did not crash")],
            Some(false) => vec![CheckResult::fail("malformed transaction correctly rejected with 4xx",
                "response was not a 4xx -- check node health immediately")],
            None => vec![CheckResult::fail("malformed transaction correctly rejected with 4xx",
                "no response at all -- the node may have crashed or hung")],
        }
    }
}

/// The standard roster -- everything this crate ships, ready to hand to a
/// SimRunner. Callers can also build their own subset directly from the
/// individual persona types above.
pub fn standard_roster() -> Vec<Box<dyn Persona>> {
    vec![
        Box::new(HonestEarlyAdopter),
        Box::new(ReliableAttester),
        Box::new(Newcomer),
        Box::new(DormantParticipant),
        Box::new(DuplicateRegistrationAttempt::new()),
        Box::new(SelfAttestationAttempt::new()),
        Box::new(RateLimitProber::new()),
        Box::new(MalformedTransactionSender::new()),
    ]
}
