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
        // Seed attesters are pre-existing genesis validator accounts whose
        // on-chain nonce is already ahead of 0 (they've committed blocks).
        // Sync the local counter before the first use so nonce mismatches
        // don't silently reject every attestation.
        ctx.sync_nonce(seed).await?;
        let nonce = ctx.next_nonce(seed);
        let tx = Transaction::attest(
            &format!("bootstrap-{seed}-{claimant_id}"),
            seed, claimant_id, nonce,
        );
        ctx.submit_tx(seed, "attest_bootstrap", tx).await?;
    }
    Ok(())
}

/// A fault-injection check only counts as a pass if the node rejected the
/// transaction for the specific reason being tested. Any other failure --
/// most importantly a nonce mismatch, which is how the first "clean" live
/// run produced three false passes -- is reported as a FAIL with the real
/// error attached, so a check can never pass by accident again.
fn rejected_for(outcome: &TxOutcome, expected_fragment: &str) -> Result<(), String> {
    match outcome {
        TxOutcome::Confirmed { success: false, error: Some(e), .. } if e.contains(expected_fragment) => Ok(()),
        TxOutcome::Confirmed { success: false, error, .. } =>
            Err(format!("rejected, but for the wrong reason: {}", error.clone().unwrap_or_default())),
        TxOutcome::Confirmed { success: true, .. } => Err("was accepted -- guard did not fire".into()),
        TxOutcome::RejectedAtSubmission { message } =>
            Err(format!("rejected at submission instead of by the guard: {message}")),
        TxOutcome::Queued => Err("never confirmed -- outcome unknown".into()),
    }
}

/// Like rejected_for, but for rejections the API is expected to make at
/// submission (the stateless signature pre-check), before execution.
fn rejected_at_submission_for(outcome: &TxOutcome, expected_fragment: &str) -> Result<(), String> {
    match outcome {
        TxOutcome::RejectedAtSubmission { message } if message.contains(expected_fragment) => Ok(()),
        TxOutcome::RejectedAtSubmission { message } =>
            Err(format!("rejected at submission, but for the wrong reason: {message}")),
        TxOutcome::Confirmed { success: true, .. } => Err("was accepted and executed -- signature check did not fire".into()),
        TxOutcome::Confirmed { success: false, error, .. } =>
            Err(format!("got past the API pre-check and failed at execution instead: {}", error.clone().unwrap_or_default())),
        TxOutcome::Queued => Err("was queued -- the API pre-check did not reject it".into()),
    }
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
                ctx.sync_nonce(self.id()).await?;
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
        // Note: pre-quorum check removed -- sim-alice can reach quorum
        // within epoch 1 itself if attestations commit quickly, making
        // the "expected Provisional at end of epoch 1" assertion
        // timing-dependent rather than a real invariant.
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
                ctx.sync_nonce(self.id()).await?;
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
                ctx.sync_nonce(seed).await?;
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
    verdict: Option<Result<(), String>>,
}

impl DuplicateRegistrationAttempt {
    pub fn new() -> Self { Self { verdict: None } }
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
                self.verdict = Some(rejected_for(&outcome, "already exists"));
            }
            _ => {}
        }
        Ok(())
    }

    async fn check_expectations(&self, epoch: u64, _ctx: &SimContext) -> Vec<CheckResult> {
        if epoch != 1 { return Vec::new(); }
        match &self.verdict {
            Some(Ok(()))   => vec![CheckResult::pass("duplicate registration rejected by the already-exists guard")],
            Some(Err(why)) => vec![CheckResult::fail("duplicate registration rejected by the already-exists guard", why.clone())],
            None => vec![CheckResult::fail("duplicate registration rejected by the already-exists guard",
                "second attempt never ran -- submit_tx errored at the transport level")],
        }
    }
}

// -- 5. Fault injection: self-attestation --------------------------------------

pub struct SelfAttestationAttempt {
    verdict: Option<Result<(), String>>,
}

impl SelfAttestationAttempt {
    pub fn new() -> Self { Self { verdict: None } }
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
                self.verdict = Some(rejected_for(&outcome, "cannot attest for itself"));
            }
            _ => {}
        }
        Ok(())
    }

    async fn check_expectations(&self, epoch: u64, _ctx: &SimContext) -> Vec<CheckResult> {
        if epoch != 1 { return Vec::new(); }
        match &self.verdict {
            Some(Ok(()))   => vec![CheckResult::pass("self-attestation rejected by the self-attest guard")],
            Some(Err(why)) => vec![CheckResult::fail("self-attestation rejected by the self-attest guard", why.clone())],
            None => vec![CheckResult::fail("self-attestation rejected by the self-attest guard", "attempt never ran")],
        }
    }
}

// -- 6. Fault injection: per-epoch attestation rate limit ----------------------

pub struct RateLimitProber {
    verdict: Option<Result<(), String>>,
}

impl RateLimitProber {
    pub fn new() -> Self { Self { verdict: None } }
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
                // Sync own nonce -- this persona registered in epoch 0
                // but hasn't transacted since, so the local counter is
                // still 0 while on-chain it's 1.
                ctx.sync_nonce(self.id()).await?;
                let mut outcomes = Vec::new();
                for i in 0..6 {
                    let claimant = format!("sim-ratelimit-claimant{i}");
                    let nonce = ctx.next_nonce(self.id());
                    let tx = Transaction::attest(
                        &format!("sim-ratelimit-attest{i}"), self.id(), &claimant, nonce,
                    );
                    outcomes.push(ctx.submit_tx(self.id(), "attest_ratelimit_probe", tx).await?);
                }
                // The limit is only genuinely exercised if the first five
                // actually got through the attest logic and succeeded.
                let first_five_ok = outcomes[..5].iter()
                    .all(|o| matches!(o, TxOutcome::Confirmed { success: true, .. }));
                self.verdict = Some(if !first_five_ok {
                    let bad = outcomes[..5].iter().position(|o| !matches!(o, TxOutcome::Confirmed { success: true, .. })).unwrap();
                    Err(format!("attestation #{} of the allowed five did not succeed ({:?}) -- rate limit was never reached", bad + 1, outcomes[bad]))
                } else {
                    rejected_for(&outcomes[5], "maximum attestations allowed this epoch")
                });
            }
            _ => {}
        }
        Ok(())
    }

    async fn check_expectations(&self, epoch: u64, _ctx: &SimContext) -> Vec<CheckResult> {
        if epoch != 3 { return Vec::new(); }
        match &self.verdict {
            Some(Ok(()))   => vec![CheckResult::pass("5 attestations accepted, 6th rejected by the per-epoch rate limit")],
            Some(Err(why)) => vec![CheckResult::fail("5 attestations accepted, 6th rejected by the per-epoch rate limit", why.clone())],
            None => vec![CheckResult::fail("5 attestations accepted, 6th rejected by the per-epoch rate limit", "probe never ran")],
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
    fn registers_on_chain(&self) -> bool { false }

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


// -- Fault injection: signatures ------------------------------------------------
//
// These three only mean anything against a node whose genesis has
// execution.require_signatures = true (the default).

/// Submits a well-formed but UNSIGNED registration. The API pre-check
/// must reject it before it ever reaches the mempool.
pub struct UnsignedSender {
    verdict: Option<Result<(), String>>,
}

impl UnsignedSender {
    pub fn new() -> Self { Self { verdict: None } }
}

#[async_trait::async_trait]
impl Persona for UnsignedSender {
    fn id(&self) -> &str { "sim-unsigned" }
    fn registers_on_chain(&self) -> bool { false }

    async fn run_epoch(&mut self, epoch: u64, ctx: &mut SimContext) -> Result<()> {
        if epoch == 0 {
            let addr = ctx.resolve(self.id());
            let tx = Transaction::register_identity(&ctx.tag("sim-unsigned-reg"), &addr, 0);
            let outcome = ctx.submit_prepared(self.id(), "register_unsigned", tx).await?;
            self.verdict = Some(rejected_at_submission_for(&outcome, "unsigned"));
        }
        Ok(())
    }

    async fn check_expectations(&self, epoch: u64, _ctx: &SimContext) -> Vec<CheckResult> {
        if epoch != 0 { return Vec::new(); }
        let label = "unsigned transaction rejected by the API signature pre-check";
        match &self.verdict {
            Some(Ok(()))   => vec![CheckResult::pass(label)],
            Some(Err(why)) => vec![CheckResult::fail(label, why.clone())],
            None           => vec![CheckResult::fail(label, "attempt never ran")],
        }
    }
}

/// Signs a registration correctly, then changes the nonce afterwards.
/// The signature no longer covers the transaction, so the API must reject it.
pub struct TamperedSender {
    verdict: Option<Result<(), String>>,
}

impl TamperedSender {
    pub fn new() -> Self { Self { verdict: None } }
}

#[async_trait::async_trait]
impl Persona for TamperedSender {
    fn id(&self) -> &str { "sim-tamper" }
    fn registers_on_chain(&self) -> bool { false }

    async fn run_epoch(&mut self, epoch: u64, ctx: &mut SimContext) -> Result<()> {
        if epoch == 0 {
            let addr = ctx.resolve(self.id());
            let kp = ctx.keypair_for(self.id()).expect("resolve() creates a key for sim-* labels");
            let mut tx = Transaction::register_identity(&ctx.tag("sim-tamper-reg"), &addr, 0);
            tx.sign(&kp, ctx.chain_id()).map_err(|e| anyhow::anyhow!(e))?;
            tx.nonce = 7; // altered after signing
            let outcome = ctx.submit_prepared(self.id(), "register_tampered", tx).await?;
            self.verdict = Some(rejected_at_submission_for(&outcome, "invalid signature"));
        }
        Ok(())
    }

    async fn check_expectations(&self, epoch: u64, _ctx: &SimContext) -> Vec<CheckResult> {
        if epoch != 0 { return Vec::new(); }
        let label = "transaction altered after signing rejected by the API signature pre-check";
        match &self.verdict {
            Some(Ok(()))   => vec![CheckResult::pass(label)],
            Some(Err(why)) => vec![CheckResult::fail(label, why.clone())],
            None           => vec![CheckResult::fail(label, "attempt never ran")],
        }
    }
}

/// Registers normally with its own key, then tries to act AS sim-alice:
/// an attestation whose sender is sim-alice's address, validly signed --
/// but by the forger's key. The signature itself is genuine, so it passes
/// the stateless API pre-check; only the key-binding check at execution
/// can stop it, and must.
pub struct ForgedSender {
    verdict: Option<Result<(), String>>,
}

impl ForgedSender {
    pub fn new() -> Self { Self { verdict: None } }
}

#[async_trait::async_trait]
impl Persona for ForgedSender {
    fn id(&self) -> &str { "sim-forger" }

    async fn run_epoch(&mut self, epoch: u64, ctx: &mut SimContext) -> Result<()> {
        match epoch {
            0 => {
                let nonce = ctx.next_nonce(self.id());
                let tx = Transaction::register_identity("sim-forger-reg", self.id(), nonce);
                ctx.submit_tx(self.id(), "register_identity", tx).await?;
            }
            // By epoch 2 sim-alice has transacted, so her key is bound.
            2 => {
                let victim = ctx.address_of("sim-alice");
                let own = ctx.address_of(self.id());
                let kp = ctx.keypair_for(self.id()).expect("registered in epoch 0");
                let mut tx = Transaction::attest(&ctx.tag("sim-forger-as-alice"), &victim, &own, 0);
                tx.sign(&kp, ctx.chain_id()).map_err(|e| anyhow::anyhow!(e))?;
                let outcome = ctx.submit_prepared(self.id(), "attest_forged_sender", tx).await?;
                self.verdict = Some(rejected_for(&outcome, "does not match the key bound"));
            }
            _ => {}
        }
        Ok(())
    }

    async fn check_expectations(&self, epoch: u64, _ctx: &SimContext) -> Vec<CheckResult> {
        if epoch != 2 { return Vec::new(); }
        let label = "validly signed tx sent as another account rejected by key binding at execution";
        match &self.verdict {
            Some(Ok(()))   => vec![CheckResult::pass(label)],
            Some(Err(why)) => vec![CheckResult::fail(label, why.clone())],
            None           => vec![CheckResult::fail(label, "attempt never ran")],
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
        Box::new(UnsignedSender::new()),
        Box::new(TamperedSender::new()),
        Box::new(ForgedSender::new()),
    ]
}
