/// chain-forge-governance
///
/// On-chain governance for QCB Chain.
///
/// Implements the two-tier governance model from Whitepaper Sections 6.6 and 7.3:
///
/// ORDINARY GOVERNANCE — one-human-one-vote for $CIRFI parameters.
///   Who votes: verified humans (VerificationTier::Verified or Established).
///   What passes: simple majority of votes cast.
///   Quorum floor: >3% of verified population (derived from f/(p+f) < 0.5
///   at 3% sybil rate — Section 6.6).
///   Examples: decay rate changes, UBI rate, exemption thresholds.
///
/// CONSTITUTIONAL GOVERNANCE — for the things Section 7.3 lists as
///   requiring a higher bar: the two-token separation, the sovereignty
///   constraint, the identity and crypto replacement mechanisms.
///   Who votes: same verified humans.
///   What passes: two-thirds supermajority of votes cast.
///   Quorum floor: >6% of verified population (derived from f/(p+f) < 1/3
///   at 3% sybil rate — Section 6.6).
///   Additional: mandatory waiting period before execution.
///
/// Three-protection model enforced on every vote:
///   1. Participation quorum — minimum fraction of verified humans
///   2. Approval threshold — minimum fraction of votes cast
///   3. Absolute minimum voter count — prevents thin-population attacks (Q15)
///
/// What this module does NOT decide:
///   - The specific parameter values (those come from the passing proposal)
///   - The identity oracle (that's chain-forge-identity)
///   - Execution of the change (the node applies it after on_execute() is called)

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

// -- Error --------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum GovError {
    #[error("proposal {0} not found")]
    NotFound(u64),

    #[error("proposal {0} is not in voting state (status: {1})")]
    NotVoting(u64, String),

    #[error("voter {0} is not a verified human")]
    NotVerified(String),

    #[error("voter {0} has already voted on proposal {1}")]
    AlreadyVoted(String, u64),

    #[error("proposal {0} voting period has not ended (ends at epoch {1})")]
    VotingActive(u64, u64),

    #[error("proposal {0} waiting period has not elapsed (executable at epoch {1})")]
    WaitingPeriodActive(u64, u64),

    #[error("constitutional proposal requires {needed} voters, got {have}")]
    BelowAbsoluteMinimum { needed: u64, have: u64 },

    #[error("quorum not met: need {needed_pct}% of verified humans ({needed_voters}), got {actual}")]
    QuorumNotMet { needed_pct: u32, needed_voters: u64, actual: u64 },

    #[error("approval threshold not met: need {threshold_pct}%, got {actual_pct:.1}%")]
    ThresholdNotMet { threshold_pct: u32, actual_pct: f64 },

    #[error("proposal {0} was rejected")]
    Rejected(u64),

    #[error("proposal {0} has already been executed")]
    AlreadyExecuted(u64),

    #[error("internal governance error: {0}")]
    Internal(String),
}

pub type GovResult<T> = Result<T, GovError>;

// -- ProposalKind -------------------------------------------------------------

/// What a proposal is allowed to change.
///
/// This determines which governance tier applies and what quorum/threshold
/// rules are enforced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProposalKind {
    /// Change a $CIRFI monetary parameter (decay rate, UBI rate, etc.).
    /// Ordinary governance: simple majority, >3% quorum.
    CirfiParameter {
        parameter: String,
        current_value: String,
        proposed_value: String,
    },
    /// Change a chain parameter (gas fee, validator set policy, treasury).
    /// Ordinary governance, stake-weighted quorum considerations.
    ChainParameter {
        parameter: String,
        current_value: String,
        proposed_value: String,
    },
    /// Change something in the constitutional layer (Section 7.3).
    /// Constitutional governance: two-thirds supermajority, >6% quorum,
    /// mandatory waiting period before execution.
    Constitutional {
        description: String,
        affected_section: String,
    },
    /// Replace the identity primitive (Section 7.3 / Q9).
    /// Constitutional — highest bar.
    IdentityPrimitiveReplacement {
        current_mechanism: String,
        proposed_mechanism: String,
        rationale: String,
    },
    /// Replace the cryptographic signature scheme (Section 7.3 / Q16).
    /// Constitutional — aligns with SchemeRegistry::propose_migration().
    CryptoPrimitiveReplacement {
        current_scheme: String,
        proposed_scheme: String,
        rationale: String,
    },
    /// Treasury allocation from the genesis reserve.
    /// Ordinary governance.
    TreasurySpend {
        recipient: String,
        amount_uqcb: u128,
        purpose: String,
    },
    /// Text-only signal proposal (no on-chain execution).
    /// Used for off-chain coordination, recording community sentiment.
    SignalProposal {
        title: String,
        body: String,
    },
}

impl ProposalKind {
    /// Whether this proposal requires constitutional governance rules.
    pub fn is_constitutional(&self) -> bool {
        matches!(
            self,
            Self::Constitutional { .. }
            | Self::IdentityPrimitiveReplacement { .. }
            | Self::CryptoPrimitiveReplacement { .. }
        )
    }

    pub fn display_name(&self) -> &str {
        match self {
            Self::CirfiParameter { .. }            => "CirFi Parameter Change",
            Self::ChainParameter { .. }            => "Chain Parameter Change",
            Self::Constitutional { .. }            => "Constitutional Amendment",
            Self::IdentityPrimitiveReplacement { .. } => "Identity Primitive Replacement",
            Self::CryptoPrimitiveReplacement { .. } => "Crypto Primitive Replacement",
            Self::TreasurySpend { .. }             => "Treasury Spend",
            Self::SignalProposal { .. }            => "Signal Proposal",
        }
    }
}

// -- VoteChoice ---------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VoteChoice {
    Yes,
    No,
    Abstain, // counted toward quorum but not approval
}

// -- ProposalStatus -----------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProposalStatus {
    /// Open for voting. Voting ends at `voting_end_epoch`.
    Voting,
    /// Voting ended. Awaiting tally.
    Tallying,
    /// Passed ordinary governance. Ready to execute immediately.
    PassedOrdinary,
    /// Passed constitutional governance. Must wait until `executable_after_epoch`.
    PassedConstitutional { executable_after_epoch: u64 },
    /// Failed: quorum not met, threshold not met, or below abs minimum.
    Failed { reason: String },
    /// Executed on-chain. Terminal state.
    Executed { executed_at_epoch: u64 },
}

impl std::fmt::Display for ProposalStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Voting                              => write!(f, "Voting"),
            Self::Tallying                            => write!(f, "Tallying"),
            Self::PassedOrdinary                     => write!(f, "Passed (Ordinary)"),
            Self::PassedConstitutional { .. }        => write!(f, "Passed (Constitutional)"),
            Self::Failed { reason }                  => write!(f, "Failed: {reason}"),
            Self::Executed { executed_at_epoch }     => write!(f, "Executed at epoch {executed_at_epoch}"),
        }
    }
}

// -- GovernanceConfig ---------------------------------------------------------

/// The quorum and threshold parameters that govern vote tallying.
///
/// These are NOT governance-adjustable by ordinary governance — that would
/// let an attacker lower the quorum before attacking. The quorum floors are
/// derived from the sybil-rate target (Section 6.6) and sit in the
/// constitutional layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceConfig {
    /// Ordinary governance: participation quorum floor (% of verified humans).
    /// Derived from f/(p+f) < 0.5 at f=3%: p > 3%.
    pub ordinary_quorum_pct: u32,
    /// Ordinary governance: approval threshold (% of votes cast).
    pub ordinary_approval_pct: u32,
    /// Constitutional governance: participation quorum floor.
    /// Derived from f/(p+f) < 1/3 at f=3%: p > 6%.
    pub constitutional_quorum_pct: u32,
    /// Constitutional governance: approval threshold.
    pub constitutional_approval_pct: u32,
    /// Absolute minimum voters for constitutional proposals (Q15).
    /// Prevents attacks when verified population is very small.
    pub constitutional_min_voters: u64,
    /// Voting period in epochs.
    pub voting_period_epochs: u64,
    /// Mandatory waiting period for constitutional changes before execution.
    pub constitutional_wait_epochs: u64,
}

impl GovernanceConfig {
    /// The QCB default: quorum floors derived from Section 6.6 math.
    pub fn qcb_default() -> Self {
        Self {
            // Ordinary: >3% quorum (derived from 3% sybil rate + majority safety)
            ordinary_quorum_pct:          4, // 4% — above the 3% floor
            ordinary_approval_pct:        51,
            // Constitutional: >6% quorum (derived from 3% sybil rate + supermajority safety)
            constitutional_quorum_pct:    7, // 7% — above the 6% floor
            constitutional_approval_pct:  67, // two-thirds
            // Absolute minimum: 10 voters regardless of population fraction
            // (provisional — Open Question 15)
            constitutional_min_voters:    10,
            voting_period_epochs:         14,  // ~2 weeks
            constitutional_wait_epochs:   28,  // ~4 weeks mandatory wait
        }
    }
}

// -- Proposal -----------------------------------------------------------------

/// A governance proposal on QCB Chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    pub id:               u64,
    pub proposer:         String,
    pub kind:             ProposalKind,
    pub status:           ProposalStatus,
    pub submitted_epoch:  u64,
    pub voting_end_epoch: u64,
    /// Votes cast: voter address -> choice.
    pub votes:            HashMap<String, VoteChoice>,
    /// Snapshot of verified human count at submission time.
    /// Used for quorum calculation — prevents gaming by changing
    /// the population between submission and tally.
    pub verified_humans_at_submission: u64,
}

impl Proposal {
    pub fn new(
        id:               u64,
        proposer:         String,
        kind:             ProposalKind,
        submitted_epoch:  u64,
        voting_period:    u64,
        verified_humans:  u64,
    ) -> Self {
        Self {
            id,
            proposer,
            kind,
            status:           ProposalStatus::Voting,
            submitted_epoch,
            voting_end_epoch: submitted_epoch + voting_period,
            votes:            HashMap::new(),
            verified_humans_at_submission: verified_humans,
        }
    }

    pub fn yes_count(&self) -> u64 {
        self.votes.values().filter(|v| **v == VoteChoice::Yes).count() as u64
    }

    pub fn no_count(&self) -> u64 {
        self.votes.values().filter(|v| **v == VoteChoice::No).count() as u64
    }

    pub fn abstain_count(&self) -> u64 {
        self.votes.values().filter(|v| **v == VoteChoice::Abstain).count() as u64
    }

    pub fn total_participating(&self) -> u64 {
        self.votes.len() as u64
    }

    /// Approval percentage among Yes + No votes (Abstain excluded from ratio).
    pub fn approval_pct(&self) -> f64 {
        let decisive = self.yes_count() + self.no_count();
        if decisive == 0 { return 0.0; }
        self.yes_count() as f64 / decisive as f64 * 100.0
    }

    /// Participation as a percentage of verified humans at submission.
    pub fn participation_pct(&self) -> f64 {
        if self.verified_humans_at_submission == 0 { return 0.0; }
        self.total_participating() as f64
            / self.verified_humans_at_submission as f64
            * 100.0
    }
}

// -- GovernanceModule ---------------------------------------------------------

/// The on-chain governance module for QCB Chain.
pub struct GovernanceModule {
    config:    GovernanceConfig,
    proposals: HashMap<u64, Proposal>,
    next_id:   u64,
}

impl GovernanceModule {
    pub fn new(config: GovernanceConfig) -> Self {
        Self {
            config,
            proposals: HashMap::new(),
            next_id:   1,
        }
    }

    pub fn with_qcb_defaults() -> Self {
        Self::new(GovernanceConfig::qcb_default())
    }

    // -- Submission -----------------------------------------------------------

    /// Submit a new governance proposal.
    /// Any verified human may propose; proposals are free (Phase 1 may add
    /// a deposit requirement to prevent spam).
    pub fn submit(
        &mut self,
        proposer:        String,
        kind:            ProposalKind,
        current_epoch:   u64,
        verified_humans: u64,
    ) -> u64 {
        let id = self.next_id;
        self.next_id += 1;

        let proposal = Proposal::new(
            id,
            proposer.clone(),
            kind.clone(),
            current_epoch,
            self.config.voting_period_epochs,
            verified_humans,
        );

        tracing::info!(
            id,
            proposer = %proposer,
            kind     = proposal.kind.display_name(),
            constitutional = kind.is_constitutional(),
            "governance proposal submitted"
        );

        self.proposals.insert(id, proposal);
        id
    }

    // -- Voting ---------------------------------------------------------------

    /// Cast a vote on a proposal.
    /// The caller must confirm the voter is a verified human (via
    /// chain-forge-identity) before calling this.
    pub fn vote(
        &mut self,
        proposal_id:  u64,
        voter:        String,
        choice:       VoteChoice,
        current_epoch: u64,
    ) -> GovResult<()> {
        let proposal = self.proposals.get_mut(&proposal_id)
            .ok_or(GovError::NotFound(proposal_id))?;

        if proposal.status != ProposalStatus::Voting {
            return Err(GovError::NotVoting(
                proposal_id, proposal.status.to_string()
            ));
        }
        if current_epoch > proposal.voting_end_epoch {
            return Err(GovError::NotVoting(
                proposal_id,
                format!("voting ended at epoch {}", proposal.voting_end_epoch)
            ));
        }
        if proposal.votes.contains_key(&voter) {
            return Err(GovError::AlreadyVoted(voter, proposal_id));
        }

        proposal.votes.insert(voter.clone(), choice.clone());
        tracing::debug!(
            proposal_id,
            voter = %voter,
            choice = ?choice,
            "vote cast"
        );
        Ok(())
    }

    // -- Tallying -------------------------------------------------------------

    /// Tally votes after the voting period ends.
    /// Updates the proposal status based on the three-protection model.
    pub fn tally(
        &mut self,
        proposal_id:  u64,
        current_epoch: u64,
    ) -> GovResult<ProposalStatus> {
        let proposal = self.proposals.get(&proposal_id)
            .ok_or(GovError::NotFound(proposal_id))?;

        if current_epoch <= proposal.voting_end_epoch {
            return Err(GovError::VotingActive(
                proposal_id, proposal.voting_end_epoch
            ));
        }

        let is_constitutional = proposal.kind.is_constitutional();
        let quorum_pct        = if is_constitutional {
            self.config.constitutional_quorum_pct
        } else {
            self.config.ordinary_quorum_pct
        };
        let approval_pct      = if is_constitutional {
            self.config.constitutional_approval_pct
        } else {
            self.config.ordinary_approval_pct
        };

        let participating     = proposal.total_participating();
        let verified          = proposal.verified_humans_at_submission;
        let approval          = proposal.approval_pct();

        // Protection 3: absolute minimum for constitutional proposals
        if is_constitutional && participating < self.config.constitutional_min_voters {
            let status = ProposalStatus::Failed {
                reason: format!(
                    "below absolute minimum voters: need {}, got {}",
                    self.config.constitutional_min_voters, participating
                ),
            };
            self.proposals.get_mut(&proposal_id).unwrap().status = status.clone();
            return Ok(status);
        }

        // Protection 1: participation quorum
        let needed_voters = (verified as f64 * quorum_pct as f64 / 100.0).ceil() as u64;
        if participating < needed_voters {
            let status = ProposalStatus::Failed {
                reason: format!(
                    "quorum not met: need {}% ({} voters), got {}",
                    quorum_pct, needed_voters, participating
                ),
            };
            self.proposals.get_mut(&proposal_id).unwrap().status = status.clone();
            return Ok(status);
        }

        // Protection 2: approval threshold
        if approval < approval_pct as f64 {
            let status = ProposalStatus::Failed {
                reason: format!(
                    "approval threshold not met: need {}%, got {:.1}%",
                    approval_pct, approval
                ),
            };
            self.proposals.get_mut(&proposal_id).unwrap().status = status.clone();
            return Ok(status);
        }

        // Passed
        let status = if is_constitutional {
            let wait = self.config.constitutional_wait_epochs;
            ProposalStatus::PassedConstitutional {
                executable_after_epoch: current_epoch + wait,
            }
        } else {
            ProposalStatus::PassedOrdinary
        };

        self.proposals.get_mut(&proposal_id).unwrap().status = status.clone();
        tracing::info!(
            proposal_id,
            constitutional = is_constitutional,
            approval_pct = approval,
            "proposal passed"
        );
        Ok(status)
    }

    // -- Execution ------------------------------------------------------------

    /// Mark a passed proposal as executed.
    /// The node calls this after applying the parameter change on-chain.
    pub fn execute(
        &mut self,
        proposal_id:  u64,
        current_epoch: u64,
    ) -> GovResult<&Proposal> {
        let proposal = self.proposals.get_mut(&proposal_id)
            .ok_or(GovError::NotFound(proposal_id))?;

        match &proposal.status {
            ProposalStatus::PassedOrdinary => {
                proposal.status = ProposalStatus::Executed {
                    executed_at_epoch: current_epoch,
                };
            }
            ProposalStatus::PassedConstitutional { executable_after_epoch } => {
                if current_epoch < *executable_after_epoch {
                    return Err(GovError::WaitingPeriodActive(
                        proposal_id, *executable_after_epoch
                    ));
                }
                proposal.status = ProposalStatus::Executed {
                    executed_at_epoch: current_epoch,
                };
            }
            ProposalStatus::Executed { .. } => {
                return Err(GovError::AlreadyExecuted(proposal_id));
            }
            ProposalStatus::Failed { .. } => {
                return Err(GovError::Rejected(proposal_id));
            }
            _ => {
                return Err(GovError::NotVoting(
                    proposal_id, proposal.status.to_string()
                ));
            }
        }

        tracing::info!(proposal_id, epoch = current_epoch, "proposal executed");
        Ok(self.proposals.get(&proposal_id).unwrap())
    }

    // -- Lookups --------------------------------------------------------------

    pub fn get(&self, id: u64) -> GovResult<&Proposal> {
        self.proposals.get(&id).ok_or(GovError::NotFound(id))
    }

    pub fn active_proposals(&self) -> Vec<&Proposal> {
        self.proposals.values()
            .filter(|p| p.status == ProposalStatus::Voting)
            .collect()
    }

    pub fn total_proposals(&self) -> usize {
        self.proposals.len()
    }

    pub fn config(&self) -> &GovernanceConfig {
        &self.config
    }
}

// -- Tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn gov() -> GovernanceModule {
        GovernanceModule::with_qcb_defaults()
    }

    fn cirfi_proposal(gov: &mut GovernanceModule, epoch: u64, humans: u64) -> u64 {
        gov.submit(
            "qcb1alice".into(),
            ProposalKind::CirfiParameter {
                parameter:      "demurrage_rate_tier2".into(),
                current_value:  "0.5%".into(),
                proposed_value: "0.75%".into(),
            },
            epoch,
            humans,
        )
    }

    fn constitutional_proposal(gov: &mut GovernanceModule, epoch: u64, humans: u64) -> u64 {
        gov.submit(
            "qcb1alice".into(),
            ProposalKind::Constitutional {
                description:      "Adopt new PoP mechanism".into(),
                affected_section: "7.3".into(),
            },
            epoch,
            humans,
        )
    }

    fn add_yes_votes(gov: &mut GovernanceModule, id: u64, n: usize, epoch: u64) {
        for i in 0..n {
            gov.vote(id, format!("qcb1voter{i}"), VoteChoice::Yes, epoch).unwrap();
        }
    }

    fn add_no_votes(gov: &mut GovernanceModule, id: u64, n: usize, epoch: u64) {
        for i in 0..n {
            gov.vote(id, format!("qcb1no{i}"), VoteChoice::No, epoch).unwrap();
        }
    }

    // -- Submission tests -----------------------------------------------------

    #[test]
    fn submit_returns_incrementing_ids() {
        let mut gov = gov();
        let a = cirfi_proposal(&mut gov, 0, 100);
        let b = cirfi_proposal(&mut gov, 0, 100);
        assert_eq!(a, 1);
        assert_eq!(b, 2);
    }

    #[test]
    fn new_proposal_is_in_voting_state() {
        let mut gov = gov();
        let id = cirfi_proposal(&mut gov, 0, 100);
        assert_eq!(gov.get(id).unwrap().status, ProposalStatus::Voting);
    }

    #[test]
    fn constitutional_proposal_flagged_correctly() {
        let mut gov = gov();
        let id = constitutional_proposal(&mut gov, 0, 100);
        assert!(gov.get(id).unwrap().kind.is_constitutional());
    }

    // -- Voting tests ---------------------------------------------------------

    #[test]
    fn vote_recorded_correctly() {
        let mut gov = gov();
        let id = cirfi_proposal(&mut gov, 0, 100);
        gov.vote(id, "qcb1alice".into(), VoteChoice::Yes, 1).unwrap();
        let p = gov.get(id).unwrap();
        assert_eq!(p.yes_count(), 1);
        assert_eq!(p.total_participating(), 1);
    }

    #[test]
    fn double_vote_rejected() {
        let mut gov = gov();
        let id = cirfi_proposal(&mut gov, 0, 100);
        gov.vote(id, "qcb1alice".into(), VoteChoice::Yes, 1).unwrap();
        assert!(gov.vote(id, "qcb1alice".into(), VoteChoice::No, 1).is_err());
    }

    #[test]
    fn vote_after_voting_period_rejected() {
        let mut gov = gov();
        let id = cirfi_proposal(&mut gov, 0, 100);
        // voting_end = 0 + 14 = epoch 14
        assert!(gov.vote(id, "qcb1alice".into(), VoteChoice::Yes, 15).is_err());
    }

    #[test]
    fn abstain_counts_toward_quorum_not_approval() {
        let mut gov = gov();
        // 100 verified humans, need 4% = 4 voters for ordinary quorum
        let id = cirfi_proposal(&mut gov, 0, 100);
        gov.vote(id, "qcb1a".into(), VoteChoice::Yes,     1).unwrap();
        gov.vote(id, "qcb1b".into(), VoteChoice::Abstain, 1).unwrap();
        gov.vote(id, "qcb1c".into(), VoteChoice::Abstain, 1).unwrap();
        gov.vote(id, "qcb1d".into(), VoteChoice::Abstain, 1).unwrap();

        let p = gov.get(id).unwrap();
        assert_eq!(p.total_participating(), 4);  // quorum satisfied
        assert_eq!(p.yes_count(), 1);
        // approval_pct = 1/(1+0) = 100% (abstains excluded from ratio)
        assert!((p.approval_pct() - 100.0).abs() < 0.01);
    }

    // -- Tally: ordinary governance -------------------------------------------

    #[test]
    fn ordinary_proposal_passes_with_quorum_and_majority() {
        let mut gov = gov();
        // 100 humans, need 4% = 4 voters, 51% approval
        let id = cirfi_proposal(&mut gov, 0, 100);
        add_yes_votes(&mut gov, id, 5, 1); // 5 yes votes = 5% quorum, 100% approval

        let status = gov.tally(id, 15).unwrap(); // after voting_end=14
        assert_eq!(status, ProposalStatus::PassedOrdinary);
    }

    #[test]
    fn ordinary_proposal_fails_quorum() {
        let mut gov = gov();
        let id = cirfi_proposal(&mut gov, 0, 1000);
        // Need 4% of 1000 = 40 voters. Only 3.
        add_yes_votes(&mut gov, id, 3, 1);

        let status = gov.tally(id, 15).unwrap();
        assert!(matches!(status, ProposalStatus::Failed { .. }));
    }

    #[test]
    fn ordinary_proposal_fails_approval_threshold() {
        let mut gov = gov();
        let id = cirfi_proposal(&mut gov, 0, 100);
        // 5 yes, 6 no = 5/11 = 45.5% approval < 51%
        add_yes_votes(&mut gov, id, 5, 1);
        add_no_votes(&mut gov,  id, 6, 1);

        let status = gov.tally(id, 15).unwrap();
        assert!(matches!(status, ProposalStatus::Failed { .. }));
    }

    #[test]
    fn tally_before_voting_ends_fails() {
        let mut gov = gov();
        let id = cirfi_proposal(&mut gov, 0, 100);
        add_yes_votes(&mut gov, id, 10, 1);
        // voting_end = 14, tally at epoch 10 should fail
        assert!(gov.tally(id, 10).is_err());
    }

    // -- Tally: constitutional governance -------------------------------------

    #[test]
    fn constitutional_proposal_requires_supermajority() {
        let mut gov = gov();
        // 1000 humans, need 7% = 70 voters, 67% approval threshold
        let id = constitutional_proposal(&mut gov, 0, 1000);
        // 67 yes, 33 no = 67/100 = 67.0% approval, 100 voters (> 70 quorum)
        add_yes_votes(&mut gov, id, 67, 1);
        add_no_votes(&mut gov,  id, 33, 1);

        let status = gov.tally(id, 15).unwrap();
        assert!(matches!(status, ProposalStatus::PassedConstitutional { .. }),
            "67% yes of 100 voters should pass constitutional threshold");
    }

    #[test]
    fn constitutional_proposal_fails_below_two_thirds() {
        let mut gov = gov();
        let id = constitutional_proposal(&mut gov, 0, 1000);
        // 60 yes, 40 no = 60% approval < 67% threshold
        add_yes_votes(&mut gov, id, 60, 1);
        add_no_votes(&mut gov,  id, 40, 1);

        let status = gov.tally(id, 15).unwrap();
        assert!(matches!(status, ProposalStatus::Failed { .. }));
    }

    #[test]
    fn constitutional_proposal_fails_absolute_minimum() {
        let mut gov = gov();
        // Only 5 voters (< constitutional_min_voters = 10) even with 100% approval
        let id = constitutional_proposal(&mut gov, 0, 50);
        add_yes_votes(&mut gov, id, 5, 1);

        let status = gov.tally(id, 15).unwrap();
        assert!(matches!(status, ProposalStatus::Failed { .. }),
            "should fail absolute minimum voter check");
    }

    #[test]
    fn constitutional_proposal_has_mandatory_wait() {
        let mut gov = gov();
        let id = constitutional_proposal(&mut gov, 0, 1000);
        add_yes_votes(&mut gov, id, 100, 1);
        add_no_votes(&mut gov,  id,  10, 1);

        let tally_epoch = 15u64;
        let status = gov.tally(id, tally_epoch).unwrap();
        assert!(matches!(
            status,
            ProposalStatus::PassedConstitutional { executable_after_epoch }
            if executable_after_epoch == tally_epoch + gov.config().constitutional_wait_epochs
        ));

        // Cannot execute before wait period
        assert!(gov.execute(id, tally_epoch).is_err());
        assert!(gov.execute(id, tally_epoch + 27).is_err());

        // Can execute after wait period
        let wait = gov.config().constitutional_wait_epochs;
        assert!(gov.execute(id, tally_epoch + wait).is_ok());
    }

    // -- Execution tests ------------------------------------------------------

    #[test]
    fn ordinary_proposal_executes_immediately_after_passing() {
        let mut gov = gov();
        let id = cirfi_proposal(&mut gov, 0, 100);
        add_yes_votes(&mut gov, id, 10, 1);
        gov.tally(id, 15).unwrap();

        let result = gov.execute(id, 16);
        assert!(result.is_ok());
        assert!(matches!(
            gov.get(id).unwrap().status,
            ProposalStatus::Executed { .. }
        ));
    }

    #[test]
    fn cannot_execute_twice() {
        let mut gov = gov();
        let id = cirfi_proposal(&mut gov, 0, 100);
        add_yes_votes(&mut gov, id, 10, 1);
        gov.tally(id, 15).unwrap();
        gov.execute(id, 16).unwrap();
        assert!(gov.execute(id, 17).is_err());
    }

    #[test]
    fn cannot_execute_failed_proposal() {
        let mut gov = gov();
        let id = cirfi_proposal(&mut gov, 0, 1000);
        add_yes_votes(&mut gov, id, 1, 1); // quorum fails
        gov.tally(id, 15).unwrap();
        assert!(gov.execute(id, 16).is_err());
    }

    // -- Quorum math sanity checks --------------------------------------------

    #[test]
    fn ordinary_quorum_floor_is_above_3pct_sybil_threshold() {
        let config = GovernanceConfig::qcb_default();
        assert!(config.ordinary_quorum_pct > 3,
            "ordinary quorum must be above the 3% sybil safety floor (Section 6.6)");
    }

    #[test]
    fn constitutional_quorum_floor_is_above_6pct_sybil_threshold() {
        let config = GovernanceConfig::qcb_default();
        assert!(config.constitutional_quorum_pct > 6,
            "constitutional quorum must be above the 6% blocking-safety floor (Section 6.6)");
    }

    #[test]
    fn constitutional_approval_is_at_least_two_thirds() {
        let config = GovernanceConfig::qcb_default();
        assert!(config.constitutional_approval_pct >= 67,
            "constitutional proposals require two-thirds supermajority (Section 7.3)");
    }

    #[test]
    fn crypto_primitive_replacement_is_constitutional() {
        let kind = ProposalKind::CryptoPrimitiveReplacement {
            current_scheme:  "HybridEd25519MlDsa".into(),
            proposed_scheme: "MlDsa".into(),
            rationale:       "CRQC demonstrated".into(),
        };
        assert!(kind.is_constitutional(),
            "crypto primitive replacement must go through constitutional governance");
    }

    #[test]
    fn identity_primitive_replacement_is_constitutional() {
        let kind = ProposalKind::IdentityPrimitiveReplacement {
            current_mechanism:  "web-of-trust + live-challenge".into(),
            proposed_mechanism: "zk-proof of government ID".into(),
            rationale:          "sybil rate target not achievable".into(),
        };
        assert!(kind.is_constitutional());
    }

    #[test]
    fn treasury_spend_is_ordinary_governance() {
        let kind = ProposalKind::TreasurySpend {
            recipient:   "qcb1dev".into(),
            amount_uqcb: 1_000_000,
            purpose:     "identity pilot funding".into(),
        };
        assert!(!kind.is_constitutional());
    }

    #[test]
    fn participation_pct_calculated_correctly() {
        let mut gov = gov();
        let id = cirfi_proposal(&mut gov, 0, 200);
        add_yes_votes(&mut gov, id, 10, 1); // 10/200 = 5%

        let p = gov.get(id).unwrap();
        assert!((p.participation_pct() - 5.0).abs() < 0.01);
    }
}
