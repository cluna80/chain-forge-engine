//! Governance path for the approved-issuer registry used by
//! `n_distinct_approved_issuers`. Mirrors chain-forge-consensus's
//! `ValidatorSetChange` (epoch-delayed activation) for the same safety
//! reason: a node that applies a new issuer_root at a different height than
//! its peers would accept or reject proofs its peers wouldn't, which is a
//! consensus-safety problem, not just an inconvenience.
//!
//! But issuer governance has a second requirement validator-set governance
//! didn't: REVOCATION. Removing a compromised or malicious issuer needs to
//! take effect immediately, not after a grace delay - a grace period that's
//! good for tolerating in-flight proofs during a routine addition is exactly
//! the wrong thing to give a revoked issuer extra time to exploit. So this
//! module has two distinct change paths:
//!
//!   - `propose_change` / `advance_height` — routine, epoch-delayed, and the
//!     old root stays valid for a bounded grace window afterward so a prover
//!     who built a proof just before rotation doesn't have it break.
//!   - `revoke_immediately` — takes effect this instant AND purges every
//!     historical root that included the revoked issuer, even ones still
//!     "young enough" to otherwise be inside the grace window. Revocation
//!     overrides the grace period; it does not wait for it.

use crate::{LeafHash, TwoToOneHash, VrcRegistryTree};
use ark_crypto_primitives::crh::{CRHScheme, TwoToOneCRHScheme};
use std::collections::{BTreeSet, VecDeque};

pub type Root = <TwoToOneHash as TwoToOneCRHScheme>::Output;

#[derive(Debug, Clone)]
pub struct IssuerRegistrySnapshot {
    pub root: Root,
    pub height: u64,
    pub approved_issuers: BTreeSet<u32>,
}

#[derive(Debug, Clone)]
pub struct PendingIssuerChange {
    pub proposed_at: u64,
    pub activation_height: u64,
    pub new_approved_issuers: BTreeSet<u32>,
}

#[derive(Debug)]
pub enum IssuerGovernanceError {
    ChangeAlreadyPending { activation_height: u64 },
    EmptySet,
    IssuerNotFound(u32),
}

impl std::fmt::Display for IssuerGovernanceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ChangeAlreadyPending { activation_height } => write!(
                f,
                "a change is already pending, activating at height {activation_height}"
            ),
            Self::EmptySet => write!(f, "proposed approved-issuer set is empty"),
            Self::IssuerNotFound(id) => write!(f, "issuer {id} is not currently approved"),
        }
    }
}

pub struct IssuerRegistry {
    pub current: IssuerRegistrySnapshot,
    /// Bounded history of recently-superseded snapshots, newest first.
    /// A root found here is still accepted by `is_valid_root` - this is the
    /// grace window that tolerates a proof built just before a routine
    /// rotation. `revoke_immediately` can strip entries out of this deque
    /// out of normal FIFO order, which is the whole point of it.
    pub history: VecDeque<IssuerRegistrySnapshot>,
    pub pending: Option<PendingIssuerChange>,
    pub activation_delay: u64,
    pub grace_window: usize,
    pub height: u64,
    leaf_crh_params: <LeafHash as CRHScheme>::Parameters,
    two_to_one_params: <TwoToOneHash as TwoToOneCRHScheme>::Parameters,
}

impl IssuerRegistry {
    pub fn new(
        initial_issuers: BTreeSet<u32>,
        activation_delay: u64,
        grace_window: usize,
        leaf_crh_params: <LeafHash as CRHScheme>::Parameters,
        two_to_one_params: <TwoToOneHash as TwoToOneCRHScheme>::Parameters,
    ) -> Self {
        let root = Self::build_root(&initial_issuers, &leaf_crh_params, &two_to_one_params);
        Self {
            current: IssuerRegistrySnapshot {
                root,
                height: 0,
                approved_issuers: initial_issuers,
            },
            history: VecDeque::new(),
            pending: None,
            activation_delay,
            grace_window,
            height: 0,
            leaf_crh_params,
            two_to_one_params,
        }
    }

    /// Rebuild the Merkle tree for a given issuer set and return its root.
    /// Padded to the next power of two with a sentinel value that can never
    /// collide with a real issuer_id in this demo. A production system would
    /// use a sparse Merkle tree instead of padding, to avoid a magic value
    /// with any special meaning at all — noted as a known simplification.
    fn build_root(
        issuers: &BTreeSet<u32>,
        leaf_crh_params: &<LeafHash as CRHScheme>::Parameters,
        two_to_one_params: &<TwoToOneHash as TwoToOneCRHScheme>::Parameters,
    ) -> Root {
        const PADDING_SENTINEL: u32 = u32::MAX;
        let mut leaves: Vec<Vec<u8>> = issuers.iter().map(|id| id.to_le_bytes().to_vec()).collect();
        let mut padded_len = leaves.len().max(2);
        while padded_len & (padded_len - 1) != 0 {
            padded_len += 1;
        }
        while leaves.len() < padded_len {
            leaves.push(PADDING_SENTINEL.to_le_bytes().to_vec());
        }
        let tree = VrcRegistryTree::new(leaf_crh_params, two_to_one_params, leaves.iter().map(|l| l.as_slice()))
            .expect("issuer tree must build");
        tree.root()
    }

    /// Propose a routine change (add and/or remove issuers) to activate
    /// after `activation_delay` heights. Only one change may be pending.
    pub fn propose_change(
        &mut self,
        new_approved_issuers: BTreeSet<u32>,
    ) -> Result<u64, IssuerGovernanceError> {
        if let Some(pending) = &self.pending {
            return Err(IssuerGovernanceError::ChangeAlreadyPending {
                activation_height: pending.activation_height,
            });
        }
        if new_approved_issuers.is_empty() {
            return Err(IssuerGovernanceError::EmptySet);
        }
        let activation_height = self.height + self.activation_delay.max(1);
        self.pending = Some(PendingIssuerChange {
            proposed_at: self.height,
            activation_height,
            new_approved_issuers,
        });
        Ok(activation_height)
    }

    /// Revoke a single issuer with IMMEDIATE effect: rebuilds the current
    /// root without that issuer right now (no delay), and purges every
    /// historical snapshot that included them — even ones still well within
    /// the grace window's age limit. A pending routine change, if any, is
    /// left untouched (it will still activate on schedule) but if it still
    /// includes the revoked issuer that's a governance-layer inconsistency
    /// this function deliberately does NOT paper over — see the returned
    /// warning check callers should make.
    pub fn revoke_immediately(&mut self, issuer_id: u32) -> Result<(), IssuerGovernanceError> {
        if !self.current.approved_issuers.contains(&issuer_id) {
            return Err(IssuerGovernanceError::IssuerNotFound(issuer_id));
        }

        let mut new_set = self.current.approved_issuers.clone();
        new_set.remove(&issuer_id);
        let new_root = Self::build_root(&new_set, &self.leaf_crh_params, &self.two_to_one_params);

        self.current = IssuerRegistrySnapshot {
            root: new_root,
            height: self.height,
            approved_issuers: new_set,
        };

        // The security-critical step: unlike routine rotation, which leaves
        // the old snapshot sitting in history for the grace window, a
        // revocation strips out every snapshot that still recognizes the
        // revoked issuer, however recently it was superseded.
        self.history.retain(|snap| !snap.approved_issuers.contains(&issuer_id));

        Ok(())
    }

    /// Call once per committed block/height. Applies the pending routine
    /// change if its activation height has been reached, snapshotting the
    /// outgoing state into the grace-window history.
    pub fn advance_height(&mut self, new_height: u64) {
        self.height = new_height;

        let ready = self
            .pending
            .as_ref()
            .map(|p| self.height >= p.activation_height)
            .unwrap_or(false);

        if ready {
            let change = self.pending.take().unwrap();
            let new_root =
                Self::build_root(&change.new_approved_issuers, &self.leaf_crh_params, &self.two_to_one_params);

            let outgoing = std::mem::replace(
                &mut self.current,
                IssuerRegistrySnapshot {
                    root: new_root,
                    height: self.height,
                    approved_issuers: change.new_approved_issuers,
                },
            );

            self.history.push_front(outgoing);
            while self.history.len() > self.grace_window {
                self.history.pop_back();
            }
        }
    }

    /// Whether a root is currently acceptable: either the live root, or
    /// still sitting in the grace-window history (and not purged by a
    /// revocation). Returns the snapshot it matched, so a caller can also
    /// inspect how old it is or what issuer set it corresponds to.
    pub fn is_valid_root(&self, root: &Root) -> Option<&IssuerRegistrySnapshot> {
        if &self.current.root == root {
            return Some(&self.current);
        }
        self.history.iter().find(|snap| &snap.root == root)
    }
}
