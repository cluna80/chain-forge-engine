//! The safety store (stub: tests-first commit; every call fails until the implementation lands).
use super::*;
use crate::pq_hotstuff::wire::{BlockSigningMessage, SignatureEnvelope, TimeoutMessage, VoteMessage};

/// What a successful signing call returns, only after the new record is durable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed {
    /// The exact canonical message bytes.
    pub message: Vec<u8>,
    pub envelope: SignatureEnvelope,
    /// `true` if this is a byte-for-byte re-send of an earlier signature (the signer was not called).
    pub resent: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct FreshInit<'a> {
    pub protocol_profile: &'a str,
    pub chain_id: &'a str,
    pub public_key: &'a [u8],
    pub instance_id: [u8; 16],
    pub epoch: u64,
}

pub struct SafetyStore<S: Storage, C: MonotonicCounter> {
    storage: S,
    counter: C,
    rec: SafetyRecord,
    latched: bool,
}

impl<S: Storage, C: MonotonicCounter> SafetyStore<S, C> {
    pub fn initialize_fresh(_storage: S, _counter: C, _init: &FreshInit, _evidence: &ParticipationEvidence) -> Result<Self, InitError> {
        Err(InitError::Unimplemented)
    }

    pub fn open(_storage: S, _counter: C, _expected: &Expected, _verifier: &dyn ConsensusVerifier, _evidence: &ParticipationEvidence) -> Result<Self, OpenError> {
        Err(OpenError::Unimplemented)
    }

    pub fn record(&self) -> &SafetyRecord { &self.rec }
    pub fn is_latched(&self) -> bool { self.latched }
    pub fn into_parts(self) -> (S, C) { (self.storage, self.counter) }

    pub fn sign_vote(&mut self, _msg: &VoteMessage, _qc_round: u64, _signer: &mut dyn ConsensusSigner) -> Result<Signed, SignError> {
        Err(SignError::Unimplemented)
    }
    pub fn sign_timeout(&mut self, _msg: &TimeoutMessage, _signer: &mut dyn ConsensusSigner) -> Result<Signed, SignError> {
        Err(SignError::Unimplemented)
    }
    pub fn sign_proposal(&mut self, _epoch: u64, _round: u64, _msg: &BlockSigningMessage, _signer: &mut dyn ConsensusSigner) -> Result<Signed, SignError> {
        Err(SignError::Unimplemented)
    }
}
