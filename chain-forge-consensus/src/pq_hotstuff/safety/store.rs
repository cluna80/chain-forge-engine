//! The safety store: opens fail closed, signing is check -> sign -> durable commit -> return, and nothing is returned to the
//! caller (so nothing can be broadcast) until the new record is durable and the trusted counter has advanced.
use super::record::{decode_marker, decode_record, encode_marker, encode_record, Marker};
use super::*;
use crate::pq_hotstuff::wire::{
    AlgId, BlockSigningMessage, SignatureEnvelope, TimeoutMessage, VoteMessage, MAX_NAME_LEN, MLDSA65_PUBLIC_KEY_LEN, MLDSA65_SIGNATURE_LEN,
};

const ALG: AlgId = AlgId::MLDSA65_FIPS204;

/// What a successful signing call returns, only after the new record is durable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed {
    /// The exact canonical message bytes.
    pub message: Vec<u8>,
    pub envelope: SignatureEnvelope,
    /// `true` if this is a byte-for-byte re-send of an earlier signature (the signer was not called, nothing was written).
    pub resent: bool,
}

/// The identity of a validator being initialized for the first time.
#[derive(Debug, Clone, Copy)]
pub struct FreshInit<'a> {
    pub protocol_profile: &'a str,
    pub chain_id: &'a str,
    pub public_key: &'a [u8],
    pub instance_id: [u8; 16],
    /// The epoch the validator starts in.
    pub epoch: u64,
}

pub struct SafetyStore<S: Storage, C: MonotonicCounter> {
    storage: S,
    counter: C,
    rec: SafetyRecord,
    /// Set by any failure after which memory may no longer match what is durable. A latched store refuses everything.
    latched: bool,
}

/// temporary file -> `fsync` -> rename -> directory `fsync`.
fn durable_replace<S: Storage>(s: &mut S, tmp: &str, dst: &str, bytes: &[u8]) -> Result<(), StorageError> {
    s.write_tmp(tmp, bytes)?;
    s.sync_file(tmp)?;
    s.rename(tmp, dst)?;
    s.sync_dir()
}

fn name_ok(s: &str) -> bool { !s.is_empty() && s.len() <= MAX_NAME_LEN && !s.as_bytes().contains(&0) }

fn open_decode_err(e: RecordError) -> OpenError {
    match e { RecordError::Version(v) => OpenError::VersionUnsupported(v), other => OpenError::Damaged(other.to_string()) }
}

impl<S: Storage, C: MonotonicCounter> SafetyStore<S, C> {
    /// Explicit initialization of a validator that has never signed. Writes the marker first and the `Fresh` record second, so
    /// a state file never exists without its marker. A crash in between leaves a marker without state, which `open` refuses;
    /// the identity is then not reused (use a new key).
    pub fn initialize_fresh(mut storage: S, mut counter: C, init: &FreshInit, evidence: &ParticipationEvidence) -> Result<Self, InitError> {
        if init.public_key.len() != MLDSA65_PUBLIC_KEY_LEN { return Err(InitError::BadIdentity("public key length")); }
        if !name_ok(init.protocol_profile) { return Err(InitError::BadIdentity("protocol profile")); }
        if !name_ok(init.chain_id) { return Err(InitError::BadIdentity("chain id")); }
        let st = |e: StorageError| InitError::Storage(e.0);
        if storage.read(STATE_FILE).map_err(st)?.is_some() || storage.read(MARKER_FILE).map_err(st)?.is_some() {
            return Err(InitError::AlreadyInitialized);
        }
        let c = counter.read().map_err(|e| InitError::Counter(e.0))?;
        if c != 0 { return Err(InitError::CounterNotZero(c)); }
        if evidence.highest_signed.is_some() { return Err(InitError::KeyAlreadyParticipated); }

        let marker = Marker {
            protocol_profile: init.protocol_profile.into(), chain_id: init.chain_id.into(),
            public_key: init.public_key.to_vec(), instance_id: init.instance_id,
        };
        let mb = encode_marker(&marker).map_err(|e| InitError::Storage(e.to_string()))?;
        durable_replace(&mut storage, MARKER_TMP, MARKER_FILE, &mb).map_err(st)?;
        let rec = SafetyRecord {
            state: State::Fresh, protocol_profile: init.protocol_profile.into(), chain_id: init.chain_id.into(),
            public_key: init.public_key.to_vec(), instance_id: init.instance_id, counter: 1, epoch: init.epoch,
            hvr: None, hqr: None, last_vote: None, last_timeout: None, last_proposal: None,
        };
        let rb = encode_record(&rec).map_err(|e| InitError::Storage(e.to_string()))?;
        durable_replace(&mut storage, STATE_TMP, STATE_FILE, &rb).map_err(st)?;
        counter.advance(0, &Session::new(0)).map_err(|e| InitError::Counter(e.0))?;
        Ok(SafetyStore { storage, counter, rec, latched: false })
    }

    /// Open an existing validator's safety state, or refuse. Never creates or repairs anything: any missing, damaged, stale,
    /// rolled-back or mismatched state is an error and the caller must not sign.
    pub fn open(mut storage: S, mut counter: C, expected: &Expected, verifier: &dyn ConsensusVerifier, evidence: &ParticipationEvidence) -> Result<Self, OpenError> {
        let sto = |e: StorageError| OpenError::Storage(e.0);
        let state_bytes = storage.read(STATE_FILE).map_err(sto)?;
        let marker_bytes = storage.read(MARKER_FILE).map_err(sto)?;
        let (state_bytes, marker_bytes) = match (state_bytes, marker_bytes) {
            (None, None) => return Err(OpenError::NoState),
            (None, Some(_)) => return Err(OpenError::MarkerWithoutState),
            (Some(_), None) => return Err(OpenError::StateWithoutMarker),
            (Some(s), Some(m)) => (s, m),
        };
        let marker = decode_marker(&marker_bytes).map_err(open_decode_err)?;
        let rec = decode_record(&state_bytes).map_err(open_decode_err)?;

        // identity: the record is for the profile, chain and key the caller expects, and belongs with its marker
        if rec.protocol_profile != expected.protocol_profile { return Err(OpenError::ProfileMismatch); }
        if rec.chain_id != expected.chain_id { return Err(OpenError::ChainMismatch); }
        if rec.public_key != expected.public_key { return Err(OpenError::KeyMismatch); }
        if marker.protocol_profile != rec.protocol_profile || marker.chain_id != rec.chain_id
            || marker.public_key != rec.public_key || marker.instance_id != rec.instance_id {
            return Err(OpenError::InstanceMismatch);
        }

        // rollback: classify against the trusted counter now, but complete the counter only after everything else checks out
        let trusted = counter.read().map_err(|e| OpenError::Counter(e.0))?;
        let crash_window = if rec.counter == trusted {
            false
        } else if rec.counter == trusted + 1 {
            true // the file is durable, the counter advance did not happen: nothing from this record was ever returned
        } else if rec.counter < trusted {
            return Err(OpenError::Rollback { file_counter: rec.counter, trusted_counter: trusted });
        } else {
            return Err(OpenError::CounterInconsistent { file_counter: rec.counter, trusted_counter: trusted });
        };

        Self::verify_content(&rec, expected, verifier)?;

        // staleness against what the chain already shows about this key
        if let Some((ce, cr)) = evidence.highest_signed {
            let behind = match rec.high_water() { None => true, Some((re, rr)) => ce > re || (ce == re && cr > rr) };
            if behind { return Err(OpenError::StaleAgainstChain { chain: (ce, cr), record: rec.high_water() }); }
        }

        if crash_window { counter.advance(trusted, &Session::new(0)).map_err(|e| OpenError::Counter(e.0))?; }
        // a leftover temporary file from an interrupted commit was never read; clear it (best effort)
        let _ = storage.remove(STATE_TMP);
        let _ = storage.remove(MARKER_TMP);
        Ok(SafetyStore { storage, counter, rec, latched: false })
    }

    /// Internal consistency of a decoded record, and verification of every stored signature.
    fn verify_content(rec: &SafetyRecord, expected: &Expected, verifier: &dyn ConsensusVerifier) -> Result<(), OpenError> {
        let bad = |m: &str| OpenError::Damaged(m.to_string());
        let slots = [Kind::Vote, Kind::Timeout, Kind::Proposal].map(|k| (k, rec.slot(k)));
        match rec.state {
            State::Fresh => {
                if slots.iter().any(|(_, s)| s.is_some()) || rec.hvr.is_some() || rec.hqr.is_some() { return Err(bad("a fresh record has signed items")); }
                if rec.counter != 1 { return Err(bad("a fresh record must be at counter 1")); }
            }
            State::Active => {
                if slots.iter().all(|(_, s)| s.is_none()) { return Err(bad("an active record has nothing signed")); }
                if rec.counter < 2 { return Err(bad("an active record must be past counter 1")); }
            }
        }
        for (kind, item) in slots {
            let Some(item) = item else { continue };
            let message_round = match kind {
                Kind::Vote => {
                    let m = VoteMessage::decode(&item.message, ALG).map_err(|e| bad(&format!("vote message: {e}")))?;
                    if m.chain_id != expected.chain_id { return Err(OpenError::ChainMismatch); }
                    if m.epoch != rec.epoch { return Err(bad("vote message epoch differs from the record")); }
                    Some(m.round)
                }
                Kind::Timeout => {
                    let m = TimeoutMessage::decode(&item.message, ALG).map_err(|e| bad(&format!("timeout message: {e}")))?;
                    if m.chain_id != expected.chain_id { return Err(OpenError::ChainMismatch); }
                    if m.epoch != rec.epoch { return Err(bad("timeout message epoch differs from the record")); }
                    Some(m.round)
                }
                Kind::Proposal => {
                    BlockSigningMessage::decode(&item.message, ALG).map_err(|e| bad(&format!("proposal message: {e}")))?;
                    None
                }
            };
            if let Some(r) = message_round { if r != item.round { return Err(bad("stored round differs from the message round")); } }
            if !verifier.verify(&rec.public_key, kind.context(), &item.message, &item.envelope.signature) {
                return Err(OpenError::BadSignature { kind: kind.name() });
            }
            if kind != Kind::Proposal {
                match rec.hvr { Some(h) if h >= item.round => {} _ => return Err(bad("hvr is below a signed round")) }
            }
        }
        if rec.last_vote.is_some() && rec.hqr.is_none() { return Err(bad("a vote was signed but no lock round is recorded")); }
        Ok(())
    }

    pub fn record(&self) -> &SafetyRecord { &self.rec }
    pub fn is_latched(&self) -> bool { self.latched }

    /// Give the storage and counter back (to simulate a restart in tests, or to shut down).
    pub fn into_parts(self) -> (S, C) { (self.storage, self.counter) }

    /// Sign a vote. `qc_round` is the round of the QC the voted block carries; it only ever raises the recorded lock.
    pub fn sign_vote(&mut self, msg: &VoteMessage, qc_round: u64, signer: &mut dyn ConsensusSigner) -> Result<Signed, SignError> {
        if msg.chain_id != self.rec.chain_id { return Err(SignError::IdentityMismatch("chain id")); }
        let bytes = msg.encode()?;
        self.sign_core(Kind::Vote, msg.epoch, msg.round, bytes, Some(qc_round), signer)
    }

    pub fn sign_timeout(&mut self, msg: &TimeoutMessage, signer: &mut dyn ConsensusSigner) -> Result<Signed, SignError> {
        if msg.chain_id != self.rec.chain_id { return Err(SignError::IdentityMismatch("chain id")); }
        let bytes = msg.encode()?;
        self.sign_core(Kind::Timeout, msg.epoch, msg.round, bytes, None, signer)
    }

    /// Sign a block as its proposer. The block signing message carries no round, so the caller states `epoch` and `round`.
    pub fn sign_proposal(&mut self, epoch: u64, round: u64, msg: &BlockSigningMessage, signer: &mut dyn ConsensusSigner) -> Result<Signed, SignError> {
        let bytes = msg.encode()?;
        self.sign_core(Kind::Proposal, epoch, round, bytes, None, signer)
    }

    fn sign_core(&mut self, kind: Kind, epoch: u64, round: u64, message: Vec<u8>, qc_round: Option<u64>, signer: &mut dyn ConsensusSigner) -> Result<Signed, SignError> {
        if self.latched { return Err(SignError::Latched); }
        if signer.public_key() != self.rec.public_key.as_slice() { return Err(SignError::IdentityMismatch("signer key")); }
        if epoch < self.rec.epoch { return Err(SignError::EpochRegression { record: self.rec.epoch, requested: epoch }); }
        // floors and the stored item only mean something inside one epoch; a new epoch starts clean
        let same_epoch = epoch == self.rec.epoch;
        let (hvr, slot) = if same_epoch { (self.rec.hvr, self.rec.slot(kind).cloned()) } else { (None, None) };

        if let Some(s) = &slot {
            if s.round == round {
                // the same round: only the identical message, and it is re-sent verbatim, never re-signed
                return if s.message == message {
                    Ok(Signed { message: s.message.clone(), envelope: s.envelope.clone(), resent: true })
                } else {
                    Err(SignError::ConflictingMessage { kind: kind.name(), round })
                };
            }
            if s.round > round { return Err(SignError::RoundBelowSigned { kind: kind.name(), signed: s.round, requested: round }); }
        }
        match (kind, hvr) {
            (Kind::Vote, Some(h)) if round <= h => return Err(SignError::FloorViolation { kind: "vote", round, floor: h }),
            (Kind::Timeout, Some(h)) if round < h => return Err(SignError::FloorViolation { kind: "timeout", round, floor: h }),
            _ => {}
        }

        // sign (hedged). A failed signer, including a failed RNG, latches the store: fail closed.
        let signature = match signer.sign(kind.context(), &message) {
            Ok(s) => s,
            Err(e) => { self.latched = true; return Err(SignError::Signer(e.0)); }
        };
        if signature.len() != MLDSA65_SIGNATURE_LEN { self.latched = true; return Err(SignError::BadSignatureLength(signature.len())); }
        let envelope = SignatureEnvelope { alg_id: ALG, signature };
        let item = SignedItem { round, message: message.clone(), envelope: envelope.clone() };

        // the new record
        let mut n = self.rec.clone();
        if !same_epoch {
            n.epoch = epoch;
            n.hvr = None;
            n.hqr = None;
            n.last_vote = None;
            n.last_timeout = None;
            n.last_proposal = None;
        }
        n.state = State::Active;
        n.counter += 1;
        match kind {
            Kind::Vote => {
                n.hvr = Some(round);
                n.hqr = Some(n.hqr.unwrap_or(0).max(qc_round.unwrap_or(0)));
                n.last_vote = Some(item);
            }
            Kind::Timeout => {
                n.hvr = Some(n.hvr.unwrap_or(0).max(round));
                n.last_timeout = Some(item);
            }
            Kind::Proposal => n.last_proposal = Some(item),
        }

        // durable commit, then the trusted counter; only then is the signature returned
        if let Err(e) = self.commit(&n) { self.latched = true; return Err(SignError::Commit(e)); }
        self.rec = n;
        Ok(Signed { message, envelope, resent: false })
    }

    fn commit(&mut self, n: &SafetyRecord) -> Result<(), String> {
        let bytes = encode_record(n).map_err(|e| e.to_string())?;
        durable_replace(&mut self.storage, STATE_TMP, STATE_FILE, &bytes).map_err(|e| e.0)?;
        let t = self.counter.read().map_err(|e| e.0)?;
        self.counter.advance(t, &Session::new(0)).map_err(|e| e.0)
    }
}
