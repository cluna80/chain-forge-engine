//! Crash-safe safety-state persistence for PQ-HotStuff-2 (spec section 7, Phase 1 step 1).
//!
//! A validator must never sign two conflicting messages, even across crashes, restarts, interrupted writes and damaged or
//! restored state. This module keeps, durably and before anything can be broadcast, the last vote, timeout and proposal it
//! signed (the exact canonical message and the exact signature envelope) together with the round floors.
//!
//! # Commit sequence (a new signature is returned to the caller only after step 7)
//! 1. check the persisted state (floors, one message per round) -> 2. build the canonical message (wire, spec 3.2) ->
//! 3. sign (hedged) -> 4. write the new record to a temporary file -> 5. `fsync` it -> 6. rename it over the state file and
//! `fsync` the directory -> 7. **compare-and-advance** the trusted monotonic counter from the record's previous counter, presenting
//! the store's exclusive-writer [`Session`]. Only then is the signed item returned; sending it is the caller's next step.
//!
//! # Sessions (spec section 7.1)
//! A store becomes the one valid writer by acquiring a [`Session`] from the counter, and only after every validation in `open` has
//! passed (a failed open never supersedes the running store). Every counter advance presents that session; the counter refuses
//! stale ones, and the store then latches and returns nothing. A successful advance is permission to return *that* signature from
//! the commit path and nothing more: the signer is called only inside the commit path, no method returns a raw signature, and the
//! caller holds no way to obtain one from the store without a completed commit.
//!
//! # Digest-bound commits (spec section 7.1.1)
//! The counter holds `(value, digest)`, where the digest is the checksum that seals the record's canonical body, and every record
//! carries the digest of the record it replaced. A commit advances from the replaced record's state to the new record's digest.
//! On open, a file at the committed counter value must be the committed record (otherwise it is a fork and is refused), and a file
//! one ahead must be a successor of the committed record. So a record left behind by a fenced-out writer, or a file overwritten
//! after the commit, is refused on restart instead of being mistaken for the committed state.
//!
//! # What this does and does not protect
//! * A crash at any point leaves either the old record or the new record (the temporary file is never read), and nothing has
//!   been sent for an uncommitted record. After a restart the stored message is re-sent byte-for-byte and never re-signed.
//! * **Rollback.** An ordinary file cannot tell a restored old backup from the current file, and this module does not claim
//!   it can. Rollback is detected only through the [`MonotonicCounter`], which must be a trusted mechanism outside the file's
//!   reach (hardware counter, HSM, remote witness). The counter implementations in this repository's tests are test doubles.
//!   Without a trusted counter, a restored backup is undetectable; with one, an older file is rejected.
//! * The record carries an integrity checksum, not an authentication tag: someone who can write the file can forge it. The
//!   stored signatures are verified on load, so the stored *messages* cannot be forged without the validator's key.
//! * Keys: none are stored or handled here. Signing goes through the [`ConsensusSigner`] trait; production validator key
//!   storage is out of scope (blocked on the independent review of PR #109).
mod fs;
mod record;
mod store;

pub use fs::FsStorage;
pub use record::{decode_marker, decode_record, encode_marker, encode_record, Marker};
pub use store::{FreshInit, SafetyStore, Signed};

use super::wire::{SignatureEnvelope, WireError};

/// FIPS 204 contexts (domain separation) for the three things a validator signs here.
pub const CTX_VOTE: &[u8] = b"qattice/vote/v2";
pub const CTX_TIMEOUT: &[u8] = b"qattice/timeout/v2";
pub const CTX_PROPOSAL: &[u8] = b"qattice/proposal/v2";

/// File names inside the safety directory.
pub const STATE_FILE: &str = "pq_hotstuff_safety.state";
pub const MARKER_FILE: &str = "pq_hotstuff_safety.init";
pub const STATE_TMP: &str = "pq_hotstuff_safety.state.tmp";
pub const MARKER_TMP: &str = "pq_hotstuff_safety.init.tmp";

pub const FORMAT_VERSION: u16 = 2;
/// Upper bound on a stored canonical message.
pub const MAX_MESSAGE_LEN: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind { Vote, Timeout, Proposal }

impl Kind {
    pub fn context(self) -> &'static [u8] {
        match self { Kind::Vote => CTX_VOTE, Kind::Timeout => CTX_TIMEOUT, Kind::Proposal => CTX_PROPOSAL }
    }
    pub fn name(self) -> &'static str {
        match self { Kind::Vote => "vote", Kind::Timeout => "timeout", Kind::Proposal => "proposal" }
    }
}

/// The last thing signed of one kind: the exact canonical message and the exact signature envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedItem {
    pub round: u64,
    pub message: Vec<u8>,
    pub envelope: SignatureEnvelope,
}

/// `Fresh`: explicitly initialized, nothing signed yet. `Active`: at least one signature has been produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State { Fresh, Active }

/// The persisted safety state (spec section 7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafetyRecord {
    pub state: State,
    pub protocol_profile: String,
    pub chain_id: String,
    pub public_key: Vec<u8>,
    pub instance_id: [u8; 16],
    /// Monotonic write counter; equals the trusted counter after a completed commit.
    pub counter: u64,
    /// The digest of the record this one replaced (all zero for the first record); chains the records (spec 7.1.1).
    pub prev_digest: [u8; 32],
    pub epoch: u64,
    /// Highest round at which a vote or timeout was signed in `epoch` (`None` = none yet).
    pub hvr: Option<u64>,
    /// Highest QC round this validator has voted on (the lock).
    pub hqr: Option<u64>,
    pub last_vote: Option<SignedItem>,
    pub last_timeout: Option<SignedItem>,
    pub last_proposal: Option<SignedItem>,
}

impl SafetyRecord {
    /// The digest the trusted counter commits to for this record: the checksum sealing its canonical encoding.
    pub fn digest(&self) -> Result<[u8; 32], RecordError> {
        let b = encode_record(self)?;
        Ok(b[b.len() - 32..].try_into().unwrap())
    }

    pub fn slot(&self, kind: Kind) -> Option<&SignedItem> {
        match kind { Kind::Vote => self.last_vote.as_ref(), Kind::Timeout => self.last_timeout.as_ref(), Kind::Proposal => self.last_proposal.as_ref() }
    }

    /// The highest `(epoch, round)` this record shows the key has signed at, if any.
    pub fn high_water(&self) -> Option<(u64, u64)> {
        let r = [self.hvr, self.last_proposal.as_ref().map(|p| p.round)].into_iter().flatten().max()?;
        Some((self.epoch, r))
    }
}

/// What the chain already shows about this key (committed participation). Used to refuse a stale record and to refuse
/// "fresh" initialization of a key that has already participated.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ParticipationEvidence {
    /// Highest `(epoch, round)` at which this key appears in committed QCs, TCs, vote evidence or participation records.
    pub highest_signed: Option<(u64, u64)>,
}

/// The identity the caller expects the record to belong to.
#[derive(Debug, Clone, Copy)]
pub struct Expected<'a> {
    pub protocol_profile: &'a str,
    pub chain_id: &'a str,
    pub public_key: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("storage: {0}")]
pub struct StorageError(pub String);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("monotonic counter: {0}")]
pub struct CounterError(pub String);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("signer: {0}")]
pub struct SignerError(pub String);

/// Durable storage, exposed as the individual steps so that every step can be fault-injected and its durability reasoned about.
pub trait Storage {
    /// `Ok(None)` if the file does not exist.
    fn read(&self, name: &str) -> Result<Option<Vec<u8>>, StorageError>;
    /// Create or truncate `name` and write `data`. Not durable until [`Storage::sync_file`].
    fn write_tmp(&mut self, name: &str, data: &[u8]) -> Result<(), StorageError>;
    /// Make the contents of `name` durable.
    fn sync_file(&mut self, name: &str) -> Result<(), StorageError>;
    /// Atomically replace `to` with `from`. Not durable until [`Storage::sync_dir`].
    fn rename(&mut self, from: &str, to: &str) -> Result<(), StorageError>;
    /// Make directory entries (creations, renames) durable.
    fn sync_dir(&mut self) -> Result<(), StorageError>;
    /// Remove `name` if present (used only to clear a stale temporary file).
    fn remove(&mut self, name: &str) -> Result<(), StorageError>;
}

/// The identity a counter belongs to: one validator key and one initialization instance. A counter handle is constructed bound
/// to exactly one identity and is never reused for another (spec section 7.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CounterBinding {
    pub public_key: Vec<u8>,
    pub instance_id: [u8; 16],
}

/// What a counter holds: how many records have been committed and the digest of the latest one (spec 7.1.1). The digest is the
/// SHA3-256 checksum that seals the record's canonical body, so it commits to the whole record, including its predecessor's digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CounterState {
    pub value: u64,
    pub digest: [u8; 32],
}

impl CounterState {
    /// A counter that has never been advanced.
    pub const INITIAL: CounterState = CounterState { value: 0, digest: [0; 32] };
}

/// The exclusive-writer credential: a fencing token that increases with every acquisition. Only the holder of the latest
/// session can advance the counter (spec section 7.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session { token: u64 }

impl Session {
    /// For counter backends, which issue sessions. The store never invents one.
    pub fn new(token: u64) -> Self { Session { token } }
    pub fn token(&self) -> u64 { self.token }
}

/// A trusted monotonic counter that the file's owner cannot roll back (hardware counter, HSM, remote witness). It must be
/// durable, atomic, bound to one validator instance, enforce one exclusive signing session, and refuse to move backwards.
/// **An ordinary file is not a valid implementation**, and neither is any test double in this repository.
pub trait MonotonicCounter {
    /// The validator identity this counter belongs to.
    fn binding(&self) -> &CounterBinding;
    fn read(&self) -> Result<CounterState, CounterError>;
    /// Become the one valid writer. Supersedes every earlier session; the backend rejects advances from those.
    fn acquire_session(&mut self) -> Result<Session, CounterError>;
    /// Compare-and-advance: succeeds only if the counter's current state equals `expected` (value **and** digest) and `session`
    /// is the latest session, and then becomes `(expected.value + 1, new_digest)`. Otherwise it fails and changes nothing.
    /// There is no idempotent form.
    fn advance(&mut self, expected: &CounterState, new_digest: [u8; 32], session: &Session) -> Result<(), CounterError>;
}

/// Signs one canonical message under a FIPS 204 context (hedged). Returns the raw signature bytes.
pub trait ConsensusSigner {
    fn public_key(&self) -> &[u8];
    fn sign(&mut self, context: &[u8], message: &[u8]) -> Result<Vec<u8>, SignerError>;
}

/// Verifies a raw signature under a FIPS 204 context.
pub trait ConsensusVerifier {
    fn verify(&self, public_key: &[u8], context: &[u8], message: &[u8], signature: &[u8]) -> bool;
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecordError {
    #[error("truncated")]
    Truncated,
    #[error("{0} trailing byte(s)")]
    Trailing(usize),
    #[error("bad magic")]
    BadMagic,
    #[error("unsupported format version {0}")]
    Version(u16),
    #[error("checksum mismatch")]
    BadChecksum,
    #[error("non-canonical field: {0}")]
    BadField(&'static str),
    #[error("{what}: {len} bytes exceeds the limit")]
    TooLarge { what: &'static str, len: usize },
    #[error("wire: {0}")]
    Wire(#[from] WireError),
}

/// Why a validator's safety state could not be opened. Every variant means: do not sign (an observer may keep running).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OpenError {
    #[error("no safety state exists (open never creates one; initialization is explicit)")]
    NoState,
    #[error("an initialization marker exists but the state file is missing")]
    MarkerWithoutState,
    #[error("a state file exists but the initialization marker is missing")]
    StateWithoutMarker,
    #[error("damaged or non-canonical state: {0}")]
    Damaged(String),
    #[error("unsupported format version {0}")]
    VersionUnsupported(u16),
    #[error("the record belongs to a different protocol profile")]
    ProfileMismatch,
    #[error("the record belongs to a different chain")]
    ChainMismatch,
    #[error("the record belongs to a different validator key")]
    KeyMismatch,
    #[error("the state file and the initialization marker do not belong together")]
    InstanceMismatch,
    #[error("a stored {kind} signature does not verify")]
    BadSignature { kind: &'static str },
    #[error("rollback: the state file is at counter {file_counter} but the trusted counter is {trusted_counter}")]
    Rollback { file_counter: u64, trusted_counter: u64 },
    #[error("fork: the file is at the committed counter {counter} but is not the committed record")]
    Fork { counter: u64 },
    #[error("the file is one ahead of the counter {counter} but is a successor of a record other than the committed one")]
    SuccessorOfAnotherRecord { counter: u64 },
    #[error("counter inconsistency: file {file_counter}, trusted {trusted_counter}")]
    CounterInconsistent { file_counter: u64, trusted_counter: u64 },
    #[error("stale: the chain shows this key signing at {chain:?}, beyond the record's {record:?}")]
    StaleAgainstChain { chain: (u64, u64), record: Option<(u64, u64)> },
    #[error("the counter is bound to a different validator identity than the record")]
    CounterBindingMismatch,
    #[error("{0}")]
    Storage(String),
    #[error("{0}")]
    Counter(String),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InitError {
    #[error("safety state or an initialization marker already exists; a key is initialized once")]
    AlreadyInitialized,
    #[error("the trusted counter is {0}, so this identity has been used before")]
    CounterNotZero(u64),
    #[error("this key already appears in committed participation; it cannot be initialized fresh")]
    KeyAlreadyParticipated,
    #[error("invalid identity: {0}")]
    BadIdentity(&'static str),
    #[error("the counter is bound to a different validator identity")]
    CounterBindingMismatch,
    #[error("{0}")]
    Storage(String),
    #[error("{0}")]
    Counter(String),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SignError {
    #[error("the store is latched after a failure and refuses to sign; restart and reopen")]
    Latched,
    #[error("epoch {requested} is below the recorded epoch {record}")]
    EpochRegression { record: u64, requested: u64 },
    #[error("a different {kind} was already signed for round {round}")]
    ConflictingMessage { kind: &'static str, round: u64 },
    #[error("a {kind} for round {signed} was already signed, so round {requested} is below it")]
    RoundBelowSigned { kind: &'static str, signed: u64, requested: u64 },
    #[error("{kind} at round {round} violates the persisted floor {floor}")]
    FloorViolation { kind: &'static str, round: u64, floor: u64 },
    #[error("{0}")]
    Wire(#[from] WireError),
    #[error("the request does not match this validator: {0}")]
    IdentityMismatch(&'static str),
    #[error("{0}")]
    Signer(String),
    #[error("the signer returned {0} bytes, not a valid signature")]
    BadSignatureLength(usize),
    #[error("commit failed: {0}")]
    Commit(String),
}
