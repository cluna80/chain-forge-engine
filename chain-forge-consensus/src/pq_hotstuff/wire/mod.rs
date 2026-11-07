//! Canonical message serialization for PQ-HotStuff-2 (spec section 3.2, normative).
//!
//! Every item has exactly one valid byte string. All integers are unsigned big-endian (network byte order). Decoders are strict:
//! they reject truncation, trailing bytes, unknown or unpermitted algorithm identifiers, wrong lengths, non-canonical optional
//! flags and non-canonical strings, and `decode` followed by `encode` is the identity. This module does no cryptography: the
//! FIPS 204 context is passed to the signer separately and is never part of these bytes (spec 3.2 rule 1).
//!
//! Out of scope here, because the spec has not yet fixed their layouts: the `BlockPayload` encoding (so `H(payload)` is an
//! input, not computed) and the QC/TC encodings (so `H(qc)` is an input).
mod codec;

pub use codec::{decode_bitmap, encode_bitmap};

/// Constant, prefix-free ASCII tags (the `CFH1` family is retained).
pub const TAG_VOTE: &[u8] = b"CFH1|vote|";
pub const TAG_TIMEOUT: &[u8] = b"CFH1|timeout|";
pub const TAG_BLOCK: &[u8] = b"CFH1|block|";
pub const TAG_BLOCK_ID: &[u8] = b"CFH1|blockid|";
pub const TAG_POP: &[u8] = b"CFH1|pop|";
pub const ALL_TAGS: [&[u8]; 5] = [TAG_VOTE, TAG_TIMEOUT, TAG_BLOCK, TAG_BLOCK_ID, TAG_POP];

pub const HASH_LEN: usize = 32;
/// Maximum byte length of a `chain_id`, profile name, address or proposer string.
pub const MAX_NAME_LEN: usize = 255;
/// FIPS 204 ML-DSA-65 sizes (`alg_id` 1).
pub const MLDSA65_PUBLIC_KEY_LEN: usize = 1952;
pub const MLDSA65_SIGNATURE_LEN: usize = 3309;

/// The algorithm identifier: an unsigned 16-bit integer, big-endian on the wire, always 2 bytes. `1` is ML-DSA-65 (FIPS 204);
/// `0` is reserved and always invalid; any other value is unknown and invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AlgId(u16);

impl AlgId {
    pub const MLDSA65_FIPS204: AlgId = AlgId(1);

    pub fn new(value: u16) -> Result<AlgId, WireError> {
        match value {
            0 => Err(WireError::AlgIdReserved),
            1 => Ok(AlgId::MLDSA65_FIPS204),
            other => Err(WireError::AlgIdUnknown(other)),
        }
    }

    pub fn get(self) -> u16 { self.0 }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    #[error("input ended before the item was complete")]
    Truncated,
    #[error("{0} unexpected trailing byte(s) after a complete item")]
    TrailingBytes(usize),
    #[error("wrong domain tag")]
    BadTag,
    #[error("alg_id 0 is reserved and invalid")]
    AlgIdReserved,
    #[error("unknown alg_id {0}")]
    AlgIdUnknown(u16),
    #[error("alg_id {found} is not the algorithm the profile permits")]
    AlgIdNotPermitted { found: u16 },
    #[error("{what}: expected {expected} bytes, found {found}")]
    BadLength { what: &'static str, expected: usize, found: usize },
    #[error("{what}: declared length {len} is larger than the input or the limit")]
    LengthTooLarge { what: &'static str, len: usize },
    #[error("option flag must be 0 or 1, found {0}")]
    BadOption(u8),
    #[error("non-canonical bitmap")]
    BadBitmap,
    #[error("non-canonical string: {0}")]
    BadString(&'static str),
}

/// The message a validator signs for a vote (context `qattice/vote/v2`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoteMessage {
    pub alg_id: AlgId,
    pub chain_id: String,
    pub epoch: u64,
    pub round: u64,
    pub block_id: [u8; HASH_LEN],
    pub parent_id: [u8; HASH_LEN],
    pub parent_round: u64,
}

/// The message signed for a timeout (context `qattice/timeout/v2`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeoutMessage {
    pub alg_id: AlgId,
    pub chain_id: String,
    pub epoch: u64,
    pub round: u64,
    pub high_qc_round: u64,
}

/// The message the proposer signs over a block (context `qattice/proposal/v2`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockSigningMessage {
    pub alg_id: AlgId,
    pub block_id: [u8; HASH_LEN],
}

/// The input hashed to produce `block_id` (spec 3.2 rule 6). `payload_hash` and `qc_hash` are the hashes of the canonical
/// payload and QC encodings; those encodings are specified separately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockIdInput {
    pub alg_id: AlgId,
    pub protocol_profile: String,
    pub chain_id: String,
    pub epoch: u64,
    pub round: u64,
    pub height: u64,
    pub parent_id: [u8; HASH_LEN],
    pub payload_hash: [u8; HASH_LEN],
    pub qc_hash: [u8; HASH_LEN],
    pub tc_hash: Option<[u8; HASH_LEN]>,
    pub proposer: String,
}

/// The validator proof-of-possession message (context `qattice/validator-pop/v2`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PopMessage {
    pub alg_id: AlgId,
    pub chain_id: String,
    pub address: String,
    pub public_key: Vec<u8>,
}

/// A signature on the wire: `alg_id` then the signature bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureEnvelope {
    pub alg_id: AlgId,
    pub signature: Vec<u8>,
}

/// A validator key registration: `alg_id` then the public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRegistration {
    pub alg_id: AlgId,
    pub public_key: Vec<u8>,
}
