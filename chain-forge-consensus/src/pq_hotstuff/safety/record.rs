//! Canonical, checksummed encoding of the safety record and the initialization marker.
//!
//! Layout (all integers big-endian, as in the wire module; every item has exactly one valid byte string):
//!
//! ```text
//! record  = "PQHS" · version u16 · state u8 (0 fresh, 1 active) · profile string · chain_id string · public_key bytes
//!           · instance_id [16] · counter u64 · epoch u64 · hvr option<u64> · hqr option<u64>
//!           · slot(vote) · slot(timeout) · slot(proposal) · SHA3-256 of everything before it
//! slot    = 0x00 | 0x01 · round u64 · message bytes · envelope bytes      (the envelope is its canonical wire encoding)
//! marker  = "PQHI" · version u16 · profile string · chain_id string · public_key bytes · instance_id [16] · SHA3-256
//! string  = u32 length · UTF-8 (at most 255 bytes, no NUL)      bytes = u32 length · bytes      option = 0x00 | 0x01 · value
//! ```
//! The checksum detects corruption and truncation. It is not an authentication tag (see the module documentation).
use super::*;
use crate::pq_hotstuff::wire::{AlgId, MAX_NAME_LEN, MLDSA65_PUBLIC_KEY_LEN};
use sha3::{Digest, Sha3_256};

const RECORD_MAGIC: &[u8; 4] = b"PQHS";
const MARKER_MAGIC: &[u8; 4] = b"PQHI";
const CHECKSUM_LEN: usize = 32;
const MAX_ENVELOPE_LEN: usize = 4096;

/// The initialization marker: written once, before any state exists, so that a missing state file is distinguishable from a
/// never-initialized validator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Marker {
    pub protocol_profile: String,
    pub chain_id: String,
    pub public_key: Vec<u8>,
    pub instance_id: [u8; 16],
}

// ------------------------------------------------------------------ writing

fn put_u16(o: &mut Vec<u8>, v: u16) { o.extend_from_slice(&v.to_be_bytes()); }
fn put_u32(o: &mut Vec<u8>, v: u32) { o.extend_from_slice(&v.to_be_bytes()); }
fn put_u64(o: &mut Vec<u8>, v: u64) { o.extend_from_slice(&v.to_be_bytes()); }

fn put_string(o: &mut Vec<u8>, what: &'static str, s: &str) -> Result<(), RecordError> {
    if s.len() > MAX_NAME_LEN { return Err(RecordError::TooLarge { what, len: s.len() }); }
    if s.as_bytes().contains(&0) { return Err(RecordError::BadField(what)); }
    put_u32(o, s.len() as u32);
    o.extend_from_slice(s.as_bytes());
    Ok(())
}

fn put_bytes(o: &mut Vec<u8>, what: &'static str, b: &[u8], max: usize) -> Result<(), RecordError> {
    if b.len() > max { return Err(RecordError::TooLarge { what, len: b.len() }); }
    put_u32(o, b.len() as u32);
    o.extend_from_slice(b);
    Ok(())
}

fn put_public_key(o: &mut Vec<u8>, pk: &[u8]) -> Result<(), RecordError> {
    if pk.len() != MLDSA65_PUBLIC_KEY_LEN { return Err(RecordError::BadField("public_key length")); }
    put_bytes(o, "public_key", pk, MLDSA65_PUBLIC_KEY_LEN)
}

fn put_opt_u64(o: &mut Vec<u8>, v: Option<u64>) {
    match v { None => o.push(0), Some(x) => { o.push(1); put_u64(o, x); } }
}

fn put_slot(o: &mut Vec<u8>, s: &Option<SignedItem>) -> Result<(), RecordError> {
    match s {
        None => o.push(0),
        Some(item) => {
            o.push(1);
            put_u64(o, item.round);
            put_bytes(o, "message", &item.message, MAX_MESSAGE_LEN)?;
            put_bytes(o, "envelope", &item.envelope.encode()?, MAX_ENVELOPE_LEN)?;
        }
    }
    Ok(())
}

fn seal(mut body: Vec<u8>) -> Vec<u8> {
    let sum = Sha3_256::digest(&body);
    body.extend_from_slice(&sum);
    body
}

pub fn encode_record(r: &SafetyRecord) -> Result<Vec<u8>, RecordError> {
    let mut o = Vec::with_capacity(6144);
    o.extend_from_slice(RECORD_MAGIC);
    put_u16(&mut o, FORMAT_VERSION);
    o.push(match r.state { State::Fresh => 0, State::Active => 1 });
    put_string(&mut o, "protocol_profile", &r.protocol_profile)?;
    put_string(&mut o, "chain_id", &r.chain_id)?;
    put_public_key(&mut o, &r.public_key)?;
    o.extend_from_slice(&r.instance_id);
    put_u64(&mut o, r.counter);
    put_u64(&mut o, r.epoch);
    put_opt_u64(&mut o, r.hvr);
    put_opt_u64(&mut o, r.hqr);
    put_slot(&mut o, &r.last_vote)?;
    put_slot(&mut o, &r.last_timeout)?;
    put_slot(&mut o, &r.last_proposal)?;
    Ok(seal(o))
}

pub fn encode_marker(m: &Marker) -> Result<Vec<u8>, RecordError> {
    let mut o = Vec::with_capacity(2112);
    o.extend_from_slice(MARKER_MAGIC);
    put_u16(&mut o, FORMAT_VERSION);
    put_string(&mut o, "protocol_profile", &m.protocol_profile)?;
    put_string(&mut o, "chain_id", &m.chain_id)?;
    put_public_key(&mut o, &m.public_key)?;
    o.extend_from_slice(&m.instance_id);
    Ok(seal(o))
}

// ------------------------------------------------------------------ reading

struct Reader<'a> { b: &'a [u8], pos: usize }

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], RecordError> {
        let end = self.pos.checked_add(n).ok_or(RecordError::Truncated)?;
        if end > self.b.len() { return Err(RecordError::Truncated); }
        let s = &self.b[self.pos..end];
        self.pos = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, RecordError> { Ok(self.take(1)?[0]) }
    fn u32(&mut self) -> Result<u32, RecordError> { Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap())) }
    fn u64(&mut self) -> Result<u64, RecordError> { Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap())) }

    fn string(&mut self, what: &'static str) -> Result<String, RecordError> {
        let len = self.u32()? as usize;
        if len > MAX_NAME_LEN { return Err(RecordError::TooLarge { what, len }); }
        let raw = self.take(len)?;
        let s = std::str::from_utf8(raw).map_err(|_| RecordError::BadField(what))?;
        if raw.contains(&0) { return Err(RecordError::BadField(what)); }
        Ok(s.to_owned())
    }

    /// `bytes` with a declared length bound checked before anything is read or allocated.
    fn bytes(&mut self, what: &'static str, max: usize) -> Result<Vec<u8>, RecordError> {
        let len = self.u32()? as usize;
        if len > max { return Err(RecordError::TooLarge { what, len }); }
        Ok(self.take(len)?.to_vec())
    }

    fn public_key(&mut self) -> Result<Vec<u8>, RecordError> {
        let len = self.u32()? as usize;
        if len != MLDSA65_PUBLIC_KEY_LEN { return Err(RecordError::BadField("public_key length")); }
        Ok(self.take(len)?.to_vec())
    }

    fn opt_u64(&mut self) -> Result<Option<u64>, RecordError> {
        match self.u8()? { 0 => Ok(None), 1 => Ok(Some(self.u64()?)), _ => Err(RecordError::BadField("option flag")) }
    }

    fn slot(&mut self) -> Result<Option<SignedItem>, RecordError> {
        match self.u8()? {
            0 => Ok(None),
            1 => {
                let round = self.u64()?;
                let message = self.bytes("message", MAX_MESSAGE_LEN)?;
                let env = self.bytes("envelope", MAX_ENVELOPE_LEN)?;
                let envelope = crate::pq_hotstuff::wire::SignatureEnvelope::decode(&env, AlgId::MLDSA65_FIPS204)?;
                Ok(Some(SignedItem { round, message, envelope }))
            }
            _ => Err(RecordError::BadField("option flag")),
        }
    }

    fn finish(self) -> Result<(), RecordError> {
        match self.b.len() - self.pos { 0 => Ok(()), n => Err(RecordError::Trailing(n)) }
    }
}

/// Check magic, version and checksum, and return the body (everything before the checksum), positioned after the header.
fn open_sealed<'a>(b: &'a [u8], magic: &[u8; 4]) -> Result<Reader<'a>, RecordError> {
    if b.len() < 4 + 2 + CHECKSUM_LEN { return Err(RecordError::Truncated); }
    if &b[..4] != magic { return Err(RecordError::BadMagic); }
    let version = u16::from_be_bytes([b[4], b[5]]);
    if version != FORMAT_VERSION { return Err(RecordError::Version(version)); }
    let (body, sum) = b.split_at(b.len() - CHECKSUM_LEN);
    if Sha3_256::digest(body)[..] != *sum { return Err(RecordError::BadChecksum); }
    Ok(Reader { b: body, pos: 6 })
}

pub fn decode_record(b: &[u8]) -> Result<SafetyRecord, RecordError> {
    let mut r = open_sealed(b, RECORD_MAGIC)?;
    let state = match r.u8()? { 0 => State::Fresh, 1 => State::Active, _ => return Err(RecordError::BadField("state")) };
    let rec = SafetyRecord {
        state,
        protocol_profile: r.string("protocol_profile")?,
        chain_id: r.string("chain_id")?,
        public_key: r.public_key()?,
        instance_id: r.take(16)?.try_into().unwrap(),
        counter: r.u64()?,
        epoch: r.u64()?,
        hvr: r.opt_u64()?,
        hqr: r.opt_u64()?,
        last_vote: r.slot()?,
        last_timeout: r.slot()?,
        last_proposal: r.slot()?,
    };
    r.finish()?;
    Ok(rec)
}

pub fn decode_marker(b: &[u8]) -> Result<Marker, RecordError> {
    let mut r = open_sealed(b, MARKER_MAGIC)?;
    let m = Marker {
        protocol_profile: r.string("protocol_profile")?,
        chain_id: r.string("chain_id")?,
        public_key: r.public_key()?,
        instance_id: r.take(16)?.try_into().unwrap(),
    };
    r.finish()?;
    Ok(m)
}
