//! Encoders and strict decoders for the section 3.2 layouts.
use super::*;
use sha3::{Digest, Sha3_256};

// ------------------------------------------------------------------ writing

fn put_u16(o: &mut Vec<u8>, v: u16) { o.extend_from_slice(&v.to_be_bytes()); }
fn put_u32(o: &mut Vec<u8>, v: u32) { o.extend_from_slice(&v.to_be_bytes()); }
fn put_u64(o: &mut Vec<u8>, v: u64) { o.extend_from_slice(&v.to_be_bytes()); }

/// `string`: `u32` byte length, then UTF-8; at most 255 bytes; no NUL.
fn put_string(o: &mut Vec<u8>, what: &'static str, s: &str) -> Result<(), WireError> {
    if s.len() > MAX_NAME_LEN { return Err(WireError::LengthTooLarge { what, len: s.len() }); }
    if s.as_bytes().contains(&0) { return Err(WireError::BadString("NUL byte")); }
    put_u32(o, s.len() as u32);
    o.extend_from_slice(s.as_bytes());
    Ok(())
}

/// `bytes` whose length the algorithm fixes exactly: `u32` length, then the bytes.
fn put_exact_bytes(o: &mut Vec<u8>, what: &'static str, b: &[u8], expected: usize) -> Result<(), WireError> {
    if b.len() != expected { return Err(WireError::BadLength { what, expected, found: b.len() }); }
    put_u32(o, b.len() as u32);
    o.extend_from_slice(b);
    Ok(())
}

fn public_key_len(alg: AlgId) -> usize { match alg.get() { 1 => MLDSA65_PUBLIC_KEY_LEN, _ => unreachable!("AlgId only holds known values") } }
fn signature_len(alg: AlgId) -> usize { match alg.get() { 1 => MLDSA65_SIGNATURE_LEN, _ => unreachable!("AlgId only holds known values") } }

// ------------------------------------------------------------------ reading

struct Reader<'a> { b: &'a [u8], pos: usize }

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self { Reader { b, pos: 0 } }

    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let end = self.pos.checked_add(n).ok_or(WireError::Truncated)?;
        if end > self.b.len() { return Err(WireError::Truncated); }
        let s = &self.b[self.pos..end];
        self.pos = end;
        Ok(s)
    }
    fn u16(&mut self) -> Result<u16, WireError> { Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap())) }
    fn u32(&mut self) -> Result<u32, WireError> { Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap())) }
    fn u64(&mut self) -> Result<u64, WireError> { Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap())) }
    fn bytes32(&mut self) -> Result<[u8; HASH_LEN], WireError> { Ok(self.take(HASH_LEN)?.try_into().unwrap()) }

    fn tag(&mut self, tag: &[u8]) -> Result<(), WireError> {
        if self.take(tag.len()).map_err(|_| WireError::BadTag)? == tag { Ok(()) } else { Err(WireError::BadTag) }
    }

    /// The algorithm identifier, checked before anything after it is read.
    fn alg(&mut self, permitted: AlgId) -> Result<AlgId, WireError> {
        let found = AlgId::new(self.u16()?)?;
        if found != permitted { return Err(WireError::AlgIdNotPermitted { found: found.get() }); }
        Ok(found)
    }

    fn string(&mut self, what: &'static str) -> Result<String, WireError> {
        let len = self.u32()? as usize;
        if len > MAX_NAME_LEN { return Err(WireError::LengthTooLarge { what, len }); }
        let raw = self.take(len)?;
        let s = std::str::from_utf8(raw).map_err(|_| WireError::BadString("not valid UTF-8"))?;
        if raw.contains(&0) { return Err(WireError::BadString("NUL byte")); }
        Ok(s.to_owned())
    }

    /// `bytes` whose declared length must equal `expected`; checked before the bytes are read or any buffer is allocated.
    fn exact_bytes(&mut self, what: &'static str, expected: usize) -> Result<Vec<u8>, WireError> {
        let len = self.u32()? as usize;
        if len != expected { return Err(WireError::BadLength { what, expected, found: len }); }
        Ok(self.take(len)?.to_vec())
    }

    fn option_hash(&mut self) -> Result<Option<[u8; HASH_LEN]>, WireError> {
        match self.take(1)?[0] {
            0 => Ok(None),
            1 => Ok(Some(self.bytes32()?)),
            other => Err(WireError::BadOption(other)),
        }
    }

    fn finish(self) -> Result<(), WireError> {
        match self.b.len() - self.pos { 0 => Ok(()), n => Err(WireError::TrailingBytes(n)) }
    }
}

// ------------------------------------------------------------------ bitmap

/// `bitmap`: `u32` bit count, then `ceil(n/8)` bytes, most significant bit first, unused trailing bits zero.
pub fn encode_bitmap(bits: &[bool]) -> Result<Vec<u8>, WireError> {
    let n = u32::try_from(bits.len()).map_err(|_| WireError::LengthTooLarge { what: "bitmap", len: bits.len() })?;
    let mut o = Vec::with_capacity(4 + (bits.len() + 7) / 8);
    put_u32(&mut o, n);
    for chunk in bits.chunks(8) {
        o.push(chunk.iter().enumerate().fold(0u8, |acc, (i, &b)| acc | ((b as u8) << (7 - i))));
    }
    Ok(o)
}

pub fn decode_bitmap(bytes: &[u8]) -> Result<Vec<bool>, WireError> {
    let mut r = Reader::new(bytes);
    let n = r.u32()? as usize;
    let data = r.take((n + 7) / 8)?;
    r.finish()?;
    if n % 8 != 0 && data[data.len() - 1] & (0xFFu8 >> (n % 8)) != 0 { return Err(WireError::BadBitmap); }
    Ok((0..n).map(|i| data[i / 8] & (0x80 >> (i % 8)) != 0).collect())
}

// ------------------------------------------------------------------ items

impl VoteMessage {
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        let mut o = Vec::with_capacity(128);
        o.extend_from_slice(TAG_VOTE);
        put_u16(&mut o, self.alg_id.get());
        put_string(&mut o, "chain_id", &self.chain_id)?;
        put_u64(&mut o, self.epoch);
        put_u64(&mut o, self.round);
        o.extend_from_slice(&self.block_id);
        o.extend_from_slice(&self.parent_id);
        put_u64(&mut o, self.parent_round);
        Ok(o)
    }

    pub fn decode(bytes: &[u8], permitted: AlgId) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        r.tag(TAG_VOTE)?;
        let alg_id = r.alg(permitted)?;
        let v = VoteMessage {
            alg_id, chain_id: r.string("chain_id")?, epoch: r.u64()?, round: r.u64()?,
            block_id: r.bytes32()?, parent_id: r.bytes32()?, parent_round: r.u64()?,
        };
        r.finish()?;
        Ok(v)
    }
}

impl TimeoutMessage {
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        let mut o = Vec::with_capacity(64);
        o.extend_from_slice(TAG_TIMEOUT);
        put_u16(&mut o, self.alg_id.get());
        put_string(&mut o, "chain_id", &self.chain_id)?;
        put_u64(&mut o, self.epoch);
        put_u64(&mut o, self.round);
        put_u64(&mut o, self.high_qc_round);
        Ok(o)
    }

    pub fn decode(bytes: &[u8], permitted: AlgId) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        r.tag(TAG_TIMEOUT)?;
        let alg_id = r.alg(permitted)?;
        let v = TimeoutMessage { alg_id, chain_id: r.string("chain_id")?, epoch: r.u64()?, round: r.u64()?, high_qc_round: r.u64()? };
        r.finish()?;
        Ok(v)
    }
}

impl BlockSigningMessage {
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        let mut o = Vec::with_capacity(48);
        o.extend_from_slice(TAG_BLOCK);
        put_u16(&mut o, self.alg_id.get());
        o.extend_from_slice(&self.block_id);
        Ok(o)
    }

    pub fn decode(bytes: &[u8], permitted: AlgId) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        r.tag(TAG_BLOCK)?;
        let alg_id = r.alg(permitted)?;
        let v = BlockSigningMessage { alg_id, block_id: r.bytes32()? };
        r.finish()?;
        Ok(v)
    }
}

impl BlockIdInput {
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        let mut o = Vec::with_capacity(256);
        o.extend_from_slice(TAG_BLOCK_ID);
        put_u16(&mut o, self.alg_id.get());
        put_string(&mut o, "protocol_profile", &self.protocol_profile)?;
        put_string(&mut o, "chain_id", &self.chain_id)?;
        put_u64(&mut o, self.epoch);
        put_u64(&mut o, self.round);
        put_u64(&mut o, self.height);
        o.extend_from_slice(&self.parent_id);
        o.extend_from_slice(&self.payload_hash);
        o.extend_from_slice(&self.qc_hash);
        match &self.tc_hash {
            None => o.push(0),
            Some(h) => { o.push(1); o.extend_from_slice(h); }
        }
        put_string(&mut o, "proposer", &self.proposer)?;
        Ok(o)
    }

    pub fn decode(bytes: &[u8], permitted: AlgId) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        r.tag(TAG_BLOCK_ID)?;
        let alg_id = r.alg(permitted)?;
        let v = BlockIdInput {
            alg_id, protocol_profile: r.string("protocol_profile")?, chain_id: r.string("chain_id")?,
            epoch: r.u64()?, round: r.u64()?, height: r.u64()?, parent_id: r.bytes32()?, payload_hash: r.bytes32()?,
            qc_hash: r.bytes32()?, tc_hash: r.option_hash()?, proposer: r.string("proposer")?,
        };
        r.finish()?;
        Ok(v)
    }

    /// `block_id = SHA3-256` of the canonical input. A verifier recomputes it from the received fields; it never trusts an
    /// identifier carried on the wire.
    pub fn block_id(&self) -> Result<[u8; HASH_LEN], WireError> {
        Ok(Sha3_256::digest(self.encode()?).into())
    }
}

impl PopMessage {
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        let mut o = Vec::with_capacity(2048);
        o.extend_from_slice(TAG_POP);
        put_u16(&mut o, self.alg_id.get());
        put_string(&mut o, "chain_id", &self.chain_id)?;
        put_string(&mut o, "address", &self.address)?;
        put_exact_bytes(&mut o, "public_key", &self.public_key, public_key_len(self.alg_id))?;
        Ok(o)
    }

    pub fn decode(bytes: &[u8], permitted: AlgId) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        r.tag(TAG_POP)?;
        let alg_id = r.alg(permitted)?;
        let v = PopMessage {
            alg_id, chain_id: r.string("chain_id")?, address: r.string("address")?,
            public_key: r.exact_bytes("public_key", public_key_len(alg_id))?,
        };
        r.finish()?;
        Ok(v)
    }
}

impl SignatureEnvelope {
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        let mut o = Vec::with_capacity(3320);
        put_u16(&mut o, self.alg_id.get());
        put_exact_bytes(&mut o, "signature", &self.signature, signature_len(self.alg_id))?;
        Ok(o)
    }

    pub fn decode(bytes: &[u8], permitted: AlgId) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        let alg_id = r.alg(permitted)?;
        let v = SignatureEnvelope { alg_id, signature: r.exact_bytes("signature", signature_len(alg_id))? };
        r.finish()?;
        Ok(v)
    }
}

impl KeyRegistration {
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        let mut o = Vec::with_capacity(1960);
        put_u16(&mut o, self.alg_id.get());
        put_exact_bytes(&mut o, "public_key", &self.public_key, public_key_len(self.alg_id))?;
        Ok(o)
    }

    pub fn decode(bytes: &[u8], permitted: AlgId) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        let alg_id = r.alg(permitted)?;
        let v = KeyRegistration { alg_id, public_key: r.exact_bytes("public_key", public_key_len(alg_id))? };
        r.finish()?;
        Ok(v)
    }
}
