//! PERSIST-001 P-02b PR 1 — canonical binary encoding primitives (UNWIRED).
//!
//! Owner decision (2026-11-03): log payloads use an explicitly specified, deterministic, versioned
//! binary encoding with golden bytes pinned on Windows and Linux. This module defines the
//! **primitives and the strict decoder**; the encoders for the consensus types
//! (`CommitCertificate`, `BlockProposal`, `ValidatorSet`) need those types and ship in PR 2 with their
//! own pinned vectors.
//!
//! # Specification (version 1)
//! * Integers: fixed width, **little-endian** (`u8`, `u16`, `u32`, `u64`). No varints.
//! * `bool`: one byte, `0x00` or `0x01`; any other value is a decode error.
//! * Byte string: `u64` length, then that many bytes. `str`: the same, bytes must be valid UTF-8.
//! * `Option<T>`: one tag byte, `0x00` (absent) or `0x01` (present, then `T`); any other tag is an error.
//! * Sequence: `u64` element count, then the elements in order. **Maps are encoded as a sequence of
//!   `(key, value)` pairs sorted by the key's encoded bytes**; the encoder helper enforces strict
//!   ascending order and the decoder rejects any other order or a duplicate key.
//! * No padding, no alignment, no floating point, no platform-dependent width (`usize` is never encoded).
//! * Decoding is **strict**: truncated input, trailing bytes, a length above the remaining input, an
//!   invalid tag or invalid UTF-8 are errors; nothing is repaired or defaulted.
//! * Every encoded value is prefixed by the caller with a schema version byte (`Canonical::VERSION`);
//!   an unknown version is an error.

#![allow(dead_code)]

#[derive(Debug, PartialEq, Eq)]
pub enum CanonError {
    Truncated,
    TrailingBytes,
    BadTag(u8),
    BadUtf8,
    LengthOutOfRange,
    UnknownVersion(u8),
    MapOrder,
}
impl std::fmt::Display for CanonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "{self:?}") }
}
impl std::error::Error for CanonError {}

#[derive(Default)]
pub struct Enc { buf: Vec<u8> }
impl Enc {
    pub fn new() -> Self { Enc { buf: Vec::new() } }
    pub fn u8(&mut self, v: u8) -> &mut Self { self.buf.push(v); self }
    pub fn u16(&mut self, v: u16) -> &mut Self { self.buf.extend_from_slice(&v.to_le_bytes()); self }
    pub fn u32(&mut self, v: u32) -> &mut Self { self.buf.extend_from_slice(&v.to_le_bytes()); self }
    pub fn u64(&mut self, v: u64) -> &mut Self { self.buf.extend_from_slice(&v.to_le_bytes()); self }
    pub fn bool(&mut self, v: bool) -> &mut Self { self.buf.push(v as u8); self }
    pub fn bytes(&mut self, v: &[u8]) -> &mut Self { self.u64(v.len() as u64); self.buf.extend_from_slice(v); self }
    pub fn str(&mut self, v: &str) -> &mut Self { self.bytes(v.as_bytes()) }
    pub fn fixed<const N: usize>(&mut self, v: &[u8; N]) -> &mut Self { self.buf.extend_from_slice(v); self }
    pub fn opt<T>(&mut self, v: &Option<T>, f: impl FnOnce(&mut Enc, &T)) -> &mut Self {
        match v { None => { self.buf.push(0); } Some(x) => { self.buf.push(1); f(self, x); } }
        self
    }
    pub fn seq<T>(&mut self, items: &[T], mut f: impl FnMut(&mut Enc, &T)) -> &mut Self {
        self.u64(items.len() as u64);
        for i in items { f(self, i); }
        self
    }
    /// Encode map entries sorted by the key's encoded bytes. `entries` may be in any order.
    pub fn map<K, V>(&mut self, entries: &[(K, V)], mut key: impl FnMut(&mut Enc, &K), mut val: impl FnMut(&mut Enc, &V)) -> &mut Self {
        let mut enc: Vec<(Vec<u8>, Vec<u8>)> = entries.iter().map(|(k, v)| {
            let (mut ke, mut ve) = (Enc::new(), Enc::new()); key(&mut ke, k); val(&mut ve, v); (ke.finish(), ve.finish())
        }).collect();
        enc.sort_by(|a, b| a.0.cmp(&b.0));
        self.u64(enc.len() as u64);
        for (k, v) in enc { self.buf.extend_from_slice(&k); self.buf.extend_from_slice(&v); }
        self
    }
    pub fn finish(self) -> Vec<u8> { self.buf }
}

pub struct Dec<'a> { buf: &'a [u8], pos: usize }
impl<'a> Dec<'a> {
    pub fn new(buf: &'a [u8]) -> Self { Dec { buf, pos: 0 } }
    fn take(&mut self, n: usize) -> Result<&'a [u8], CanonError> {
        let end = self.pos.checked_add(n).ok_or(CanonError::LengthOutOfRange)?;
        if end > self.buf.len() { return Err(CanonError::Truncated); }
        let s = &self.buf[self.pos..end]; self.pos = end; Ok(s)
    }
    pub fn u8(&mut self) -> Result<u8, CanonError> { Ok(self.take(1)?[0]) }
    pub fn u16(&mut self) -> Result<u16, CanonError> { Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap())) }
    pub fn u32(&mut self) -> Result<u32, CanonError> { Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap())) }
    pub fn u64(&mut self) -> Result<u64, CanonError> { Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap())) }
    pub fn bool(&mut self) -> Result<bool, CanonError> { match self.u8()? { 0 => Ok(false), 1 => Ok(true), t => Err(CanonError::BadTag(t)) } }
    fn len(&mut self) -> Result<usize, CanonError> {
        let n = self.u64()?;
        // A length can never exceed what remains: rejects absurd lengths before any allocation.
        if n > (self.buf.len() - self.pos) as u64 { return Err(CanonError::LengthOutOfRange); }
        Ok(n as usize)
    }
    pub fn bytes(&mut self) -> Result<&'a [u8], CanonError> { let n = self.len()?; self.take(n) }
    pub fn str(&mut self) -> Result<&'a str, CanonError> { std::str::from_utf8(self.bytes()?).map_err(|_| CanonError::BadUtf8) }
    pub fn fixed<const N: usize>(&mut self) -> Result<[u8; N], CanonError> { Ok(self.take(N)?.try_into().unwrap()) }
    pub fn opt<T>(&mut self, f: impl FnOnce(&mut Dec<'a>) -> Result<T, CanonError>) -> Result<Option<T>, CanonError> {
        match self.u8()? { 0 => Ok(None), 1 => Ok(Some(f(self)?)), t => Err(CanonError::BadTag(t)) }
    }
    pub fn seq<T>(&mut self, mut f: impl FnMut(&mut Dec<'a>) -> Result<T, CanonError>) -> Result<Vec<T>, CanonError> {
        let n = self.u64()?;
        // each element is at least one byte in every schema: bound the count by the remaining input
        if n > (self.buf.len() - self.pos) as u64 { return Err(CanonError::LengthOutOfRange); }
        let mut v = Vec::with_capacity(n as usize);
        for _ in 0..n { v.push(f(self)?); }
        Ok(v)
    }
    /// Decode a map, enforcing strictly ascending encoded-key order (so a duplicate is also rejected).
    pub fn map<K, V>(&mut self, mut key: impl FnMut(&mut Dec<'a>) -> Result<K, CanonError>, mut val: impl FnMut(&mut Dec<'a>) -> Result<V, CanonError>) -> Result<Vec<(K, V)>, CanonError> {
        let n = self.u64()?;
        if n > (self.buf.len() - self.pos) as u64 { return Err(CanonError::LengthOutOfRange); }
        let mut out = Vec::with_capacity(n as usize);
        let mut last: Option<&'a [u8]> = None;
        for _ in 0..n {
            let start = self.pos; let k = key(self)?; let kb = &self.buf[start..self.pos];
            if let Some(l) = last { if kb <= l { return Err(CanonError::MapOrder); } }
            last = Some(kb);
            out.push((k, val(self)?));
        }
        Ok(out)
    }
    pub fn finish(self) -> Result<(), CanonError> { if self.pos == self.buf.len() { Ok(()) } else { Err(CanonError::TrailingBytes) } }
}

/// A value with a pinned canonical encoding. `encode_versioned` writes `VERSION` then the body.
pub trait Canonical: Sized {
    const VERSION: u8;
    fn encode_body(&self, e: &mut Enc);
    fn decode_body(d: &mut Dec<'_>) -> Result<Self, CanonError>;
    fn encode_versioned(&self) -> Vec<u8> { let mut e = Enc::new(); e.u8(Self::VERSION); self.encode_body(&mut e); e.finish() }
    fn decode_versioned(bytes: &[u8]) -> Result<Self, CanonError> {
        let mut d = Dec::new(bytes);
        let v = d.u8()?; if v != Self::VERSION { return Err(CanonError::UnknownVersion(v)); }
        let x = Self::decode_body(&mut d)?; d.finish()?; Ok(x)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    struct Sample { height: u64, name: String, parent: Option<[u8; 4]>, flag: bool, data: Vec<u8>, items: Vec<u16>, map: Vec<(String, u32)> }
    impl Canonical for Sample {
        const VERSION: u8 = 1;
        fn encode_body(&self, e: &mut Enc) {
            e.u64(self.height).str(&self.name).opt(&self.parent, |e, p| { e.fixed(p); }).bool(self.flag).bytes(&self.data)
             .seq(&self.items, |e, i| { e.u16(*i); }).map(&self.map, |e, k| { e.str(k); }, |e, v| { e.u32(*v); });
        }
        fn decode_body(d: &mut Dec<'_>) -> Result<Self, CanonError> {
            Ok(Sample { height: d.u64()?, name: d.str()?.to_string(), parent: d.opt(|d| d.fixed::<4>())?, flag: d.bool()?,
                data: d.bytes()?.to_vec(), items: d.seq(|d| d.u16())?, map: d.map(|d| Ok(d.str()?.to_string()), |d| d.u32())? })
        }
    }
    fn sample() -> Sample {
        Sample { height: 258, name: "qcb1".into(), parent: Some([1, 2, 3, 4]), flag: true, data: vec![9, 8, 7], items: vec![1, 513],
                 map: vec![("b".into(), 2), ("a".into(), 1)] }
    }

    /// Golden bytes: byte-identical on every platform. Changing this vector is a format change.
    const GOLDEN: &str = "01\
        0201000000000000\
        0400000000000000 71636231\
        01 01020304\
        01\
        0300000000000000 090807\
        0200000000000000 0100 0102\
        0200000000000000 0100000000000000 61 01000000 0100000000000000 62 02000000";

    #[test]
    fn golden_bytes_are_pinned() {
        let hex: String = GOLDEN.split_whitespace().collect::<Vec<_>>().concat().replace("\\", "");
        assert_eq!(hex::encode(sample().encode_versioned()), hex);
    }

    #[test]
    fn round_trip() { let s = sample(); assert_eq!(Sample::decode_versioned(&s.encode_versioned()).unwrap(), Sample { map: vec![("a".into(), 1), ("b".into(), 2)], ..s }); }

    #[test]
    fn map_encoding_is_order_independent() {
        let a = sample(); let mut b = sample(); b.map.reverse();
        assert_eq!(a.encode_versioned(), b.encode_versioned());
    }

    #[test]
    fn decoder_is_strict() {
        let good = sample().encode_versioned();
        // every truncation fails
        for cut in 0..good.len() { assert!(Sample::decode_versioned(&good[..cut]).is_err(), "cut {cut}"); }
        // trailing byte
        let mut t = good.clone(); t.push(0); assert_eq!(Sample::decode_versioned(&t), Err(CanonError::TrailingBytes));
        // unknown version
        let mut v = good.clone(); v[0] = 2; assert_eq!(Sample::decode_versioned(&v), Err(CanonError::UnknownVersion(2)));
        // bad bool / option tag
        let mut b = good.clone(); let flag_pos = 1 + 8 + 8 + 4 + 1 + 4; b[flag_pos] = 2; assert_eq!(Sample::decode_versioned(&b), Err(CanonError::BadTag(2)));
        let mut o = good.clone(); o[1 + 8 + 8 + 4] = 7; assert_eq!(Sample::decode_versioned(&o), Err(CanonError::BadTag(7)));
        // absurd length (does not allocate)
        let mut l = good.clone(); l[1 + 8..1 + 16].copy_from_slice(&u64::MAX.to_le_bytes()); assert_eq!(Sample::decode_versioned(&l), Err(CanonError::LengthOutOfRange));
        // bad utf-8
        let mut u = good.clone(); u[1 + 8 + 8] = 0xFF; assert_eq!(Sample::decode_versioned(&u), Err(CanonError::BadUtf8));
        // map out of order / duplicate key
        let mut m = Sample { map: vec![], ..sample() }.encode_versioned();
        let tail = { let mut e = Enc::new(); e.u64(2).str("b").u32(2).str("a").u32(1); e.finish() };
        let n = m.len() - 8; m.truncate(n); m.extend_from_slice(&tail);
        assert_eq!(Sample::decode_versioned(&m), Err(CanonError::MapOrder));
        let dup = { let mut e = Enc::new(); e.u64(2).str("a").u32(1).str("a").u32(2); e.finish() };
        let mut m2 = Sample { map: vec![], ..sample() }.encode_versioned(); let n = m2.len() - 8; m2.truncate(n); m2.extend_from_slice(&dup);
        assert_eq!(Sample::decode_versioned(&m2), Err(CanonError::MapOrder));
    }

    /// Random garbage never panics and never decodes unless it is exactly canonical.
    #[test]
    fn random_bytes_never_panic_and_canonical_form_is_unique() {
        let mut x = 0x9E3779B97F4A7C15u64;
        let mut next = || { x ^= x << 13; x ^= x >> 7; x ^= x << 17; x };
        for _ in 0..20_000 {
            let n = (next() % 64) as usize; let b: Vec<u8> = (0..n).map(|_| next() as u8).collect();
            if let Ok(v) = Sample::decode_versioned(&b) { assert_eq!(v.encode_versioned(), b, "decoded input must re-encode to itself"); }
        }
    }
}
