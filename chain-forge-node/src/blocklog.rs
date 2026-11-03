//! PERSIST-001 P-02b PR 1 — append-only, hash-chained record log (UNWIRED).
//!
//! **Nothing in the node uses this module.** `persist_state`, `load_persisted_state` and every production
//! data directory are untouched; the module exists so the storage layer can be reviewed and crash-tested
//! in isolation (design: `docs/persist-001-p02b-integration-design.md`, owner decisions 2026-11-03).
//! It never opens a directory it did not create or was not explicitly handed.
//!
//! # Record format, version 1 (all integers little-endian; pinned by golden bytes)
//! ```text
//! magic "CFBL"(4) | version(1)=1 | kind(1) | height(8) | payload_len(8) | payload | prev_hash(32) | record_hash(32)
//! record_hash = SHA-256( "CFBL-record-v1\0" || every byte before record_hash )
//! ```
//! * `kind` separates logs (1 = block, 2 = validator-set history); a record of another kind is corruption.
//! * The first record's `prev_hash` is the caller's **anchor**; [`anchor_for`] derives it from the genesis
//!   hash and the kind, so a log written for another chain, genesis or kind never verifies.
//! * `payload` is opaque bytes here (the canonical encoding is [`crate::canon`]; the consensus types'
//!   encoders arrive in PR 2).
//! * The caller supplies the log's `first_height` (explicit, not inferred); the first record must carry it and
//!   heights must be consecutive thereafter. A log that starts elsewhere is corruption.
//! * Segments: `seg-<first_height, 20 digits>.log`, rolled after `seg_records` records.
//!
//! # Commit rule
//! A log may be *ahead of* the committed checkpoint (the manifest's descriptor) by crash timing, never
//! behind it. [`BlockLog::recover`] truncates everything beyond the committed tail and refuses (never
//! repairs) damage at or before it.
//!
//! # Durability
//! `append` writes the record and `fsync`s the segment (`sync_data`) before returning; creating a segment
//! also fsyncs the directory. Power-loss durability is **not** verified by any test here (documented limit).

#![allow(dead_code)]

use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub const MAGIC: [u8; 4] = *b"CFBL";
pub const VERSION: u8 = 1;
pub const KIND_BLOCK: u8 = 1;
pub const KIND_VALIDATOR_SET: u8 = 2;
const HEADER_LEN: usize = 4 + 1 + 1 + 8 + 8;
const TRAILER_LEN: usize = 32 + 32;
const RECORD_DOMAIN: &[u8] = b"CFBL-record-v1\0";
const ANCHOR_DOMAIN: &[u8] = b"CFBL-anchor-v1\0";
/// Sanity bound on one record's payload; a larger length field is corruption.
pub const MAX_PAYLOAD: u64 = 256 * 1024 * 1024;

pub type Hash32 = [u8; 32];

#[derive(Debug)]
pub enum LogError {
    Io(std::io::Error),
    /// Damage at or before the committed tail: never repaired; the node must not start.
    Corrupt { segment: String, offset: u64, detail: String },
    /// The log is shorter than, or does not match, the committed checkpoint.
    MissingCommitted { detail: String },
    /// Heights are not consecutive.
    Gap { expected: u64, got: u64 },
    /// `create` was given a directory that already holds segments.
    AlreadyExists,
}
impl std::fmt::Display for LogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "{self:?}") }
}
impl std::error::Error for LogError {}
impl From<std::io::Error> for LogError { fn from(e: std::io::Error) -> Self { LogError::Io(e) } }

/// The committed checkpoint's view of a log (stored in the generation's descriptor).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tail { pub height: u64, pub hash: Hash32 }

/// Anchor for a log: `SHA-256("CFBL-anchor-v1\0" || kind || genesis_hash_bytes)`.
pub fn anchor_for(genesis_hash: &[u8], kind: u8) -> Hash32 {
    let mut h = Sha256::new();
    h.update(ANCHOR_DOMAIN); h.update([kind]); h.update(genesis_hash);
    h.finalize().into()
}

/// Encode one record. Returns the bytes and the record hash.
pub fn record_bytes(kind: u8, height: u64, payload: &[u8], prev: &Hash32) -> (Vec<u8>, Hash32) {
    let mut v = Vec::with_capacity(HEADER_LEN + payload.len() + TRAILER_LEN);
    v.extend_from_slice(&MAGIC);
    v.push(VERSION);
    v.push(kind);
    v.extend_from_slice(&height.to_le_bytes());
    v.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    v.extend_from_slice(payload);
    v.extend_from_slice(prev);
    let mut h = Sha256::new(); h.update(RECORD_DOMAIN); h.update(&v);
    let h: Hash32 = h.finalize().into();
    v.extend_from_slice(&h);
    (v, h)
}

fn seg_name(first_height: u64) -> String { format!("seg-{first_height:020}.log") }
fn fsync_dir(dir: &Path) -> std::io::Result<()> { crate::persistence::fsync_dir(dir) }

struct Rec { end_off: u64, tail: Tail }
struct Scan { recs: Vec<Rec>, damage: Option<(u64, String)> }

/// Validate records in `bytes`, stopping at the first invalid or short record.
fn scan_bytes(bytes: &[u8], kind: u8, mut prev: Hash32, mut expect: u64, mut on_record: impl FnMut(u64, &[u8])) -> Scan {
    let (mut off, mut recs) = (0usize, vec![]);
    loop {
        if off == bytes.len() { return Scan { recs, damage: None }; }
        let rest = &bytes[off..];
        macro_rules! bad { ($why:expr) => { return Scan { recs, damage: Some((off as u64, $why.to_string())) } }; }
        if rest.len() < HEADER_LEN { bad!("short header"); }
        if rest[0..4] != MAGIC { bad!("bad magic"); }
        if rest[4] != VERSION { bad!("unsupported version"); }
        if rest[5] != kind { bad!("record kind does not match the log"); }
        let height = u64::from_le_bytes(rest[6..14].try_into().unwrap());
        let len = u64::from_le_bytes(rest[14..22].try_into().unwrap());
        if len > MAX_PAYLOAD { bad!("payload length out of bounds"); }
        let total = HEADER_LEN as u64 + len + TRAILER_LEN as u64;
        if (rest.len() as u64) < total { bad!("short record"); }
        let total = total as usize;
        let body_end = HEADER_LEN + len as usize;
        if rest[body_end..body_end + 32] != prev { bad!("prev_hash mismatch"); }
        let mut hh = Sha256::new(); hh.update(RECORD_DOMAIN); hh.update(&rest[..body_end + 32]);
        let h: Hash32 = hh.finalize().into();
        if rest[body_end + 32..total] != h { bad!("record_hash mismatch"); }
        if height != expect { bad!("height not consecutive"); }
        on_record(height, &rest[HEADER_LEN..body_end]);
        prev = h; expect = height + 1; off += total;
        recs.push(Rec { end_off: off as u64, tail: Tail { height, hash: h } });
    }
}

/// Segment files sorted by first height.
fn segments(dir: &Path) -> std::io::Result<Vec<(u64, PathBuf)>> {
    let mut v = vec![];
    if !dir.exists() { return Ok(v); }
    for e in std::fs::read_dir(dir)? {
        let e = e?; let n = e.file_name().to_string_lossy().to_string();
        if let Some(num) = n.strip_prefix("seg-").and_then(|s| s.strip_suffix(".log")) {
            if let Ok(h) = num.parse::<u64>() { v.push((h, e.path())); }
        }
    }
    v.sort();
    Ok(v)
}

pub struct BlockLog {
    dir: PathBuf,
    kind: u8,
    first_height: u64,
    seg_records: u64,
    tail: Option<Tail>,
    anchor: Hash32,
    cur: Option<(std::fs::File, u64)>, // open segment, records in it
}

impl BlockLog {
    pub fn tail(&self) -> Option<&Tail> { self.tail.as_ref() }
    pub fn kind(&self) -> u8 { self.kind }

    /// Create an empty log in a new or empty directory (refuses a directory that already holds segments).
    pub fn create(dir: &Path, kind: u8, anchor: Hash32, first_height: u64, seg_records: u64) -> Result<Self, LogError> {
        std::fs::create_dir_all(dir)?;
        if !segments(dir)?.is_empty() { return Err(LogError::AlreadyExists); }
        Ok(BlockLog { dir: dir.to_path_buf(), kind, first_height, seg_records: seg_records.max(1), tail: None, anchor, cur: None })
    }

    /// Open an existing log for appending, recovering against the committed checkpoint `committed`.
    ///
    /// * `committed = None`: nothing is committed; every segment is removed.
    /// * The committed tail must be present with the exact hash, every record before it valid; otherwise
    ///   `Err` (fatal, never repaired).
    /// * Valid records beyond the committed tail, a torn record beyond it, trailing garbage beyond it, or an
    ///   empty or damaged later segment are truncated or removed; the log is reopened exactly at the tail.
    /// * Idempotent: recovering twice gives the same result.
    pub fn recover(dir: &Path, kind: u8, anchor: Hash32, first_height: u64, seg_records: u64, committed: Option<Tail>) -> Result<Self, LogError> {
        let segs = segments(dir)?;
        let seg_records = seg_records.max(1);
        let Some(c) = committed else {
            for (_, p) in &segs { std::fs::remove_file(p)?; }
            if dir.exists() { fsync_dir(dir)?; }
            return Ok(BlockLog { dir: dir.to_path_buf(), kind, first_height, seg_records, tail: None, anchor, cur: None });
        };
        // (segment index, offset after the record, tail) for every valid record, in order.
        let mut index: Vec<(usize, u64, Tail)> = vec![];
        let mut damage: Option<(usize, u64, String)> = None;
        let (mut prev, mut expect) = (anchor, first_height);
        for (i, (first, path)) in segs.iter().enumerate() {
            if *first != expect { damage = Some((i, 0, format!("segment starts at {first}, expected {expect}"))); break; }
            let mut bytes = vec![]; std::fs::File::open(path)?.read_to_end(&mut bytes)?;
            let s = scan_bytes(&bytes, kind, prev, expect, |_, _| {});
            for r in &s.recs { index.push((i, r.end_off, r.tail.clone())); }
            if let Some(r) = s.recs.last() { prev = r.tail.hash; expect = r.tail.height + 1; }
            if let Some((o, why)) = s.damage { damage = Some((i, o, why)); break; }
        }
        let Some(pos) = index.iter().position(|(_, _, t)| t.height == c.height) else {
            return Err(match damage {
                Some((i, o, why)) => LogError::Corrupt { segment: seg_name(segs[i].0), offset: o, detail: format!("{why} (committed tail {} not reached)", c.height) },
                None => LogError::MissingCommitted { detail: format!("committed tail {} not present in log", c.height) },
            });
        };
        if index[pos].2.hash != c.hash {
            return Err(LogError::MissingCommitted { detail: format!("committed tail hash mismatch at height {}", c.height) });
        }
        // Truncate to the committed tail: cut its segment, delete every later segment.
        let (seg_i, end_off, _) = index[pos].clone();
        for (j, (_, path)) in segs.iter().enumerate() { if j > seg_i { std::fs::remove_file(path)?; } }
        let path = &segs[seg_i].1;
        let f = std::fs::OpenOptions::new().write(true).open(path)?;
        if f.metadata()?.len() != end_off { f.set_len(end_off)?; }
        f.sync_all()?;
        fsync_dir(dir)?;
        let count = index[..=pos].iter().filter(|(si, _, _)| *si == seg_i).count() as u64;
        let file = std::fs::OpenOptions::new().append(true).open(path)?;
        Ok(BlockLog { dir: dir.to_path_buf(), kind, first_height, seg_records, tail: Some(c), anchor, cur: Some((file, count)) })
    }

    /// Append one record and make it durable (`sync_data`; directory fsync when a segment is created).
    /// Heights must be consecutive. A failed append leaves the in-memory tail unchanged, and the
    /// caller must treat any error as fatal (the on-disk tail is then resolved by `recover`).
    pub fn append(&mut self, height: u64, payload: &[u8]) -> Result<Tail, LogError> {
        if payload.len() as u64 > MAX_PAYLOAD { return Err(LogError::Corrupt { segment: String::new(), offset: 0, detail: "payload exceeds MAX_PAYLOAD".into() }); }
        let expected = self.tail.as_ref().map(|t| t.height + 1).unwrap_or(self.first_height);
        if height != expected { return Err(LogError::Gap { expected, got: height }); }
        let prev = self.tail.as_ref().map(|t| t.hash).unwrap_or(self.anchor);
        let (bytes, h) = record_bytes(self.kind, height, payload, &prev);
        let roll = match &self.cur { Some((_, n)) => *n >= self.seg_records, None => true };
        if roll {
            let path = self.dir.join(seg_name(height));
            let f = std::fs::OpenOptions::new().create_new(true).append(true).open(&path)?;
            self.cur = Some((f, 0));
            fsync_dir(&self.dir)?;
        }
        let (f, n) = self.cur.as_mut().unwrap();
        f.write_all(&bytes)?;
        f.sync_data()?;
        *n += 1;
        let t = Tail { height, hash: h };
        self.tail = Some(t.clone());
        Ok(t)
    }

    /// Read and verify the whole log from the anchor, calling `f(height, payload)` in order. Any damage is an
    /// error. Used for replay and full verification.
    pub fn replay(dir: &Path, kind: u8, anchor: Hash32, first_height: u64, mut f: impl FnMut(u64, &[u8])) -> Result<Option<Tail>, LogError> {
        let (mut prev, mut expect, mut tail) = (anchor, first_height, None);
        for (first, path) in segments(dir)? {
            if first != expect { return Err(LogError::Corrupt { segment: seg_name(first), offset: 0, detail: format!("segment starts at {first}, expected {expect}") }); }
            let mut bytes = vec![]; std::fs::File::open(&path)?.read_to_end(&mut bytes)?;
            let s = scan_bytes(&bytes, kind, prev, expect, &mut f);
            if let Some((off, why)) = s.damage { return Err(LogError::Corrupt { segment: seg_name(first), offset: off, detail: why }); }
            if let Some(r) = s.recs.last() { prev = r.tail.hash; expect = r.tail.height + 1; tail = Some(r.tail.clone()); }
        }
        Ok(tail)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const K: u8 = KIND_BLOCK;
    fn anchor() -> Hash32 { anchor_for(b"golden-genesis", K) }
    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("cf-blocklog-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d); d
    }
    fn payload(h: u64) -> Vec<u8> { format!("block-{h}-{}", "x".repeat((h % 17) as usize * 3)).into_bytes() }
    fn fill(dir: &Path, n: u64, seg: u64) -> Vec<Tail> {
        let mut l = BlockLog::create(dir, K, anchor(), 0, seg).unwrap();
        (0..n).map(|h| l.append(h, &payload(h)).unwrap()).collect()
    }
    fn rec_len(h: u64) -> usize { HEADER_LEN + payload(h).len() + TRAILER_LEN }
    fn first_seg(dir: &Path) -> PathBuf { segments(dir).unwrap()[0].1.clone() }
    fn rec(dir: &Path, committed: Option<Tail>, seg: u64) -> Result<BlockLog, LogError> { BlockLog::recover(dir, K, anchor(), 0, seg, committed) }

    // ── golden vectors: byte-identical on every platform; changing them is a format change ──
    #[test]
    fn golden_anchor_record_and_chain_are_pinned() {
        assert_eq!(hex::encode(anchor()), "489089a54054392056d7bd42e5e834f068a9e870a97afa6cbc0f780186ebe3ef");
        assert_eq!(hex::encode(anchor_for(b"golden-genesis", KIND_VALIDATOR_SET)), "c614e19cb8b59d0b55dc30d5952c809065dc475d56cd34ec9754b289ac763e57");
        let (b, h) = record_bytes(K, 7, b"abc", &anchor());
        assert_eq!(hex::encode(&b), "4346424c010107000000000000000300000000000000616263489089a54054392056d7bd42e5e834f068a9e870a97afa6cbc0f780186ebe3ef4e1d6524f5c326e51370489d2d45b617cf38db4c37056ff617267e6a6a79424f");
        assert_eq!(hex::encode(h), "4e1d6524f5c326e51370489d2d45b617cf38db4c37056ff617267e6a6a79424f");
        // a three-record chain (empty, 5 bytes, 10 bytes): pinned tail hash
        let mut prev = anchor();
        for (h, p) in [(0u64, vec![]), (1, vec![b'x'; 5]), (2, (0u8..10).collect())] { prev = record_bytes(K, h, &p, &prev).1; }
        assert_eq!(hex::encode(prev), "4b0fd02007f005ad54b06666c64d037237af2278b3f6995dd6d6550ccc7b0520");
    }

    #[test]
    fn a_log_written_to_disk_has_exactly_the_golden_bytes_and_tail() {
        let d = tmp("goldfile"); let mut l = BlockLog::create(&d, K, anchor(), 0, 100).unwrap();
        l.append(0, b"").unwrap(); l.append(1, &[b'x'; 5]).unwrap(); let t = l.append(2, &(0u8..10).collect::<Vec<_>>()).unwrap();
        assert_eq!(hex::encode(t.hash), "4b0fd02007f005ad54b06666c64d037237af2278b3f6995dd6d6550ccc7b0520");
        assert_eq!(std::fs::read(first_seg(&d)).unwrap().len(), (HEADER_LEN + TRAILER_LEN) * 3 + 15);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn record_hash_is_domain_separated_and_covers_every_header_field() {
        let (a, _) = record_bytes(K, 1, b"p", &anchor());
        for (name, other) in [("kind", record_bytes(KIND_VALIDATOR_SET, 1, b"p", &anchor()).0), ("height", record_bytes(K, 2, b"p", &anchor()).0),
                              ("payload", record_bytes(K, 1, b"q", &anchor()).0), ("prev", record_bytes(K, 1, b"p", &[1; 32]).0)] {
            assert_ne!(a[a.len() - 32..], other[other.len() - 32..], "{name} must change the record hash");
        }
        // the hash is NOT a bare SHA-256 of the body (domain tag)
        let body = &a[..a.len() - 32];
        assert_ne!(a[a.len() - 32..], Sha256::digest(body).as_slice()[..]);
    }

    // ── basic behaviour ──
    #[test]
    fn append_replay_roundtrip_across_segments() {
        let d = tmp("rt"); let tails = fill(&d, 25, 4);
        assert_eq!(segments(&d).unwrap().len(), 7);
        let mut seen = vec![];
        let t = BlockLog::replay(&d, K, anchor(), 0, |h, p| { assert_eq!(p, payload(h).as_slice()); seen.push(h); }).unwrap().unwrap();
        assert_eq!(t, *tails.last().unwrap());
        assert_eq!(seen, (0..25).collect::<Vec<_>>());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn same_inputs_give_identical_bytes() {
        let (a, b) = (tmp("det-a"), tmp("det-b")); fill(&a, 10, 3); fill(&b, 10, 3);
        let read = |d: &Path| segments(d).unwrap().into_iter().map(|(_, p)| std::fs::read(p).unwrap()).collect::<Vec<_>>();
        assert_eq!(read(&a), read(&b));
        let _ = std::fs::remove_dir_all(&a); let _ = std::fs::remove_dir_all(&b);
    }

    #[test]
    fn append_rejects_a_height_gap_and_leaves_the_tail_unchanged() {
        let d = tmp("gap"); let mut l = BlockLog::create(&d, K, anchor(), 0, 4).unwrap();
        let t0 = l.append(0, b"a").unwrap();
        assert!(matches!(l.append(2, b"c"), Err(LogError::Gap { expected: 1, got: 2 })));
        assert_eq!(l.tail(), Some(&t0));
        l.append(1, b"b").unwrap();
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn create_refuses_a_directory_that_already_holds_a_log() {
        let d = tmp("refuse"); fill(&d, 2, 4);
        assert!(matches!(BlockLog::create(&d, K, anchor(), 0, 4), Err(LogError::AlreadyExists)));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn wrong_anchor_or_wrong_kind_is_rejected() {
        let d = tmp("anchor"); let tails = fill(&d, 3, 4);
        assert!(BlockLog::recover(&d, K, [9u8; 32], 0, 4, Some(tails[2].clone())).is_err());
        assert!(BlockLog::recover(&d, KIND_VALIDATOR_SET, anchor(), 0, 4, Some(tails[2].clone())).is_err());
        assert!(BlockLog::replay(&d, KIND_VALIDATOR_SET, anchor_for(b"golden-genesis", KIND_VALIDATOR_SET), 0, |_, _| {}).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    // ── crash recovery ──
    /// Log AHEAD of the checkpoint by one record, cut at every byte offset: always back to the tail, usable afterwards.
    #[test]
    fn torn_last_record_beyond_the_committed_tail_is_truncated_at_every_offset() {
        let d = tmp("torn"); let tails = fill(&d, 6, 100);
        let committed = tails[4].clone();
        let seg = first_seg(&d); let full = std::fs::read(&seg).unwrap();
        let end4 = full.len() - rec_len(5);
        for cut in end4..=full.len() {
            std::fs::write(&seg, &full[..cut]).unwrap();
            let mut l = rec(&d, Some(committed.clone()), 100).unwrap();
            assert_eq!(l.tail(), Some(&committed), "cut at {cut}");
            assert_eq!(std::fs::metadata(&seg).unwrap().len() as usize, end4);
            l.append(5, &payload(5)).unwrap();
            BlockLog::replay(&d, K, anchor(), 0, |_, _| {}).unwrap();
            std::fs::write(&seg, &full).unwrap();
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn torn_record_inside_the_committed_region_is_fatal() {
        let d = tmp("torn-in"); let tails = fill(&d, 6, 100);
        let seg = first_seg(&d); let full = std::fs::read(&seg).unwrap();
        for cut in [full.len() - 1, full.len() - 40, full.len() - HEADER_LEN - 3, full.len() - rec_len(5) - 1] {
            std::fs::write(&seg, &full[..cut]).unwrap();
            assert!(rec(&d, Some(tails[5].clone()), 100).is_err(), "cut {cut}");
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Flip one bit at EVERY byte of a committed record: fatal for recovery and for replay.
    #[test]
    fn a_flipped_bit_anywhere_in_a_committed_record_is_fatal() {
        let d = tmp("corrupt"); let tails = fill(&d, 6, 100);
        let seg = first_seg(&d); let orig = std::fs::read(&seg).unwrap();
        let start: usize = (0..3).map(rec_len).sum(); let len = rec_len(3);
        for off in 0..len {
            let mut b = orig.clone(); b[start + off] ^= 0x01; std::fs::write(&seg, &b).unwrap();
            assert!(rec(&d, Some(tails[5].clone()), 100).is_err(), "recover: flip at +{off}");
            assert!(BlockLog::replay(&d, K, anchor(), 0, |_, _| {}).is_err(), "replay: flip at +{off}");
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn log_ahead_of_checkpoint_is_truncated_including_later_segments() {
        let d = tmp("ahead"); let tails = fill(&d, 14, 4);
        let committed = tails[5].clone();
        let mut l = rec(&d, Some(committed.clone()), 4).unwrap();
        assert_eq!(l.tail(), Some(&committed));
        assert_eq!(segments(&d).unwrap().len(), 2);
        assert_eq!(l.append(6, &payload(6)).unwrap().height, 6);
        let mut n = 0; BlockLog::replay(&d, K, anchor(), 0, |_, _| n += 1).unwrap(); assert_eq!(n, 7);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn empty_or_garbage_segment_created_by_a_crash_in_roll_is_removed() {
        for garbage in [&b""[..], b"CFB", &[0xFFu8; 40][..]] {
            let d = tmp("roll"); let tails = fill(&d, 4, 4);
            std::fs::write(d.join(seg_name(4)), garbage).unwrap();
            let mut l = rec(&d, Some(tails[3].clone()), 4).unwrap();
            assert_eq!(segments(&d).unwrap().len(), 1);
            l.append(4, &payload(4)).unwrap();
            let _ = std::fs::remove_dir_all(&d);
        }
    }

    #[test]
    fn missing_or_mismatched_committed_tail_is_fatal() {
        let d = tmp("missing"); let tails = fill(&d, 8, 4);
        assert!(matches!(rec(&d, Some(Tail { height: 9, hash: [1; 32] }), 4), Err(LogError::MissingCommitted { .. })));
        assert!(matches!(rec(&d, Some(Tail { height: 7, hash: [1; 32] }), 4), Err(LogError::MissingCommitted { .. })));
        std::fs::remove_file(d.join(seg_name(4))).unwrap(); // the LAST segment deleted
        assert!(rec(&d, Some(tails[7].clone()), 4).is_err());
        assert!(BlockLog::replay(&d, K, anchor(), 0, |_, _| {}).is_ok(), "replay alone cannot see a missing tail segment; the checkpoint does");
        let _ = std::fs::remove_dir_all(&d);
        let d = tmp("missing-mid"); let tails = fill(&d, 12, 4);
        std::fs::remove_file(d.join(seg_name(4))).unwrap(); // a MIDDLE segment deleted
        assert!(rec(&d, Some(tails[11].clone()), 4).is_err());
        assert!(BlockLog::replay(&d, K, anchor(), 0, |_, _| {}).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn nothing_committed_removes_everything() {
        let d = tmp("none"); fill(&d, 6, 4);
        let l = rec(&d, None, 4).unwrap();
        assert!(l.tail().is_none() && segments(&d).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn recovery_is_idempotent_and_the_chain_continues_verifiably() {
        let d = tmp("idem"); let tails = fill(&d, 10, 4);
        let c = tails[6].clone();
        drop(rec(&d, Some(c.clone()), 4).unwrap());
        let bytes1: Vec<_> = segments(&d).unwrap().into_iter().map(|(_, p)| std::fs::read(p).unwrap()).collect();
        let mut l = rec(&d, Some(c.clone()), 4).unwrap();
        let bytes2: Vec<_> = segments(&d).unwrap().into_iter().map(|(_, p)| std::fs::read(p).unwrap()).collect();
        assert_eq!(bytes1, bytes2);
        for h in 7..12 { l.append(h, &payload(h)).unwrap(); }
        let t = BlockLog::replay(&d, K, anchor(), 0, |_, _| {}).unwrap().unwrap();
        assert_eq!(t.height, 11);
        // and it equals a log written in one go
        let d2 = tmp("idem2"); let t2 = fill(&d2, 12, 4);
        assert_eq!(t, *t2.last().unwrap());
        let _ = std::fs::remove_dir_all(&d); let _ = std::fs::remove_dir_all(&d2);
    }

    /// A record whose hashes are all VALID but whose height skips, repeats, or starts elsewhere is corruption: the
    /// height rule, not the hash chain, is what catches a well-formed log with a missing block.
    #[test]
    fn valid_hash_chain_with_a_skipped_repeated_or_misplaced_height_is_fatal() {
        for bad_heights in [[0u64, 1, 3], [0, 1, 1], [1, 2, 3]] {
            let d = tmp("height"); std::fs::create_dir_all(&d).unwrap();
            let mut bytes = vec![]; let mut prev = anchor(); let mut tails = vec![];
            for h in bad_heights { let (b, hh) = record_bytes(K, h, b"p", &prev); bytes.extend_from_slice(&b); prev = hh; tails.push(Tail { height: h, hash: hh }); }
            std::fs::write(d.join(seg_name(bad_heights[0])), &bytes).unwrap();
            assert!(BlockLog::replay(&d, K, anchor(), 0, |_, _| {}).is_err(), "replay must reject heights {bad_heights:?}");
            assert!(rec(&d, Some(tails[2].clone()), 100).is_err(), "recover must reject heights {bad_heights:?}");
            let _ = std::fs::remove_dir_all(&d);
        }
    }

    #[test]
    fn first_height_is_explicit_and_enforced() {
        let d = tmp("first"); let mut l = BlockLog::create(&d, K, anchor(), 5, 4).unwrap();
        assert!(matches!(l.append(0, b"x"), Err(LogError::Gap { expected: 5, got: 0 })));
        let t = l.append(5, b"x").unwrap(); l.append(6, b"y").unwrap();
        assert!(BlockLog::replay(&d, K, anchor(), 5, |_, _| {}).is_ok());
        assert!(BlockLog::replay(&d, K, anchor(), 0, |_, _| {}).is_err());
        assert!(BlockLog::recover(&d, K, anchor(), 0, 4, Some(t.clone())).is_err());
        assert!(BlockLog::recover(&d, K, anchor(), 5, 4, Some(t)).is_ok());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A record with a valid self-hash spliced in from another position (wrong prev) is fatal.
    #[test]
    fn a_spliced_record_with_the_wrong_prev_hash_is_fatal() {
        let d = tmp("splice"); std::fs::create_dir_all(&d).unwrap();
        let mut bytes = vec![]; let (mut prev, mut hashes) = (anchor(), vec![]);
        for h in 0..2u64 { let (b, hh) = record_bytes(K, h, b"p", &prev); bytes.extend_from_slice(&b); prev = hh; hashes.push(hh); }
        let (b, hh) = record_bytes(K, 2, b"p", &hashes[0]); // links to record 0, skipping record 1
        bytes.extend_from_slice(&b);
        std::fs::write(d.join(seg_name(0)), &bytes).unwrap();
        assert!(BlockLog::replay(&d, K, anchor(), 0, |_, _| {}).is_err());
        assert!(rec(&d, Some(Tail { height: 2, hash: hh }), 100).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Model-based random crash test: random segment sizes, random committed tail, random damage applied BEYOND the
    /// tail (must recover exactly to it) or INSIDE it (must be fatal). Deterministic PRNG, 300 cases.
    #[test]
    fn randomised_crash_model() {
        let mut x = 0xD1B54A32D192ED03u64;
        let mut next = move || { x ^= x << 13; x ^= x >> 7; x ^= x << 17; x };
        for case in 0..300u64 {
            let d = tmp(&format!("rand{}", case % 4));
            let seg = 1 + next() % 6; let n = 3 + next() % 20;
            let tails = fill(&d, n, seg);
            let ci = (next() % n) as usize; let committed = tails[ci].clone();
            let segs = segments(&d).unwrap();
            let (inside, victim_hint) = (next() % 2 == 0, next());
            // find the record byte range of height ci and of the last record
            let mut ranges = vec![]; // (seg path, start, end, height)
            for (_, p) in &segs { let b = std::fs::read(p).unwrap(); let mut off = 0usize;
                while off < b.len() { let len = u64::from_le_bytes(b[off + 14..off + 22].try_into().unwrap()) as usize; let t = HEADER_LEN + len + TRAILER_LEN;
                    let h = u64::from_le_bytes(b[off + 6..off + 14].try_into().unwrap()); ranges.push((p.clone(), off, off + t, h)); off += t; } }
            if inside {
                let cands: Vec<_> = ranges.iter().filter(|r| r.3 <= committed.height).collect();
                let r = cands[(victim_hint as usize) % cands.len()];
                let mut b = std::fs::read(&r.0).unwrap(); let pos = r.1 + (next() as usize) % (r.2 - r.1); b[pos] ^= 1 << (next() % 8);
                std::fs::write(&r.0, &b).unwrap();
                assert!(rec(&d, Some(committed.clone()), seg).is_err(), "case {case}: damage inside the committed region must be fatal");
            } else {
                let cands: Vec<_> = ranges.iter().filter(|r| r.3 > committed.height).collect();
                if cands.is_empty() { let l = rec(&d, Some(committed.clone()), seg).unwrap(); assert_eq!(l.tail(), Some(&committed)); continue; }
                let r = cands[(victim_hint as usize) % cands.len()];
                let mut b = std::fs::read(&r.0).unwrap();
                match next() % 3 { 0 => { let cut = r.1 + (next() as usize) % (r.2 - r.1); b.truncate(cut); }
                                   1 => { let pos = r.1 + (next() as usize) % (r.2 - r.1); b[pos] ^= 1 << (next() % 8); }
                                   _ => { b.extend_from_slice(&[0xAB; 7]); } }
                std::fs::write(&r.0, &b).unwrap();
                let mut l = rec(&d, Some(committed.clone()), seg).unwrap_or_else(|e| panic!("case {case}: damage beyond the tail must recover: {e}"));
                assert_eq!(l.tail(), Some(&committed), "case {case}");
                l.append(committed.height + 1, &payload(committed.height + 1)).unwrap();
                let t = BlockLog::replay(&d, K, anchor(), 0, |_, _| {}).unwrap().unwrap();
                assert_eq!(t.height, committed.height + 1, "case {case}");
            }
            let _ = std::fs::remove_dir_all(&d);
        }
    }
}
