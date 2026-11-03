//! PERSIST-001 P-02b — EXPERIMENTAL append-only block log (prototype).
//!
//! **Not wired into the node.** Nothing in `persist_state`, `load_persisted_state` or any
//! production data directory uses this module; it exists to benchmark and crash-test the
//! Option 2 design in `docs/persist-001-p02b-design.md` §4a. It must not open a production
//! data directory: callers give it its own directory.
//!
//! Record format (all integers little-endian):
//! `magic(4) "CFBL" | version(1) | height(8) | payload_len(8) | payload | prev_hash(32) | record_hash(32)`
//! with `record_hash = SHA-256(magic | version | height | payload_len | payload | prev_hash)`.
//! The first record's `prev_hash` is the caller-supplied anchor (the genesis hash in the design).
//!
//! Segments: `seg-<first_height as 20 digits>.log`, rolled after `seg_records` records.
//!
//! Commit rule: the log is only ever *ahead of or equal to* the committed checkpoint (the
//! generation manifest's descriptor). [`BlockLog::recover`] truncates anything beyond the
//! committed tail and refuses (never repairs) damage inside it.

use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub const MAGIC: [u8; 4] = *b"CFBL";
pub const VERSION: u8 = 1;
const HEADER_LEN: usize = 4 + 1 + 8 + 8;
const TRAILER_LEN: usize = 32 + 32;
/// Sanity bound on one record's payload (a block); larger length fields are corruption.
pub const MAX_PAYLOAD: u64 = 256 * 1024 * 1024;

pub type Hash32 = [u8; 32];

#[derive(Debug)]
pub enum LogError {
    Io(std::io::Error),
    /// Damage inside the committed region: never repaired, node must not start.
    Corrupt { segment: String, offset: u64, detail: String },
    /// The log is shorter than, or does not match, the committed checkpoint.
    MissingCommitted { detail: String },
    /// Heights are not consecutive.
    Gap { expected: u64, got: u64 },
}
impl std::fmt::Display for LogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "{self:?}") }
}
impl std::error::Error for LogError {}
impl From<std::io::Error> for LogError { fn from(e: std::io::Error) -> Self { LogError::Io(e) } }

/// The committed checkpoint's view of the log (stored in the generation, e.g. as a descriptor).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tail { pub height: u64, pub hash: Hash32 }

pub fn record_bytes(height: u64, payload: &[u8], prev: &Hash32) -> (Vec<u8>, Hash32) {
    let mut v = Vec::with_capacity(HEADER_LEN + payload.len() + TRAILER_LEN);
    v.extend_from_slice(&MAGIC);
    v.push(VERSION);
    v.extend_from_slice(&height.to_le_bytes());
    v.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    v.extend_from_slice(payload);
    v.extend_from_slice(prev);
    let h: Hash32 = Sha256::digest(&v).into();
    v.extend_from_slice(&h);
    (v, h)
}

fn seg_name(first_height: u64) -> String { format!("seg-{first_height:020}.log") }

fn fsync_dir(dir: &Path) -> std::io::Result<()> { crate::persistence::fsync_dir(dir) }

/// Outcome of scanning one segment file.
struct Scan { records: u64, good_len: u64, tail: Option<Tail>, damage: Option<(u64, String)> }

/// Validate records in `bytes` starting from `prev`/`expect_height`. Stops at the first invalid or short record.
fn scan_bytes(bytes: &[u8], mut prev: Hash32, mut expect: Option<u64>,
              mut on_record: impl FnMut(u64, &[u8])) -> Scan {
    let mut off = 0usize;
    let mut records = 0u64;
    let mut tail = None;
    loop {
        if off == bytes.len() { return Scan { records, good_len: off as u64, tail, damage: None }; }
        let rest = &bytes[off..];
        let torn = |why: &str| Scan { records, good_len: off as u64, tail: tail.clone(), damage: Some((off as u64, why.to_string())) };
        if rest.len() < HEADER_LEN { return torn("short header"); }
        if rest[0..4] != MAGIC { return torn("bad magic"); }
        if rest[4] != VERSION { return torn("unsupported version"); }
        let height = u64::from_le_bytes(rest[5..13].try_into().unwrap());
        let len = u64::from_le_bytes(rest[13..21].try_into().unwrap());
        if len > MAX_PAYLOAD { return torn("payload length out of bounds"); }
        let total = HEADER_LEN as u64 + len + TRAILER_LEN as u64;
        if (rest.len() as u64) < total { return torn("short record"); }
        let total = total as usize;
        let body_end = HEADER_LEN + len as usize;
        if rest[body_end..body_end + 32] != prev { return torn("prev_hash mismatch"); }
        let h: Hash32 = Sha256::digest(&rest[..body_end + 32]).into();
        if rest[body_end + 32..total] != h { return torn("record_hash mismatch"); }
        if let Some(e) = expect { if height != e { return torn("height not consecutive"); } }
        on_record(height, &rest[HEADER_LEN..body_end]);
        prev = h; expect = Some(height + 1); tail = Some(Tail { height, hash: h });
        records += 1; off += total;
    }
}

/// List segment files sorted by first height.
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
    seg_records: u64,
    tail: Option<Tail>,
    anchor: Hash32,
    cur: Option<(std::fs::File, u64)>, // open segment, records in it
}

impl BlockLog {
    pub fn tail(&self) -> Option<&Tail> { self.tail.as_ref() }

    /// Create an empty log in a NEW or empty directory (refuses a directory that already holds segments).
    pub fn create(dir: &Path, anchor: Hash32, seg_records: u64) -> Result<Self, LogError> {
        std::fs::create_dir_all(dir)?;
        if !segments(dir)?.is_empty() {
            return Err(LogError::MissingCommitted { detail: "directory already holds log segments".into() });
        }
        Ok(BlockLog { dir: dir.to_path_buf(), seg_records: seg_records.max(1), tail: None, anchor, cur: None })
    }

    /// Open an existing log for appending, recovering against the committed checkpoint `committed`.
    ///
    /// * `committed = None`: nothing is committed; every segment is removed.
    /// * The committed tail must be present with the exact hash, with every record before it valid;
    ///   otherwise `Err` (fatal, never repaired).
    /// * Valid records beyond the committed tail, a torn record beyond it, or trailing garbage beyond it
    ///   are truncated, and the log is reopened exactly at the committed tail.
    pub fn recover(dir: &Path, anchor: Hash32, seg_records: u64, committed: Option<Tail>) -> Result<Self, LogError> {
        let segs = segments(dir)?;
        let seg_records = seg_records.max(1);
        let Some(c) = committed else {
            for (_, p) in &segs { std::fs::remove_file(p)?; }
            if dir.exists() { fsync_dir(dir)?; }
            return Ok(BlockLog { dir: dir.to_path_buf(), seg_records, tail: None, anchor, cur: None });
        };
        // (segment index, byte offset after the record, tail) for every valid record, in order.
        let mut index: Vec<(usize, u64, Tail)> = vec![];
        let mut damage: Option<(usize, u64, String)> = None;
        let (mut prev, mut expect) = (anchor, None::<u64>);
        for (i, (first, path)) in segs.iter().enumerate() {
            if let Some(e) = expect { if *first != e { damage = Some((i, 0, format!("segment starts at {first}, expected {e}"))); break; } }
            let mut bytes = vec![]; std::fs::File::open(path)?.read_to_end(&mut bytes)?;
            let mut off_acc = 0u64;
            let s = scan_bytes(&bytes, prev, Some(expect.unwrap_or(*first)), |_, p| { off_acc += (HEADER_LEN + p.len() + TRAILER_LEN) as u64; index.push((i, off_acc, Tail { height: 0, hash: [0; 32] })); });
            // fill in tails (scan_bytes callback has no hash): recompute by walking offsets
            let mut off = 0usize; let n = s.records as usize; let base = index.len() - n;
            for k in 0..n {
                let len = u64::from_le_bytes(bytes[off + 13..off + 21].try_into().unwrap()) as usize;
                let total = HEADER_LEN + len + TRAILER_LEN;
                index[base + k].2 = Tail { height: u64::from_le_bytes(bytes[off + 5..off + 13].try_into().unwrap()),
                                            hash: bytes[off + total - 32..off + total].try_into().unwrap() };
                off += total;
            }
            if let Some(t) = &s.tail { prev = t.hash; expect = Some(t.height + 1); }
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
        // Truncate to the committed tail: cut its segment, delete later segments.
        let (seg_i, end_off, _) = index[pos].clone();
        for (j, (_, path)) in segs.iter().enumerate() {
            if j > seg_i { std::fs::remove_file(path)?; }
        }
        let path = &segs[seg_i].1;
        let f = std::fs::OpenOptions::new().write(true).open(path)?;
        if f.metadata()?.len() != end_off { f.set_len(end_off)?; }
        f.sync_all()?;
        fsync_dir(dir)?;
        let count = index[..=pos].iter().filter(|(si, _, _)| *si == seg_i).count() as u64;
        let file = std::fs::OpenOptions::new().append(true).open(path)?;
        Ok(BlockLog { dir: dir.to_path_buf(), seg_records, tail: Some(c), anchor, cur: Some((file, count)) })
    }

    /// Append one record and make it durable (file fsync; directory fsync when a segment is created).
    /// Heights must be consecutive. Returns the new tail.
    pub fn append(&mut self, height: u64, payload: &[u8]) -> Result<Tail, LogError> {
        if let Some(t) = &self.tail { if height != t.height + 1 { return Err(LogError::Gap { expected: t.height + 1, got: height }); } }
        let prev = self.tail.as_ref().map(|t| t.hash).unwrap_or(self.anchor);
        let (bytes, h) = record_bytes(height, payload, &prev);
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

    /// Read and verify the whole log from the anchor, calling `f(height, payload)` for each record, in order.
    /// Fails on any damage. Used for replay and for the full verification cost measurement.
    pub fn replay(dir: &Path, anchor: Hash32, mut f: impl FnMut(u64, &[u8])) -> Result<Option<Tail>, LogError> {
        let mut prev = anchor; let mut expect: Option<u64> = None; let mut tail = None;
        for (first, path) in segments(dir)? {
            let mut bytes = vec![]; std::fs::File::open(&path)?.read_to_end(&mut bytes)?;
            let s = scan_bytes(&bytes, prev, expect.or(Some(first)), &mut f);
            if let Some((off, why)) = s.damage { return Err(LogError::Corrupt { segment: seg_name(first), offset: off, detail: why }); }
            if let Some(t) = s.tail { prev = t.hash; expect = Some(t.height + 1); tail = Some(t); }
        }
        Ok(tail)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ANCHOR: Hash32 = [7u8; 32];
    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("cf-blocklog-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d); d
    }
    fn payload(h: u64) -> Vec<u8> { format!("block-{h}-{}", "x".repeat((h % 17) as usize * 3)).into_bytes() }
    fn fill(dir: &Path, n: u64, seg: u64) -> Vec<Tail> {
        let mut l = BlockLog::create(dir, ANCHOR, seg).unwrap();
        (0..n).map(|h| l.append(h, &payload(h)).unwrap()).collect()
    }
    fn all_bytes(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
        segments(dir).unwrap().into_iter().map(|(_, p)| { let b = std::fs::read(&p).unwrap(); (p, b) }).collect()
    }

    #[test]
    fn golden_record_bytes_are_fixed_across_platforms() {
        let (b, h) = record_bytes(1, b"abc", &[0u8; 32]);
        assert_eq!(b.len(), HEADER_LEN + 3 + TRAILER_LEN);
        assert_eq!(&b[..4], b"CFBL");
        assert_eq!(hex::encode(h), "290132246c87e8f14505e29ce5a9b9145094dbaabef8c0b27846b3b350cebe27");
    }

    #[test]
    fn append_replay_roundtrip_across_segments() {
        let d = tmp("rt"); let tails = fill(&d, 25, 4);
        assert_eq!(segments(&d).unwrap().len(), 7);
        let mut seen = vec![];
        let t = BlockLog::replay(&d, ANCHOR, |h, p| { assert_eq!(p, payload(h).as_slice()); seen.push(h); }).unwrap().unwrap();
        assert_eq!(t, *tails.last().unwrap());
        assert_eq!(seen, (0..25).collect::<Vec<_>>());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn same_inputs_give_identical_bytes() {
        let (a, b) = (tmp("det-a"), tmp("det-b")); fill(&a, 10, 3); fill(&b, 10, 3);
        let (x, y): (Vec<_>, Vec<_>) = (all_bytes(&a).into_iter().map(|r| r.1).collect(), all_bytes(&b).into_iter().map(|r| r.1).collect());
        assert_eq!(x, y);
        let _ = std::fs::remove_dir_all(&a); let _ = std::fs::remove_dir_all(&b);
    }

    #[test]
    fn append_rejects_a_height_gap() {
        let d = tmp("gap"); let mut l = BlockLog::create(&d, ANCHOR, 4).unwrap();
        l.append(0, b"a").unwrap();
        assert!(matches!(l.append(2, b"c"), Err(LogError::Gap { expected: 1, got: 2 })));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// PB-T3/T6: log AHEAD of the committed checkpoint (record 5 appended, checkpoint still at 4),
    /// cut the last record at every byte offset: always recovers to exactly the committed tail 4.
    #[test]
    fn torn_last_record_beyond_the_committed_tail_is_truncated_at_every_offset() {
        let d = tmp("torn"); let tails = fill(&d, 6, 100);
        let committed = tails[4].clone();
        let seg = segments(&d).unwrap()[0].1.clone();
        let full = std::fs::read(&seg).unwrap();
        let end4 = full.len() - (HEADER_LEN + payload(5).len() + TRAILER_LEN);
        for cut in end4..=full.len() {
            std::fs::write(&seg, &full[..cut]).unwrap();
            let mut l = BlockLog::recover(&d, ANCHOR, 100, Some(committed.clone())).unwrap();
            assert_eq!(l.tail(), Some(&committed), "cut at {cut}");
            assert_eq!(std::fs::metadata(&seg).unwrap().len() as usize, end4);
            // and it can continue appending the next block
            l.append(5, &payload(5)).unwrap();
            std::fs::write(&seg, &full).unwrap();
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A short/partial record INSIDE the committed region is fatal (never repaired).
    #[test]
    fn torn_record_inside_the_committed_region_is_fatal() {
        let d = tmp("torn-in"); let tails = fill(&d, 6, 100);
        let seg = segments(&d).unwrap()[0].1.clone();
        let full = std::fs::read(&seg).unwrap();
        for cut in [full.len() - 1, full.len() - 40, full.len() - HEADER_LEN - 3] {
            std::fs::write(&seg, &full[..cut]).unwrap();
            assert!(BlockLog::recover(&d, ANCHOR, 100, Some(tails[5].clone())).is_err(), "cut {cut}");
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// PB-T5: flip one byte in every field region of a middle committed record: fatal, never silently repaired.
    #[test]
    fn corrupt_byte_in_a_committed_record_is_fatal() {
        let d = tmp("corrupt"); let tails = fill(&d, 6, 100);
        let seg = segments(&d).unwrap()[0].1.clone();
        let orig = std::fs::read(&seg).unwrap();
        let rec3_start: usize = (0..3).map(|h| HEADER_LEN + payload(h).len() + TRAILER_LEN).sum();
        let rec3_len = HEADER_LEN + payload(3).len() + TRAILER_LEN;
        for off in (0..rec3_len).step_by(1) {
            let mut b = orig.clone(); b[rec3_start + off] ^= 0x01;
            std::fs::write(&seg, &b).unwrap();
            assert!(BlockLog::recover(&d, ANCHOR, 100, Some(tails[5].clone())).is_err(), "flip at +{off}");
            assert!(BlockLog::replay(&d, ANCHOR, |_, _| {}).is_err(), "replay flip at +{off}");
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Interrupted checkpoint: the log is ahead of the committed checkpoint by whole records and a
    /// new segment; recovery returns to the committed tail and the log is usable.
    #[test]
    fn log_ahead_of_checkpoint_is_truncated_including_later_segments() {
        let d = tmp("ahead"); let tails = fill(&d, 14, 4);
        let committed = tails[5].clone(); // height 5 is mid-segment 2 (heights 4..7)
        let mut l = BlockLog::recover(&d, ANCHOR, 4, Some(committed.clone())).unwrap();
        assert_eq!(l.tail(), Some(&committed));
        assert_eq!(segments(&d).unwrap().len(), 2);
        let t6 = l.append(6, &payload(6)).unwrap();
        assert_eq!(t6.height, 6);
        let mut n = 0; BlockLog::replay(&d, ANCHOR, |_, _| n += 1).unwrap(); assert_eq!(n, 7);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn empty_new_segment_after_a_crash_in_roll_is_removed() {
        let d = tmp("roll"); let tails = fill(&d, 4, 4); // exactly one full segment
        std::fs::write(d.join(seg_name(4)), b"").unwrap(); // created, nothing written
        let mut l = BlockLog::recover(&d, ANCHOR, 4, Some(tails[3].clone())).unwrap();
        assert_eq!(segments(&d).unwrap().len(), 1);
        l.append(4, &payload(4)).unwrap();
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn missing_or_mismatched_committed_tail_is_fatal() {
        let d = tmp("missing"); let tails = fill(&d, 8, 4);
        // checkpoint claims height 9 but log only reaches 7
        assert!(matches!(BlockLog::recover(&d, ANCHOR, 4, Some(Tail { height: 9, hash: [1; 32] })), Err(LogError::MissingCommitted { .. })));
        // right height, wrong hash
        assert!(matches!(BlockLog::recover(&d, ANCHOR, 4, Some(Tail { height: 7, hash: [1; 32] })), Err(LogError::MissingCommitted { .. })));
        // the LAST segment deleted: replay alone cannot tell (a valid shorter log), the checkpoint catches it
        std::fs::remove_file(d.join(seg_name(4))).unwrap();
        assert!(BlockLog::recover(&d, ANCHOR, 4, Some(tails[7].clone())).is_err());
        assert!(BlockLog::replay(&d, ANCHOR, |_, _| {}).is_ok());
        let _ = std::fs::remove_dir_all(&d);
        // a MIDDLE segment deleted: both recovery and replay fail
        let d = tmp("missing-mid"); let tails = fill(&d, 12, 4);
        std::fs::remove_file(d.join(seg_name(4))).unwrap();
        assert!(BlockLog::recover(&d, ANCHOR, 4, Some(tails[11].clone())).is_err());
        assert!(BlockLog::replay(&d, ANCHOR, |_, _| {}).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn nothing_committed_removes_everything() {
        let d = tmp("none"); fill(&d, 6, 4);
        let l = BlockLog::recover(&d, ANCHOR, 4, None).unwrap();
        assert!(l.tail().is_none() && segments(&d).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn create_refuses_a_directory_that_already_holds_a_log() {
        let d = tmp("refuse"); fill(&d, 2, 4);
        assert!(BlockLog::create(&d, ANCHOR, 4).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn wrong_anchor_is_rejected() {
        let d = tmp("anchor"); let tails = fill(&d, 3, 4);
        assert!(BlockLog::recover(&d, [9u8; 32], 4, Some(tails[2].clone())).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }
}
