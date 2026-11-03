//! PERSIST-001 P-02b PR 2 — storage format 2 (DEFAULT OFF).
//!
//! Chain blocks and validator-set history are appended to two hash-chained logs ([`crate::blocklog`]); the
//! generation carries the six small state files plus `storage_descriptor.json`, which names both log tails.
//! The manifest (written last, then `CURRENT`) is the single commit point; anything in a log beyond the
//! descriptor's tail is uncommitted and removed at startup. See `docs/persist-001-p02b-integration-design.md`.
//!
//! This module does not decide *whether* v2 is used (the node does, default off) and never touches a v1
//! directory: a layout mismatch is an error, never a migration.

use crate::blocklog::{self, BlockLog, Tail, KIND_BLOCK, KIND_VALIDATOR_SET};
use crate::canon::{CanonError, Dec, Enc};
use crate::persistence::{self, Layout, SnapshotContents, SnapshotIdentity, FORMAT_VERSION_V2};
use chain_forge_consensus::{BlockHash, BlockProposal, CommitCertificate, ValidatorId, ValidatorInfo, ValidatorSet, Vote, VoteType};
use std::collections::BTreeMap;
use std::path::Path;

pub const BLOCKLOG_DIR: &str = "blocklog";
pub const HVSLOG_DIR: &str = "hvslog";
pub const DESCRIPTOR_FILE: &str = "storage_descriptor.json";
/// Records per segment (a fixed constant: the descriptor does not carry it, recovery does not depend on it).
pub const SEG_RECORDS: u64 = 1000;
/// The six state files that stay in every generation (everything except the two growing collections).
pub const SMALL_FILES: &[&str] = &["state.json", "identity.json", "validators.json", "agents.json", "slashing.json", "live_validator_set.json"];

pub type ChainStore = BTreeMap<u64, (CommitCertificate, BlockProposal)>;
pub type VsetHistory = BTreeMap<u64, ValidatorSet>;

// ── canonical encodings (version 1; pinned by golden bytes) ──────────────────────────────────────

const SCHEMA_V1: u8 = 1;

fn enc_vote(e: &mut Enc, v: &Vote) {
    e.u8(match v.vote_type { VoteType::Prevote => 0, VoteType::Precommit => 1, VoteType::Nil => 2 })
     .u64(v.height).u32(v.round).str(&v.validator.0)
     .opt(&v.block_hash, |e, h| { e.str(&h.0); }).bytes(&v.signature).str(&v.scheme);
}
fn dec_vote(d: &mut Dec<'_>) -> Result<Vote, CanonError> {
    let vote_type = match d.u8()? { 0 => VoteType::Prevote, 1 => VoteType::Precommit, 2 => VoteType::Nil, t => return Err(CanonError::BadTag(t)) };
    Ok(Vote { vote_type, height: d.u64()?, round: d.u32()?, validator: ValidatorId(d.str()?.to_string()),
              block_hash: d.opt(|d| Ok(BlockHash(d.str()?.to_string())))?, signature: d.bytes()?.to_vec(), scheme: d.str()?.to_string() })
}

/// `(CommitCertificate, BlockProposal)` → canonical bytes (schema byte, then the fields in declaration order).
pub fn encode_block(cert: &CommitCertificate, p: &BlockProposal) -> Vec<u8> {
    let mut e = Enc::new();
    e.u8(SCHEMA_V1).u64(cert.height).u32(cert.round).str(&cert.block_hash.0).seq(&cert.precommits, |e, v| enc_vote(e, v));
    e.u64(p.height).u32(p.round).str(&p.proposer.0).str(&p.block_hash.0).str(&p.parent_hash.0).u64(p.timestamp_ms)
     .bytes(&p.tx_data).bytes(&p.signature).opt(&p.pol_round, |e, r| { e.u32(*r); });
    e.finish()
}
pub fn decode_block(bytes: &[u8]) -> Result<(CommitCertificate, BlockProposal), CanonError> {
    let mut d = Dec::new(bytes);
    let v = d.u8()?; if v != SCHEMA_V1 { return Err(CanonError::UnknownVersion(v)); }
    let cert = CommitCertificate { height: d.u64()?, round: d.u32()?, block_hash: BlockHash(d.str()?.to_string()), precommits: d.seq(dec_vote)? };
    let p = BlockProposal { height: d.u64()?, round: d.u32()?, proposer: ValidatorId(d.str()?.to_string()), block_hash: BlockHash(d.str()?.to_string()),
        parent_hash: BlockHash(d.str()?.to_string()), timestamp_ms: d.u64()?, tx_data: d.bytes()?.to_vec(), signature: d.bytes()?.to_vec(),
        pol_round: d.opt(|d| d.u32())? };
    d.finish()?;
    Ok((cert, p))
}

pub fn encode_vset(s: &ValidatorSet) -> Vec<u8> {
    let mut e = Enc::new();
    e.u8(SCHEMA_V1).u64(s.height).seq(&s.validators, |e, v| { e.str(&v.id.0).u64(v.voting_power).bool(v.pop_verified).bytes(&v.public_key); });
    e.finish()
}
pub fn decode_vset(bytes: &[u8]) -> Result<ValidatorSet, CanonError> {
    let mut d = Dec::new(bytes);
    let v = d.u8()?; if v != SCHEMA_V1 { return Err(CanonError::UnknownVersion(v)); }
    let s = ValidatorSet { height: d.u64()?, validators: d.seq(|d| Ok(ValidatorInfo { id: ValidatorId(d.str()?.to_string()), voting_power: d.u64()?,
        pop_verified: d.bool()?, public_key: d.bytes()?.to_vec() }))? };
    d.finish()?;
    Ok(s)
}

// ── descriptor ──────────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Descriptor {
    pub format: String,
    pub block_first_height: u64, pub block_tail_height: u64, pub block_tail_hash: String,
    pub hvs_first_height: u64,   pub hvs_tail_height: u64,   pub hvs_tail_hash: String,
}
fn hash_of(h: &str) -> Result<[u8; 32], String> {
    let v = hex::decode(h).map_err(|e| format!("descriptor hash: {e}"))?;
    v.try_into().map_err(|_| "descriptor hash is not 32 bytes".to_string())
}
impl Descriptor {
    fn tails(&self) -> Result<(Tail, Tail), String> {
        Ok((Tail { height: self.block_tail_height, hash: hash_of(&self.block_tail_hash)? },
            Tail { height: self.hvs_tail_height, hash: hash_of(&self.hvs_tail_hash)? }))
    }
}

// ── live logs ───────────────────────────────────────────────────────────────────────────────────

pub struct V2Logs { pub block: BlockLog, pub hvs: BlockLog, pub block_first: u64, pub hvs_first: u64 }

fn anchor(identity: &SnapshotIdentity, kind: u8) -> blocklog::Hash32 { blocklog::anchor_for(identity.genesis_hash.as_bytes(), kind) }

/// One block's persistence for format 2, in the D1 order: (1) append the block, fsync; (2) append the validator
/// set, fsync; (3) write the generation (small files, descriptor, manifest last, then `CURRENT`). Returns only
/// after `CURRENT` is durable. Any error is fatal for the caller.
pub fn commit(dir: &Path, logs: &mut Option<V2Logs>, identity: &SnapshotIdentity, chain_store: &ChainStore, hvs: &VsetHistory,
              mut small: Vec<(&'static str, Vec<u8>)>, height: u64, state_root: &str) -> Result<(), String> {
    if logs.is_none() {
        let (Some(bf), Some(hf)) = (chain_store.keys().next().copied(), hvs.keys().next().copied()) else {
            return Err("v2 persist: nothing to persist (empty chain store or validator history)".into());
        };
        *logs = Some(V2Logs {
            block: BlockLog::create(&dir.join(BLOCKLOG_DIR), KIND_BLOCK, anchor(identity, KIND_BLOCK), bf, SEG_RECORDS).map_err(|e| e.to_string())?,
            hvs: BlockLog::create(&dir.join(HVSLOG_DIR), KIND_VALIDATOR_SET, anchor(identity, KIND_VALIDATOR_SET), hf, SEG_RECORDS).map_err(|e| e.to_string())?,
            block_first: bf, hvs_first: hf });
    }
    let l = logs.as_mut().unwrap();
    let next = l.block.tail().map(|t| t.height + 1).unwrap_or(l.block_first);
    for (h, (cert, p)) in chain_store.range(next..) {
        l.block.append(*h, &encode_block(cert, p)).map_err(|e| format!("v2 persist: block log append at {h}: {e}"))?;
    }
    #[cfg(test)] persistence::fault::hit("block_log_appended").map_err(|e| e.to_string())?;
    let next = l.hvs.tail().map(|t| t.height + 1).unwrap_or(l.hvs_first);
    for (h, set) in hvs.range(next..) {
        l.hvs.append(*h, &encode_vset(set)).map_err(|e| format!("v2 persist: history log append at {h}: {e}"))?;
    }
    #[cfg(test)] persistence::fault::hit("hvs_log_appended").map_err(|e| e.to_string())?;
    let (bt, ht) = (l.block.tail().cloned().ok_or("v2 persist: block log is empty")?, l.hvs.tail().cloned().ok_or("v2 persist: history log is empty")?);
    let desc = Descriptor { format: "p02b-storage-2".into(), block_first_height: l.block_first, block_tail_height: bt.height, block_tail_hash: hex::encode(bt.hash),
        hvs_first_height: l.hvs_first, hvs_tail_height: ht.height, hvs_tail_hash: hex::encode(ht.hash) };
    small.push((DESCRIPTOR_FILE, serde_json::to_vec_pretty(&desc).map_err(|e| e.to_string())?));
    persistence::write_snapshot_format(dir, height, &small, identity, state_root, FORMAT_VERSION_V2)
        .map_err(|e| format!("v2 persist: generation write failed at height {height}: {e}"))?;
    Ok(())
}

// ── startup ─────────────────────────────────────────────────────────────────────────────────────

pub struct Loaded { pub contents: SnapshotContents, pub chain_store: ChainStore, pub hvs: VsetHistory, pub logs: V2Logs }

/// Load a format-2 directory. `Ok(None)` = genuinely fresh (or a crash during the very first commit, in which
/// case at most one log record per log is removed). Every other inconsistency is `Err` (fatal; nothing repaired
/// except truncating log records beyond the committed tail).
pub fn load(dir: &Path, identity: &SnapshotIdentity) -> Result<Option<Loaded>, String> {
    match persistence::classify_layout(dir) {
        Layout::Fresh => return Ok(None),
        Layout::V1 => return Err("this data directory is storage format 1; this node is configured for storage v2 and never migrates automatically".into()),
        Layout::Ambiguous(why) => return Err(format!("ambiguous data directory layout: {why}")),
        Layout::LogsOnly => return verify_logs_only(dir, identity).map(|()| None),
        Layout::V2 => {}
    }
    let contents = persistence::load_snapshot_format(dir, identity, FORMAT_VERSION_V2).map_err(|e| e.to_string())?
        .ok_or("v2 directory classified but no snapshot loaded")?;
    let desc_bytes = contents.files.get(DESCRIPTOR_FILE).ok_or("v2 generation has no storage descriptor")?;
    let desc: Descriptor = serde_json::from_slice(desc_bytes).map_err(|e| format!("storage descriptor unreadable: {e}"))?;
    if desc.format != "p02b-storage-2" { return Err(format!("unknown descriptor format {}", desc.format)); }
    let (bt, ht) = desc.tails()?;
    if bt.height != contents.height || ht.height != contents.height {
        return Err(format!("descriptor tails (block {}, history {}) do not match the committed height {}", bt.height, ht.height, contents.height));
    }
    let block = BlockLog::recover(&dir.join(BLOCKLOG_DIR), KIND_BLOCK, anchor(identity, KIND_BLOCK), desc.block_first_height, SEG_RECORDS, Some(bt.clone())).map_err(|e| format!("block log: {e}"))?;
    let hvs_log = BlockLog::recover(&dir.join(HVSLOG_DIR), KIND_VALIDATOR_SET, anchor(identity, KIND_VALIDATOR_SET), desc.hvs_first_height, SEG_RECORDS, Some(ht.clone())).map_err(|e| format!("history log: {e}"))?;
    // Replay both logs completely (hash chain verified) and decode every record strictly.
    let mut chain_store = ChainStore::new(); let mut bad: Option<String> = None;
    let t = BlockLog::replay(&dir.join(BLOCKLOG_DIR), KIND_BLOCK, anchor(identity, KIND_BLOCK), desc.block_first_height, |h, p| match decode_block(p) {
        Ok(b) if b.0.height == h && b.1.height == h => { chain_store.insert(h, b); }
        Ok(_) => bad = Some(format!("block record {h} carries another height")), Err(e) => bad = Some(format!("block record {h}: {e}")) }).map_err(|e| format!("block log replay: {e}"))?;
    if let Some(b) = bad { return Err(b); }
    if t.as_ref() != Some(&bt) { return Err("block log replay tail differs from the committed tail".into()); }
    let mut hvs = VsetHistory::new();
    let t = BlockLog::replay(&dir.join(HVSLOG_DIR), KIND_VALIDATOR_SET, anchor(identity, KIND_VALIDATOR_SET), desc.hvs_first_height, |h, p| match decode_vset(p) {
        Ok(s) => { hvs.insert(h, s); } Err(e) => bad = Some(format!("history record {h}: {e}")) }).map_err(|e| format!("history log replay: {e}"))?;
    if let Some(b) = bad { return Err(b); }
    if t.as_ref() != Some(&ht) { return Err("history log replay tail differs from the committed tail".into()); }
    let mut contents = contents;
    // Feed the existing, unchanged restore path (it parses these two names from the verified file map).
    contents.files.insert("chain_store.json".into(), serde_json::to_vec(&chain_store).map_err(|e| e.to_string())?);
    contents.files.insert("historical_validator_sets.json".into(), serde_json::to_vec(&hvs).map_err(|e| e.to_string())?);
    Ok(Some(Loaded { contents, chain_store, hvs, logs: V2Logs { block, hvs: hvs_log, block_first: desc.block_first_height, hvs_first: desc.hvs_first_height } }))
}

/// No committed generation but log segments exist: only a crash during the very first commit may leave this, and
/// then each log holds at most one record. Anything else is refused. **Read-only**: nothing is deleted here, so the
/// caller can still refuse the start (signing guard) with the evidence intact; see [`discard_first_commit_logs`].
fn verify_logs_only(dir: &Path, identity: &SnapshotIdentity) -> Result<(), String> {
    for (sub, kind) in [(BLOCKLOG_DIR, KIND_BLOCK), (HVSLOG_DIR, KIND_VALIDATOR_SET)] {
        let ld = dir.join(sub);
        let Some(first) = blocklog::first_segment_height(&ld).map_err(|e| e.to_string())? else { continue };
        let mut n = 0u64;
        BlockLog::replay(&ld, kind, anchor(identity, kind), first, |_, _| n += 1).map_err(|e| format!("{sub}: {e}"))?;
        if n > 1 { return Err(format!("{sub} holds {n} records but no generation is committed: refusing to delete it")); }
    }
    Ok(())
}

/// Remove the (at most one-record) logs left by a crash during the very first commit. Call only after the
/// signing-guard check has allowed a fresh start.
pub fn discard_first_commit_logs(dir: &Path, identity: &SnapshotIdentity) -> Result<(), String> {
    verify_logs_only(dir, identity)?;
    for (sub, kind) in [(BLOCKLOG_DIR, KIND_BLOCK), (HVSLOG_DIR, KIND_VALIDATOR_SET)] {
        BlockLog::recover(&dir.join(sub), kind, anchor(identity, kind), 0, SEG_RECORDS, None).map_err(|e| format!("{sub}: {e}"))?;
    }
    Ok(())
}
