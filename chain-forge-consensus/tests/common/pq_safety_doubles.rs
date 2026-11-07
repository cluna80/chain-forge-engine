//! Test doubles for the PQ-HotStuff-2 safety-state tests. They are NOT trusted mechanisms:
//! * `MemStorage` models volatile vs durable state and enumerates every post-crash outcome.
//! * `TestCounter` is an in-memory counter standing in for a trusted monotonic counter.
//! * `TestSigner` / `TestVerifier` are a hedged test scheme with exact FIPS 204 ML-DSA-65 sizes (not a real signature).
#![allow(dead_code)]
use chain_forge_consensus::pq_hotstuff::safety::*;
use sha3::{Digest, Sha3_256};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

// ---------------------------------------------------------------- fault plan shared by storage and counter

#[derive(Default, Debug)]
pub struct Faults {
    /// number of fault-eligible operations performed so far (each of the five commit steps counts)
    pub ops: usize,
    /// names of the operations that took effect, in order
    pub log: Vec<&'static str>,
    /// the process dies immediately before operation number N: it and every later operation fail without effect
    pub crash_before: Option<usize>,
    /// operation number N fails with an I/O error without effect; later operations proceed
    pub fail_at: Option<usize>,
}
pub type Shared = Rc<RefCell<Faults>>;

pub fn faults() -> Shared { Rc::new(RefCell::new(Faults::default())) }

fn tick(f: &Shared, name: &'static str) -> Result<(), String> {
    let mut f = f.borrow_mut();
    let i = f.ops;
    if let Some(c) = f.crash_before { if i >= c { return Err(format!("crashed before operation {i} ({name})")); } }
    f.ops += 1;
    if f.fail_at == Some(i) { return Err(format!("injected I/O error at operation {i} ({name})")); }
    f.log.push(name);
    Ok(())
}

// ---------------------------------------------------------------- storage

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Entry { pub data: Vec<u8>, pub durable: bool }

#[derive(Clone, Debug)]
enum Effect {
    Write { name: String, data: Vec<u8>, content_durable: bool },
    Rename { from: String, to: String },
}

#[derive(Clone)]
pub struct MemStorage {
    /// what the running process sees
    vol: BTreeMap<String, Vec<u8>>,
    /// what is guaranteed to exist after a crash (`durable == false`: the name exists but its content may be torn)
    dur: BTreeMap<String, Entry>,
    /// effects since the last directory sync; each may or may not survive a crash
    pending: Vec<Effect>,
    pub faults: Shared,
}

fn prefix_lengths(len: usize, stride: usize) -> Vec<usize> {
    let mut v: BTreeSet<usize> = [0, 1, len.saturating_sub(1), len].into_iter().collect();
    let mut k = stride;
    while k < len { v.insert(k); k += stride; }
    v.into_iter().collect()
}

impl MemStorage {
    pub fn new(faults: Shared) -> Self { MemStorage { vol: BTreeMap::new(), dur: BTreeMap::new(), pending: vec![], faults } }

    /// Everything the process currently sees (used to take a "backup").
    pub fn files(&self) -> BTreeMap<String, Vec<u8>> { self.vol.clone() }

    /// Replace the storage with an earlier backup (an operator restoring old files). Everything is durable.
    pub fn restore(&mut self, files: BTreeMap<String, Vec<u8>>) {
        self.dur = files.iter().map(|(k, v)| (k.clone(), Entry { data: v.clone(), durable: true })).collect();
        self.vol = files;
        self.pending.clear();
    }

    pub fn set_raw(&mut self, name: &str, data: Vec<u8>) {
        self.vol.insert(name.into(), data.clone());
        self.dur.insert(name.into(), Entry { data, durable: true });
    }
    pub fn delete_raw(&mut self, name: &str) { self.vol.remove(name); self.dur.remove(name); }
    pub fn raw(&self, name: &str) -> Option<Vec<u8>> { self.vol.get(name).cloned() }
    pub fn is_empty(&self) -> bool { self.vol.is_empty() }

    /// Every state the storage could be in after a crash right now (a fresh, fault-free storage for each), given that the
    /// effects since the last directory sync may each have happened or not, and unsynced content may be torn at the
    /// sampled prefix lengths (`stride`, plus 0, 1, len-1, len).
    pub fn crash_outcomes(&self, stride: usize) -> Vec<MemStorage> {
        // 1. expand durable entries whose content is not durable
        let mut states: Vec<BTreeMap<String, Entry>> = vec![BTreeMap::new()];
        for (name, e) in &self.dur {
            let opts: Vec<Vec<u8>> = if e.durable { vec![e.data.clone()] } else { prefix_lengths(e.data.len(), stride).into_iter().map(|k| e.data[..k].to_vec()).collect() };
            let mut next = vec![];
            for st in &states { for o in &opts { let mut s = st.clone(); s.insert(name.clone(), Entry { data: o.clone(), durable: true }); next.push(s); } }
            states = next;
        }
        // 2. apply pending effects in order, each of which may or may not have happened
        for eff in &self.pending {
            let mut next = vec![];
            for st in &states {
                next.push(st.clone());
                match eff {
                    Effect::Write { name, data, content_durable } => {
                        if *content_durable {
                            let mut s = st.clone(); s.insert(name.clone(), Entry { data: data.clone(), durable: true }); next.push(s);
                        } else {
                            for k in prefix_lengths(data.len(), stride) {
                                let mut s = st.clone(); s.insert(name.clone(), Entry { data: data[..k].to_vec(), durable: true }); next.push(s);
                            }
                        }
                    }
                    Effect::Rename { from, to } => {
                        if st.contains_key(from) { let mut s = st.clone(); let e = s.remove(from).unwrap(); s.insert(to.clone(), e); next.push(s); }
                    }
                }
            }
            states = next;
        }
        let unique: BTreeSet<Vec<(String, Entry)>> = states.into_iter().map(|m| m.into_iter().collect()).collect();
        unique.into_iter().map(|v| {
            let dur: BTreeMap<String, Entry> = v.into_iter().collect();
            let vol = dur.iter().map(|(k, e)| (k.clone(), e.data.clone())).collect();
            MemStorage { vol, dur, pending: vec![], faults: faults() }
        }).collect()
    }
}

fn err(e: String) -> StorageError { StorageError(e) }

impl Storage for MemStorage {
    fn read(&self, name: &str) -> Result<Option<Vec<u8>>, StorageError> { Ok(self.vol.get(name).cloned()) }

    fn write_tmp(&mut self, name: &str, data: &[u8]) -> Result<(), StorageError> {
        tick(&self.faults, "write_tmp").map_err(err)?;
        self.vol.insert(name.into(), data.to_vec());
        self.pending.push(Effect::Write { name: name.into(), data: data.to_vec(), content_durable: false });
        Ok(())
    }

    fn sync_file(&mut self, name: &str) -> Result<(), StorageError> {
        tick(&self.faults, "sync_file").map_err(err)?;
        for e in self.pending.iter_mut().rev() {
            if let Effect::Write { name: n, content_durable, .. } = e { if n == name { *content_durable = true; return Ok(()); } }
        }
        if let Some(e) = self.dur.get_mut(name) { e.durable = true; }
        Ok(())
    }

    fn rename(&mut self, from: &str, to: &str) -> Result<(), StorageError> {
        tick(&self.faults, "rename").map_err(err)?;
        let d = self.vol.remove(from).ok_or_else(|| err(format!("rename: {from} does not exist")))?;
        self.vol.insert(to.into(), d);
        self.pending.push(Effect::Rename { from: from.into(), to: to.into() });
        Ok(())
    }

    fn sync_dir(&mut self) -> Result<(), StorageError> {
        tick(&self.faults, "sync_dir").map_err(err)?;
        for eff in std::mem::take(&mut self.pending) {
            match eff {
                Effect::Write { name, data, content_durable } => { self.dur.insert(name, Entry { data, durable: content_durable }); }
                Effect::Rename { from, to } => { if let Some(e) = self.dur.remove(&from) { self.dur.insert(to, e); } }
            }
        }
        Ok(())
    }

    fn remove(&mut self, name: &str) -> Result<(), StorageError> {
        self.vol.remove(name);
        self.pending.retain(|e| !matches!(e, Effect::Write { name: n, .. } if n == name));
        self.dur.remove(name);
        Ok(())
    }
}

// ---------------------------------------------------------------- trusted counter (test double)

#[derive(Clone)]
pub struct TestCounter { pub value: u64, pub faults: Shared }

impl TestCounter {
    pub fn new(faults: Shared) -> Self { TestCounter { value: 0, faults } }
    pub fn with_value(value: u64, faults: Shared) -> Self { TestCounter { value, faults } }
}

impl MonotonicCounter for TestCounter {
    fn read(&self) -> Result<u64, CounterError> { Ok(self.value) }
    fn advance_to(&mut self, v: u64) -> Result<(), CounterError> {
        tick(&self.faults, "counter").map_err(CounterError)?;
        if v != self.value && v != self.value + 1 { return Err(CounterError(format!("cannot move from {} to {v}", self.value))); }
        self.value = v;
        Ok(())
    }
}

// ---------------------------------------------------------------- hedged test signature scheme with ML-DSA-65 sizes

fn expand(seed: &[u8], n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n);
    let mut i = 0u32;
    while out.len() < n {
        let mut h = Sha3_256::new();
        h.update(seed);
        h.update(i.to_be_bytes());
        out.extend_from_slice(&h.finalize());
        i += 1;
    }
    out.truncate(n);
    out
}

pub fn test_public_key(sk: u8) -> Vec<u8> { expand(&[b'k', sk], 1952) }

fn tag(pk: &[u8], ctx: &[u8], msg: &[u8], nonce: u64, n: usize) -> Vec<u8> {
    let mut seed = pk.to_vec();
    seed.extend_from_slice(&(ctx.len() as u32).to_be_bytes());
    seed.extend_from_slice(ctx);
    seed.extend_from_slice(msg);
    seed.extend_from_slice(&nonce.to_be_bytes());
    expand(&seed, n)
}

pub struct TestSigner {
    pk: Vec<u8>,
    nonce: u64,
    /// how many times `sign` was called
    pub calls: usize,
    pub fail_next: bool,
    pub short_signature: bool,
}

impl TestSigner {
    pub fn new(sk: u8) -> Self { TestSigner { pk: test_public_key(sk), nonce: 1000 * sk as u64, calls: 0, fail_next: false, short_signature: false } }
}

impl ConsensusSigner for TestSigner {
    fn public_key(&self) -> &[u8] { &self.pk }
    fn sign(&mut self, context: &[u8], message: &[u8]) -> Result<Vec<u8>, SignerError> {
        self.calls += 1;
        if self.fail_next { self.fail_next = false; return Err(SignerError("injected RNG failure".into())); }
        self.nonce += 1; // hedged: every signature over the same message differs
        let mut s = self.nonce.to_be_bytes().to_vec();
        s.extend(tag(&self.pk, context, message, self.nonce, 3309 - 8));
        if self.short_signature { s.pop(); }
        Ok(s)
    }
}

pub struct TestVerifier;

impl ConsensusVerifier for TestVerifier {
    fn verify(&self, public_key: &[u8], context: &[u8], message: &[u8], signature: &[u8]) -> bool {
        if signature.len() != 3309 { return false; }
        let nonce = u64::from_be_bytes(signature[..8].try_into().unwrap());
        signature[8..] == tag(public_key, context, message, nonce, 3309 - 8)[..]
    }
}
