//! `qattice-key` v1 encrypted key files (issue #107). Format, threat model and limitations: `docs/key-storage/SPEC.md`.
//!
//! Argon2id → AES-256-GCM (the wallet's primitives and parameters), with every header field authenticated as AAD, strict
//! parsing, KDF bounds, a seed-only payload for new keys, and fail-closed creation (no partial or unprotected file is ever
//! left behind). Errors never contain a passphrase, seed or key.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit};
use chain_forge_core::{Address, AddressScheme, HashWidth};
use chain_forge_crypto::fips204_backend::{MlDsa65Fips204 as B, PUBLIC_KEY_BYTES, SECRET_KEY_BYTES};
use chain_forge_crypto::{KeyPair, SchemeId};
use serde_json::{json, Map, Value};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

use crate::fsperm;

const FORMAT: &str = "qattice-key";
const VERSION: u64 = 1;
const SCHEME: &str = "ml-dsa-65";
const KDF_ALG: &str = "argon2id";
const KDF_VERSION: u64 = 19; // 0x13
const CIPHER_ALG: &str = "aes-256-gcm";
const MAX_FILE_BYTES: u64 = 64 * 1024;
const MAX_LABEL_BYTES: usize = 128;
const MIN_PASSPHRASE_BYTES: usize = 12;
const SALT_BYTES: usize = 32;
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
const SEED_BYTES: usize = 32;

#[derive(Debug)]
pub enum Error {
    Passphrase(String),
    Randomness(String),
    Kdf(String),
    Format(String),
    /// Wrong passphrase or a modified file: deliberately indistinguishable.
    Decrypt,
    Permission(String),
    Io(String),
    Exists(String),
    Key(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Passphrase(m) => write!(f, "passphrase: {m}"),
            Error::Randomness(m) => write!(f, "randomness unavailable: {m}"),
            Error::Kdf(m) => write!(f, "key derivation: {m}"),
            Error::Format(m) => write!(f, "invalid key file: {m}"),
            Error::Decrypt => write!(f, "cannot decrypt: wrong passphrase or the key file was modified"),
            Error::Permission(m) => write!(f, "permissions: {m}"),
            Error::Io(m) => write!(f, "i/o: {m}"),
            Error::Exists(m) => write!(f, "refusing to overwrite {m}"),
            Error::Key(m) => write!(f, "key: {m}"),
        }
    }
}
impl std::error::Error for Error {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfCost {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}
impl KdfCost {
    /// The wallet's parameters: 128 MiB, 3 iterations, 4 lanes.
    pub const PRODUCTION: KdfCost = KdfCost { m_cost_kib: 131_072, t_cost: 3, p_cost: 4 };
    pub const FLOOR: KdfCost = KdfCost { m_cost_kib: 19_456, t_cost: 2, p_cost: 1 };
    pub const CEILING: KdfCost = KdfCost { m_cost_kib: 1_048_576, t_cost: 10, p_cost: 16 };

    fn check(&self) -> Result<(), Error> {
        let (lo, hi) = (Self::FLOOR, Self::CEILING);
        if self.m_cost_kib < lo.m_cost_kib || self.t_cost < lo.t_cost || self.p_cost < lo.p_cost {
            return Err(Error::Kdf(format!("cost {}/{}/{} is below the floor {}/{}/{}", self.m_cost_kib, self.t_cost, self.p_cost, lo.m_cost_kib, lo.t_cost, lo.p_cost)));
        }
        if self.m_cost_kib > hi.m_cost_kib || self.t_cost > hi.t_cost || self.p_cost > hi.p_cost {
            return Err(Error::Kdf(format!("cost {}/{}/{} is above the ceiling {}/{}/{}", self.m_cost_kib, self.t_cost, self.p_cost, hi.m_cost_kib, hi.t_cost, hi.p_cost)));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadKind {
    Seed,
    ExpandedSecretKey,
}
impl PayloadKind {
    fn name(self) -> &'static str { match self { PayloadKind::Seed => "seed", PayloadKind::ExpandedSecretKey => "expanded-secret-key" } }
    fn parse(s: &str) -> Option<Self> { match s { "seed" => Some(PayloadKind::Seed), "expanded-secret-key" => Some(PayloadKind::ExpandedSecretKey), _ => None } }
    fn payload_len(self) -> usize { match self { PayloadKind::Seed => SEED_BYTES, PayloadKind::ExpandedSecretKey => SECRET_KEY_BYTES } }
}

pub struct Created {
    pub address: String,
    pub public_key: Vec<u8>,
    pub payload_kind: PayloadKind,
}

pub struct Loaded {
    pub label: String,
    pub address: String,
    pub public_key: Vec<u8>,
    pub payload_kind: PayloadKind,
    /// The expanded key pair, in memory only. (`KeyPair` is not zeroized on drop: see the limitations in the spec.)
    pub keypair: KeyPair,
}

#[derive(Clone)]
pub struct CreateOptions {
    pub cost: KdfCost,
    /// Restrict an existing storage directory instead of refusing it. Never the default.
    pub harden_existing_dir: bool,
    pub prefix: String,
}
impl Default for CreateOptions {
    fn default() -> Self { CreateOptions { cost: KdfCost::PRODUCTION, harden_existing_dir: false, prefix: "qcb".into() } }
}

/// The side effects the key store depends on, injectable so tests can make each one fail.
pub trait Platform {
    fn fill_random(&self, buf: &mut [u8]) -> Result<(), Error>;
    /// Create `dir` restricted to the current user, or verify an existing one (hardening it only if `harden_existing`).
    fn prepare_dir(&self, dir: &Path, harden_existing: bool) -> Result<bool, Error>;
    fn restrict_file(&self, file: &Path) -> Result<(), Error>;
    fn verify_file(&self, file: &Path) -> Result<(), Error>;
    fn verify_dir(&self, dir: &Path) -> Result<(), Error>;
}

pub struct OsPlatform;
impl Platform for OsPlatform {
    fn fill_random(&self, buf: &mut [u8]) -> Result<(), Error> { getrandom::getrandom(buf).map_err(|e| Error::Randomness(e.to_string())) }
    fn prepare_dir(&self, dir: &Path, harden_existing: bool) -> Result<bool, Error> { fsperm::prepare_dir(dir, harden_existing).map_err(Error::Permission) }
    fn restrict_file(&self, file: &Path) -> Result<(), Error> { fsperm::restrict_file(file).map_err(Error::Permission) }
    fn verify_file(&self, file: &Path) -> Result<(), Error> { fsperm::verify_file(file).map_err(Error::Permission) }
    fn verify_dir(&self, dir: &Path) -> Result<(), Error> { fsperm::verify_dir(dir).map_err(Error::Permission) }
}

// ── helpers ──────────────────────────────────────────────────────────────────────────────────────────────────────────

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }

/// Strict lowercase hex of exactly `len` bytes.
fn unhex(s: &str, len: usize, what: &str) -> Result<Vec<u8>, Error> {
    if s.len() != 2 * len || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(Error::Format(format!("{what} must be {len} bytes of lowercase hex")));
    }
    Ok((0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("validated hex")).collect())
}

fn address_of(pk: &[u8], prefix: &str) -> String {
    Address::from_public_key_schemed(pk, prefix, HashWidth::Bits256, AddressScheme::PostQuantum).as_str().to_string()
}

fn check_passphrase(p: &str) -> Result<(), Error> {
    if p.trim().is_empty() { return Err(Error::Passphrase("the passphrase is empty".into())); }
    if p.len() < MIN_PASSPHRASE_BYTES { return Err(Error::Passphrase(format!("the passphrase must be at least {MIN_PASSPHRASE_BYTES} bytes"))); }
    Ok(())
}

/// Everything in the header, in a fixed order, length-prefixed: the AEAD's associated data.
#[allow(clippy::too_many_arguments)]
fn aad(label: &str, address: &str, pk: &[u8], kind: PayloadKind, c: KdfCost, salt: &[u8], nonce: &[u8]) -> Vec<u8> {
    let mut out = b"qattice-key/v1\0".to_vec();
    let mut put = |b: &[u8]| { out.extend_from_slice(&(b.len() as u32).to_be_bytes()); out.extend_from_slice(b); };
    put(FORMAT.as_bytes());
    put(VERSION.to_string().as_bytes());
    put(SCHEME.as_bytes());
    put(label.as_bytes());
    put(address.as_bytes());
    put(pk);
    put(kind.name().as_bytes());
    put(KDF_ALG.as_bytes());
    put(KDF_VERSION.to_string().as_bytes());
    put(c.m_cost_kib.to_string().as_bytes());
    put(c.t_cost.to_string().as_bytes());
    put(c.p_cost.to_string().as_bytes());
    put(salt);
    put(CIPHER_ALG.as_bytes());
    put(nonce);
    out
}

fn derive(passphrase: &str, salt: &[u8], c: KdfCost) -> Result<Zeroizing<[u8; 32]>, Error> {
    c.check()?;
    let params = argon2::Params::new(c.m_cost_kib, c.t_cost, c.p_cost, Some(32)).map_err(|e| Error::Kdf(format!("parameters: {e}")))?;
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon.hash_password_into(passphrase.as_bytes(), salt, &mut *key).map_err(|e| Error::Kdf(format!("derivation: {e}")))?;
    Ok(key)
}

fn parent_of(path: &Path) -> PathBuf {
    match path.parent() { Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(), _ => PathBuf::from(".") }
}

fn io(e: std::io::Error) -> Error { Error::Io(e.to_string()) }

// ── create ───────────────────────────────────────────────────────────────────────────────────────────────────────────

/// Everything needed to write one file, computed *before* any file exists, so most failures create nothing.
struct Sealed {
    json: Vec<u8>,
}

#[allow(clippy::too_many_arguments)]
fn seal(label: &str, pk: &[u8], address: &str, kind: PayloadKind, payload: &[u8], passphrase: &str, cost: KdfCost, p: &dyn Platform) -> Result<Sealed, Error> {
    check_passphrase(passphrase)?;
    cost.check()?;
    if label.len() > MAX_LABEL_BYTES { return Err(Error::Format(format!("label longer than {MAX_LABEL_BYTES} bytes"))); }
    if payload.len() != kind.payload_len() { return Err(Error::Key("payload has the wrong length".into())); }

    let mut salt = [0u8; SALT_BYTES];
    let mut nonce = [0u8; NONCE_BYTES];
    p.fill_random(&mut salt)?;
    p.fill_random(&mut nonce)?;

    let key = derive(passphrase, &salt, cost)?;
    let cipher = Aes256Gcm::new_from_slice(&*key).map_err(|e| Error::Kdf(format!("cipher init: {e}")))?;
    let aad = aad(label, address, pk, kind, cost, &salt, &nonce);
    let ct = cipher
        .encrypt(aes_gcm::Nonce::from_slice(&nonce), Payload { msg: payload, aad: &aad })
        .map_err(|_| Error::Kdf("encryption failed".into()))?;

    let doc = json!({
        "format": FORMAT, "version": VERSION, "scheme": SCHEME, "label": label, "address": address,
        "public_key": hex(pk), "payload_kind": kind.name(),
        "kdf": { "algorithm": KDF_ALG, "version": KDF_VERSION, "m_cost_kib": cost.m_cost_kib, "t_cost": cost.t_cost, "p_cost": cost.p_cost, "salt": hex(&salt) },
        "cipher": { "algorithm": CIPHER_ALG, "nonce": hex(&nonce) },
        "ciphertext": hex(&ct),
    });
    Ok(Sealed { json: serde_json::to_vec_pretty(&doc).map_err(|e| Error::Format(e.to_string()))? })
}

/// Create the file (never overwriting), restrict it, verify the restriction, write, sync, verify again. Any failure removes the
/// file this call created.
fn write_new(path: &Path, sealed: &Sealed, harden_existing_dir: bool, p: &dyn Platform) -> Result<(), Error> {
    let dir = parent_of(path);
    let created_dir = p.prepare_dir(&dir, harden_existing_dir)?;
    let result = (|| -> Result<(), Error> {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        { use std::os::unix::fs::OpenOptionsExt; opts.mode(0o600); }
        let mut f = match opts.open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Err(Error::Exists(path.display().to_string())),
            Err(e) => return Err(io(e)),
        };
        let inner = (|| -> Result<(), Error> {
            p.restrict_file(path)?;
            p.verify_file(path)?;
            f.write_all(&sealed.json).map_err(io)?;
            f.sync_all().map_err(io)?;
            p.verify_file(path)?;
            Ok(())
        })();
        drop(f);
        if inner.is_err() { let _ = std::fs::remove_file(path); }
        inner
    })();
    if result.is_err() && created_dir {
        // Only a directory this call created, and only if it is empty (remove_dir refuses otherwise).
        let _ = std::fs::remove_dir(&dir);
    }
    result
}

/// Generate a new ML-DSA-65 key (fresh OS-random seed), and write it encrypted. Only the seed is stored.
pub fn create_new(path: &Path, label: &str, passphrase: &str, opts: &CreateOptions, p: &dyn Platform) -> Result<Created, Error> {
    check_passphrase(passphrase)?;
    opts.cost.check()?;
    if path.exists() || std::fs::symlink_metadata(path).is_ok() { return Err(Error::Exists(path.display().to_string())); }

    let mut seed = Zeroizing::new([0u8; SEED_BYTES]);
    p.fill_random(&mut *seed)?;
    let kp = B::keygen_from_seed(&*seed);
    let address = address_of(&kp.public_key, &opts.prefix);
    let sealed = seal(label, &kp.public_key, &address, PayloadKind::Seed, &*seed, passphrase, opts.cost, p)?;
    write_new(path, &sealed, opts.harden_existing_dir, p)?;
    Ok(Created { address, public_key: kp.public_key, payload_kind: PayloadKind::Seed })
}

// ── load ─────────────────────────────────────────────────────────────────────────────────────────────────────────────

fn exact_keys(m: &Map<String, Value>, want: &[&str], what: &str) -> Result<(), Error> {
    if m.len() != want.len() || !want.iter().all(|k| m.contains_key(*k)) {
        return Err(Error::Format(format!("{what} must contain exactly the fields {want:?}")));
    }
    Ok(())
}

fn s<'a>(m: &'a Map<String, Value>, k: &str) -> Result<&'a str, Error> {
    m.get(k).and_then(Value::as_str).ok_or_else(|| Error::Format(format!("{k} must be a string")))
}

fn n(m: &Map<String, Value>, k: &str) -> Result<u64, Error> {
    m.get(k).and_then(Value::as_u64).ok_or_else(|| Error::Format(format!("{k} must be a non-negative integer")))
}

/// Load and decrypt a key file. Permissions of the file and its directory are verified first; the file is parsed strictly;
/// the KDF bounds are enforced before any derivation; the public key and address are recomputed after decryption.
pub fn load(path: &Path, passphrase: &str, p: &dyn Platform) -> Result<Loaded, Error> {
    p.verify_dir(&parent_of(path))?;
    p.verify_file(path)?;

    let mut raw = Vec::new();
    std::fs::File::open(path).map_err(io)?.take(MAX_FILE_BYTES + 1).read_to_end(&mut raw).map_err(io)?;
    if raw.len() as u64 > MAX_FILE_BYTES { return Err(Error::Format("file larger than 64 KiB".into())); }
    let v: Value = serde_json::from_slice(&raw).map_err(|e| Error::Format(format!("not valid JSON: {e}")))?;
    let top = v.as_object().ok_or_else(|| Error::Format("not a JSON object".into()))?;
    exact_keys(top, &["format", "version", "scheme", "label", "address", "public_key", "payload_kind", "kdf", "cipher", "ciphertext"], "the key file")?;
    let kdf = top["kdf"].as_object().ok_or_else(|| Error::Format("kdf must be an object".into()))?;
    exact_keys(kdf, &["algorithm", "version", "m_cost_kib", "t_cost", "p_cost", "salt"], "kdf")?;
    let cipher = top["cipher"].as_object().ok_or_else(|| Error::Format("cipher must be an object".into()))?;
    exact_keys(cipher, &["algorithm", "nonce"], "cipher")?;

    if s(top, "format")? != FORMAT { return Err(Error::Format("not a qattice-key file".into())); }
    if n(top, "version")? != VERSION { return Err(Error::Format("unsupported version".into())); }
    if s(top, "scheme")? != SCHEME { return Err(Error::Format("unsupported scheme".into())); }
    if s(kdf, "algorithm")? != KDF_ALG || n(kdf, "version")? != KDF_VERSION { return Err(Error::Format("unsupported key derivation".into())); }
    if s(cipher, "algorithm")? != CIPHER_ALG { return Err(Error::Format("unsupported cipher".into())); }
    let label = s(top, "label")?;
    if label.len() > MAX_LABEL_BYTES { return Err(Error::Format("label too long".into())); }
    let address = s(top, "address")?;
    let kind = PayloadKind::parse(s(top, "payload_kind")?).ok_or_else(|| Error::Format("unknown payload_kind".into()))?;
    let pk = unhex(s(top, "public_key")?, PUBLIC_KEY_BYTES, "public_key")?;
    let salt = unhex(s(kdf, "salt")?, SALT_BYTES, "salt")?;
    let nonce = unhex(s(cipher, "nonce")?, NONCE_BYTES, "nonce")?;
    let ct = unhex(s(top, "ciphertext")?, kind.payload_len() + TAG_BYTES, "ciphertext")?;

    let cost = {
        let get = |k: &str| -> Result<u32, Error> { u32::try_from(n(kdf, k)?).map_err(|_| Error::Kdf(format!("{k} out of range"))) };
        KdfCost { m_cost_kib: get("m_cost_kib")?, t_cost: get("t_cost")?, p_cost: get("p_cost")? }
    };
    cost.check()?; // before any derivation: a malicious file cannot demand unbounded memory or time

    check_passphrase_for_load(passphrase)?;
    let key = derive(passphrase, &salt, cost)?;
    let cipher = Aes256Gcm::new_from_slice(&*key).map_err(|_| Error::Decrypt)?;
    let aad = aad(label, address, &pk, kind, cost, &salt, &nonce);
    let payload = Zeroizing::new(
        cipher.decrypt(aes_gcm::Nonce::from_slice(&nonce), Payload { msg: &ct, aad: &aad }).map_err(|_| Error::Decrypt)?,
    );

    let kp = match kind {
        PayloadKind::Seed => {
            let mut seed = Zeroizing::new([0u8; SEED_BYTES]);
            seed.copy_from_slice(&payload);
            let kp = B::keygen_from_seed(&*seed);
            if kp.public_key != pk { return Err(Error::Key("the decrypted seed does not regenerate the stored public key".into())); }
            kp
        }
        PayloadKind::ExpandedSecretKey => {
            B::validate_keypair(&pk, &payload).map_err(|_| Error::Key("the decrypted secret key does not match the stored public key".into()))?;
            KeyPair { scheme: SchemeId::MlDsa, public_key: pk.clone(), private_key: payload.to_vec() }
        }
    };
    let prefix = address.find("1pq").map(|i| &address[..i]).ok_or_else(|| Error::Format("address is not a post-quantum address".into()))?;
    if address_of(&pk, prefix) != address { return Err(Error::Key("the address does not match the public key".into())); }

    Ok(Loaded { label: label.to_string(), address: address.to_string(), public_key: pk, payload_kind: kind, keypair: kp })
}

/// A load never reveals why it failed beyond "decrypt": an empty passphrase is simply a wrong one.
fn check_passphrase_for_load(p: &str) -> Result<(), Error> {
    if p.is_empty() { Err(Error::Decrypt) } else { Ok(()) }
}

// ── migration from the plaintext #106 / legacy formats ───────────────────────────────────────────────────────────────

const MAX_PLAINTEXT_BYTES: u64 = 1024 * 1024;

/// Encrypt an existing plaintext key file (`qcb-keygen mldsa-v2` or the legacy `mldsa` output) into a new key file.
/// The source is only read: never modified, deleted or printed. Everything is validated before anything is created, and the
/// result is decrypted and compared before success is reported.
pub fn migrate_plaintext(from: &Path, out: &Path, passphrase: &str, opts: &CreateOptions, p: &dyn Platform) -> Result<Created, Error> {
    check_passphrase(passphrase)?;
    opts.cost.check()?;
    if std::fs::symlink_metadata(out).is_ok() { return Err(Error::Exists(out.display().to_string())); }

    let mut raw = Zeroizing::new(Vec::new());
    std::fs::File::open(from).map_err(io)?.take(MAX_PLAINTEXT_BYTES + 1).read_to_end(&mut *raw).map_err(io)?;
    if raw.len() as u64 > MAX_PLAINTEXT_BYTES { return Err(Error::Key("the source file is larger than 1 MiB".into())); }
    let v: Value = serde_json::from_slice(&raw).map_err(|_| Error::Key("the source is not valid JSON".into()))?;
    let field = |k: &str| v.get(k).and_then(Value::as_str);

    let pk = unhex(field("public_key").ok_or_else(|| Error::Key("the source has no public_key".into()))?, PUBLIC_KEY_BYTES, "public_key").map_err(|_| Error::Key("public_key is not a valid ML-DSA-65 key encoding".into()))?;
    let sk = Zeroizing::new(unhex(field("private_key").ok_or_else(|| Error::Key("the source has no private_key".into()))?, SECRET_KEY_BYTES, "private_key").map_err(|_| Error::Key("private_key is not a valid ML-DSA-65 key encoding".into()))?);
    B::validate_keypair(&pk, &sk).map_err(|_| Error::Key("the source's secret and public keys are not a consistent pair".into()))?;

    let seed: Option<Zeroizing<Vec<u8>>> = match field("seed") {
        Some(sh) => {
            let sd = Zeroizing::new(unhex(sh, SEED_BYTES, "seed").map_err(|_| Error::Key("seed is not 32 bytes of hex".into()))?);
            let mut a = [0u8; SEED_BYTES];
            a.copy_from_slice(&sd);
            if B::keygen_from_seed(&a).public_key != pk { return Err(Error::Key("the source's seed does not regenerate its public key".into())); }
            a.zeroize();
            Some(sd)
        }
        None => None,
    };
    let address = address_of(&pk, &opts.prefix);
    if let Some(a) = field("address") {
        if a != address { return Err(Error::Key("the source's address does not match its public key".into())); }
    }
    let label = field("label").unwrap_or("migrated");

    let (kind, payload): (PayloadKind, &[u8]) = match &seed {
        Some(sd) => (PayloadKind::Seed, sd.as_slice()),
        None => (PayloadKind::ExpandedSecretKey, sk.as_slice()),
    };
    let sealed = seal(label, &pk, &address, kind, payload, passphrase, opts.cost, p)?;
    write_new(out, &sealed, opts.harden_existing_dir, p)?;

    // Decrypt what was just written and compare it with the source before reporting success.
    let check = load(out, passphrase, p).and_then(|l| {
        if l.public_key == pk && l.keypair.public_key == pk && l.payload_kind == kind { Ok(()) } else { Err(Error::Key("verification of the new file failed".into())) }
    });
    if let Err(e) = check {
        let _ = std::fs::remove_file(out);
        return Err(e);
    }
    Ok(Created { address, public_key: pk, payload_kind: kind })
}
