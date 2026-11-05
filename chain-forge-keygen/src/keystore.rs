//! `qattice-key` v1 encrypted key files. SCAFFOLD (tests first): every operation returns `Error::NotImplemented`.

use chain_forge_crypto::KeyPair;
use std::path::Path;

#[derive(Debug)]
pub enum Error {
    Passphrase(String),
    Randomness(String),
    Kdf(String),
    Format(String),
    Decrypt,
    Permission(String),
    Io(String),
    Exists(String),
    Key(String),
    NotImplemented,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "{self:?}") }
}
impl std::error::Error for Error {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfCost { pub m_cost_kib: u32, pub t_cost: u32, pub p_cost: u32 }
impl KdfCost {
    pub const PRODUCTION: KdfCost = KdfCost { m_cost_kib: 131_072, t_cost: 3, p_cost: 4 };
    pub const FLOOR: KdfCost = KdfCost { m_cost_kib: 19_456, t_cost: 2, p_cost: 1 };
    pub const CEILING: KdfCost = KdfCost { m_cost_kib: 1_048_576, t_cost: 10, p_cost: 16 };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadKind { Seed, ExpandedSecretKey }

pub struct Created { pub address: String, pub public_key: Vec<u8>, pub payload_kind: PayloadKind }

pub struct Loaded {
    pub label: String,
    pub address: String,
    pub public_key: Vec<u8>,
    pub payload_kind: PayloadKind,
    pub keypair: KeyPair,
}

#[derive(Clone)]
pub struct CreateOptions { pub cost: KdfCost, pub harden_existing_dir: bool, pub prefix: String }
impl Default for CreateOptions {
    fn default() -> Self { CreateOptions { cost: KdfCost::PRODUCTION, harden_existing_dir: false, prefix: "qcb".into() } }
}

/// The side effects the key store depends on, injectable so tests can make each one fail.
pub trait Platform {
    fn fill_random(&self, buf: &mut [u8]) -> Result<(), Error>;
    /// Create `dir` restricted to the current user, or verify an existing one (hardening it only if `harden_existing`).
    /// Returns whether the directory was created.
    fn prepare_dir(&self, dir: &Path, harden_existing: bool) -> Result<bool, Error>;
    fn restrict_file(&self, file: &Path) -> Result<(), Error>;
    fn verify_file(&self, file: &Path) -> Result<(), Error>;
    fn verify_dir(&self, dir: &Path) -> Result<(), Error>;
}

pub struct OsPlatform;
impl Platform for OsPlatform {
    fn fill_random(&self, _buf: &mut [u8]) -> Result<(), Error> { Err(Error::NotImplemented) }
    fn prepare_dir(&self, _dir: &Path, _h: bool) -> Result<bool, Error> { Err(Error::NotImplemented) }
    fn restrict_file(&self, _file: &Path) -> Result<(), Error> { Err(Error::NotImplemented) }
    fn verify_file(&self, _file: &Path) -> Result<(), Error> { Err(Error::NotImplemented) }
    fn verify_dir(&self, _dir: &Path) -> Result<(), Error> { Err(Error::NotImplemented) }
}

pub fn create_new(_path: &Path, _label: &str, _passphrase: &str, _opts: &CreateOptions, _p: &dyn Platform) -> Result<Created, Error> {
    Err(Error::NotImplemented)
}

pub fn load(_path: &Path, _passphrase: &str, _p: &dyn Platform) -> Result<Loaded, Error> { Err(Error::NotImplemented) }

pub fn migrate_plaintext(_from: &Path, _out: &Path, _passphrase: &str, _opts: &CreateOptions, _p: &dyn Platform) -> Result<Created, Error> {
    Err(Error::NotImplemented)
}
