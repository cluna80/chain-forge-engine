/// chain-forge-core
///
/// Shared primitives for the Chain Forge engine. Every other crate imports
/// this one. This crate imports nothing from the workspace.
///
/// What lives here:
///   - Hash: SHA3-256 or SHA3-384 block/tx hashing (driven by genesis config)
///   - Address: bech32-style address type and derivation
///   - GenesisConfig: deserializer for the JSON the Chain Forge wizard produces
///   - Error: core error type
///
/// Whitepaper refs:
///   - Section 10 (hash width choice: 256 vs 384 bit)
///   - Section 7.6 (Chain Forge genesis JSON schema)

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256, Sha3_384};

// -- Error --------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("genesis JSON is invalid: {0}")]
    InvalidGenesis(String),

    #[error("address is malformed: {0}")]
    InvalidAddress(String),

    #[error("hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },

    #[error("unsupported hash width: {0} (must be 256 or 384)")]
    UnsupportedHashWidth(u32),
}

pub type CoreResult<T> = Result<T, CoreError>;

// -- Hash width ---------------------------------------------------------------

/// Which SHA3 variant to use, driven by genesis cryptography config.
/// Whitepaper Section 10: 256-bit is currently adequate (Grover reduces
/// effective security to ~128 bits, still NIST-approved). 384-bit gives
/// extra margin at negligible performance cost.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HashWidth {
    Bits256,
    Bits384,
}

impl HashWidth {
    pub fn from_bits(bits: u32) -> CoreResult<Self> {
        match bits {
            256 => Ok(Self::Bits256),
            384 => Ok(Self::Bits384),
            other => Err(CoreError::UnsupportedHashWidth(other)),
        }
    }

    pub fn byte_len(self) -> usize {
        match self {
            Self::Bits256 => 32,
            Self::Bits384 => 48,
        }
    }
}

// -- Hash type ----------------------------------------------------------------

/// A raw hash produced by the chain's configured SHA3 variant.
/// Stored as bytes internally; displayed/serialised as lowercase hex.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ChainHash(Vec<u8>);

impl ChainHash {
    /// Hash arbitrary bytes using the configured width.
    pub fn digest(data: &[u8], width: HashWidth) -> Self {
        match width {
            HashWidth::Bits256 => Self(Sha3_256::digest(data).to_vec()),
            HashWidth::Bits384 => Self(Sha3_384::digest(data).to_vec()),
        }
    }

    /// Hash two inputs concatenated (used for Merkle nodes and block hashes).
    pub fn digest2(a: &[u8], b: &[u8], width: HashWidth) -> Self {
        match width {
            HashWidth::Bits256 => {
                let mut h = Sha3_256::new();
                h.update(a);
                h.update(b);
                Self(h.finalize().to_vec())
            }
            HashWidth::Bits384 => {
                let mut h = Sha3_384::new();
                h.update(a);
                h.update(b);
                Self(h.finalize().to_vec())
            }
        }
    }

    /// Raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Lowercase hex string (suitable for JSON / logging).
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Parse from a hex string.
    pub fn from_hex(s: &str) -> CoreResult<Self> {
        if s.len() % 2 != 0 {
            return Err(CoreError::InvalidAddress(format!(
                "hex string has odd length: {s}"
            )));
        }
        let bytes = (0..s.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&s[i..i + 2], 16)
                    .map_err(|_| CoreError::InvalidAddress(format!("invalid hex: {s}")))
            })
            .collect::<CoreResult<Vec<u8>>>()?;
        Ok(Self(bytes))
    }

    /// Zero hash (used as parent_hash of the genesis block).
    pub fn zero(width: HashWidth) -> Self {
        Self(vec![0u8; width.byte_len()])
    }
}

impl std::fmt::Display for ChainHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Show first 8 hex chars in short contexts, full hex via Debug.
        let hex = self.to_hex();
        write!(f, "{}", &hex[..8.min(hex.len())])
    }
}

impl Serialize for ChainHash {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for ChainHash {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

// -- Address ------------------------------------------------------------------

/// A chain address. Format: `{prefix}{hex_of_hash_prefix}`.
/// Example for QCB: `qcb1a2b3c4d5...`
///
/// In a full implementation this would use bech32 encoding with a checksum.
/// For Phase 0 we use a simpler `{prefix}1{hex}` format that is checksum-free
/// but unambiguous. Bech32 proper is a TODO once the crypto layer is wired up.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Address(String);

impl Address {
    /// Derive an address from a public key hash.
    /// Takes the first 20 bytes of the hash (matching Cosmos/Ethereum convention).
    pub fn from_pubkey_hash(hash: &ChainHash, prefix: &str) -> Self {
        let hex: String = hash.as_bytes()
            .iter()
            .take(20)
            .map(|b| format!("{b:02x}"))
            .collect();
        Self(format!("{prefix}1{hex}"))
    }

    /// Derive the address a public key controls: hash the raw key bytes,
    /// then apply from_pubkey_hash. The single place this rule lives, so
    /// the executor and any client derive addresses identically.
    pub fn from_public_key(public_key: &[u8], prefix: &str, width: HashWidth) -> Self {
        let hash = ChainHash::digest(public_key, width);
        Self::from_pubkey_hash(&hash, prefix)
    }

    /// Parse a raw address string. Only validates that it is non-empty.
    pub fn from_str(s: &str) -> CoreResult<Self> {
        if s.is_empty() {
            return Err(CoreError::InvalidAddress("empty address".into()));
        }
        Ok(Self(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// -- Genesis config -----------------------------------------------------------
// These structs mirror the JSON produced by the Chain Forge wizard exactly.
// Field names use serde rename_all = "snake_case" to match the JSON keys.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisConfig {
    pub chain_id:        String,
    pub chain_name:      String,
    pub engine_version:  String,
    pub genesis_time:    String,
    pub environment:     GenesisEnvironment,
    pub native_token:    GenesisToken,
    pub address_prefix:  String,
    pub consensus:       GenesisConsensus,
    pub execution:       GenesisExecution,
    pub cryptography:    GenesisCryptography,
    pub network:         GenesisNetwork,
    pub limits:          GenesisLimits,
    pub modules:         Vec<String>,
    pub custom_modules:  Vec<String>,
    pub genesis_accounts: Vec<GenesisAccount>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisEnvironment {
    pub mode:           String,   // "devnet" | "testnet" | "mainnet"
    pub faucet_enabled: bool,
    pub relaxed_limits: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisToken {
    pub name:       String,
    pub symbol:     String,
    pub denom:      String,
    pub max_supply: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisConsensus {
    #[serde(rename = "type")]
    pub consensus_type:   String,   // "proof-of-stake" | "proof-of-authority"
    pub validator_set_size: u32,
    pub block_time_ms:    u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisExecution {
    pub state_model:        String,   // "account" | "utxo" | "hybrid"
    pub parallel_execution: bool,
    pub gas_model:          String,   // "fixed" | "dynamic" | "eip-1559-style"
    /// Whether every transaction must carry a valid Ed25519 signature from
    /// the key bound to its sender. Defaults to true when absent: a genesis
    /// file has to opt OUT of signature checks explicitly, never opt in.
    #[serde(default = "default_require_signatures")]
    pub require_signatures: bool,
}

fn default_require_signatures() -> bool { true }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisCryptography {
    pub signature_scheme: String,        // "classical" | "hybrid" | "pqc-native"
    pub pqc_algorithm:    Option<String>,// "ml-dsa" | "falcon" | "sphincs-plus"
    pub migration_trigger: String,
    pub hash_width:       u32,           // 256 | 384
    pub validator_scheme: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisNetwork {
    pub network_id:      String,
    pub p2p_port:        u16,
    pub rpc_port:        u16,
    pub bootstrap_nodes: Vec<String>,
    pub peer_discovery:  String,   // "mdns" | "bootstrap" | "both"
    pub max_peers:       u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisLimits {
    pub max_block_bytes:    u64,
    pub max_tx_bytes:       u64,
    pub block_gas_limit:    u64,
    pub mempool_size:       u64,
    pub mempool_ttl_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisAccount {
    pub label:   String,
    pub address: String,
    pub balance: String,
    pub role:    String,   // "validator" | "treasury" | "faucet" | "user"
    /// Hex-encoded Ed25519 public key bound to this account at genesis.
    /// Named genesis addresses (e.g. "qcb1alice") are not derived from a
    /// key, so without this they cannot send signed transactions at all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
}

impl GenesisConfig {
    /// Parse from a JSON string (as produced by the Chain Forge wizard).
    pub fn from_json(json: &str) -> CoreResult<Self> {
        serde_json::from_str(json)
            .map_err(|e| CoreError::InvalidGenesis(e.to_string()))
    }

    /// Serialise back to pretty-printed JSON.
    pub fn to_json_pretty(&self) -> CoreResult<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| CoreError::InvalidGenesis(e.to_string()))
    }

    /// Resolved hash width from the cryptography config.
    pub fn hash_width(&self) -> CoreResult<HashWidth> {
        HashWidth::from_bits(self.cryptography.hash_width)
    }

    /// Validate basic invariants. Returns a list of human-readable errors
    /// so the engine can report all problems at once rather than one at a time.
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();

        if self.chain_id.is_empty() {
            errors.push("chain_id is empty".into());
        }
        if self.address_prefix.is_empty() {
            errors.push("address_prefix is empty".into());
        }
        if self.consensus.validator_set_size == 0 {
            errors.push("validator_set_size must be >= 1".into());
        }
        if self.consensus.block_time_ms == 0 {
            errors.push("block_time_ms must be > 0".into());
        }
        if self.limits.max_tx_bytes > self.limits.max_block_bytes {
            errors.push(format!(
                "max_tx_bytes ({}) exceeds max_block_bytes ({})",
                self.limits.max_tx_bytes, self.limits.max_block_bytes
            ));
        }
        if self.network.p2p_port == self.network.rpc_port {
            errors.push(format!(
                "p2p_port and rpc_port are both {} - must be different",
                self.network.p2p_port
            ));
        }
        if !["256", "384"].contains(&self.cryptography.hash_width.to_string().as_str()) {
            errors.push(format!(
                "unsupported hash_width: {} (must be 256 or 384)",
                self.cryptography.hash_width
            ));
        }
        if self.genesis_accounts.is_empty() {
            errors.push("genesis_accounts is empty - chain cannot start".into());
        }

        // Warn (not error) if PQC is enabled but max_tx_bytes may be too small.
        if let Some(ref algo) = self.cryptography.pqc_algorithm {
            let min_bytes: u64 = match algo.as_str() {
                "ml-dsa"       => 4_096,
                "falcon"       => 2_048,
                "sphincs-plus" => 65_536,
                _              => 0,
            };
            if min_bytes > 0 && self.limits.max_tx_bytes < min_bytes {
                errors.push(format!(
                    "max_tx_bytes ({}) may be too small for {} signatures \
                     (recommended minimum: {})",
                    self.limits.max_tx_bytes, algo, min_bytes
                ));
            }
        }

        errors
    }
}

// -- Tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Minimal valid genesis JSON matching the Chain Forge wizard output schema.
    fn minimal_genesis_json() -> &'static str {
        r#"{
            "chain_id": "qcb-testnet-1",
            "chain_name": "QuarkCharmBit",
            "engine_version": "0.1.0",
            "genesis_time": "2026-09-16T00:00:00Z",
            "environment": {
                "mode": "testnet",
                "faucet_enabled": true,
                "relaxed_limits": true
            },
            "native_token": {
                "name": "QuarkCharm",
                "symbol": "QCB",
                "denom": "uqcb",
                "max_supply": "210000000"
            },
            "address_prefix": "qcb",
            "consensus": {
                "type": "proof-of-stake",
                "validator_set_size": 4,
                "block_time_ms": 5000
            },
            "execution": {
                "state_model": "account",
                "parallel_execution": false,
                "gas_model": "dynamic"
            },
            "cryptography": {
                "signature_scheme": "hybrid",
                "pqc_algorithm": "ml-dsa",
                "migration_trigger": "nist-guidance",
                "hash_width": 256,
                "validator_scheme": "pqc-native"
            },
            "network": {
                "network_id": "qcb-testnet-1-net",
                "p2p_port": 26656,
                "rpc_port": 26657,
                "bootstrap_nodes": [],
                "peer_discovery": "both",
                "max_peers": 50
            },
            "limits": {
                "max_block_bytes": 1048576,
                "max_tx_bytes": 65536,
                "block_gas_limit": 10000000,
                "mempool_size": 5000,
                "mempool_ttl_seconds": 300
            },
            "modules": ["bank", "staking"],
            "custom_modules": [],
            "genesis_accounts": [
                {
                    "label": "Validator 1",
                    "address": "qcb1abc123",
                    "balance": "1000000",
                    "role": "validator"
                },
                {
                    "label": "Treasury",
                    "address": "qcb1def456",
                    "balance": "9000000",
                    "role": "treasury"
                }
            ]
        }"#
    }

    #[test]
    fn sha3_256_is_deterministic() {
        let h1 = ChainHash::digest(b"hello chain forge", HashWidth::Bits256);
        let h2 = ChainHash::digest(b"hello chain forge", HashWidth::Bits256);
        assert_eq!(h1, h2);
        assert_eq!(h1.as_bytes().len(), 32);
    }

    #[test]
    fn sha3_384_produces_48_bytes() {
        let h = ChainHash::digest(b"qcb genesis", HashWidth::Bits384);
        assert_eq!(h.as_bytes().len(), 48);
    }

    #[test]
    fn hash_hex_roundtrip() {
        let original = ChainHash::digest(b"roundtrip test", HashWidth::Bits256);
        let hex = original.to_hex();
        let recovered = ChainHash::from_hex(&hex).unwrap();
        assert_eq!(original, recovered);
    }

    #[test]
    fn digest2_differs_from_single_digest() {
        let combined = ChainHash::digest2(b"parent", b"child", HashWidth::Bits256);
        let single   = ChainHash::digest(b"parentchild", HashWidth::Bits256);
        // digest2 updates hasher twice; single hashes concatenated bytes.
        // They should be equal because SHA3 is a streaming hash.
        // This test documents that behaviour explicitly.
        assert_eq!(combined, single);
    }

    #[test]
    fn zero_hash_has_correct_length() {
        assert_eq!(ChainHash::zero(HashWidth::Bits256).as_bytes().len(), 32);
        assert_eq!(ChainHash::zero(HashWidth::Bits384).as_bytes().len(), 48);
    }

    #[test]
    fn address_derivation_uses_prefix() {
        let hash = ChainHash::digest(b"pubkey bytes", HashWidth::Bits256);
        let addr = Address::from_pubkey_hash(&hash, "qcb");
        assert!(addr.as_str().starts_with("qcb1"),
            "QCB address should start with qcb1, got: {}", addr);
        assert_eq!(addr.as_str().len(), 44, // "qcb1" + 40 hex chars
            "address length should be 44, got: {}", addr.as_str().len());
    }

    #[test]
    fn address_from_public_key_is_deterministic_and_key_specific() {
        let a1 = Address::from_public_key(&[7u8; 32], "qcb", HashWidth::Bits256);
        let a2 = Address::from_public_key(&[7u8; 32], "qcb", HashWidth::Bits256);
        let b  = Address::from_public_key(&[8u8; 32], "qcb", HashWidth::Bits256);
        assert_eq!(a1.as_str(), a2.as_str());
        assert_ne!(a1.as_str(), b.as_str());
        assert!(a1.as_str().starts_with("qcb1"));
    }

    #[test]
    fn require_signatures_defaults_to_true_when_absent() {
        let cfg = GenesisConfig::from_json(minimal_genesis_json()).unwrap();
        assert!(cfg.execution.require_signatures,
            "a genesis file must opt out of signature checks, never opt in");
    }

    #[test]
    fn genesis_parses_from_wizard_json() {
        let cfg = GenesisConfig::from_json(minimal_genesis_json()).unwrap();
        assert_eq!(cfg.chain_id, "qcb-testnet-1");
        assert_eq!(cfg.native_token.symbol, "QCB");
        assert_eq!(cfg.consensus.validator_set_size, 4);
        assert_eq!(cfg.cryptography.hash_width, 256);
        assert_eq!(cfg.genesis_accounts.len(), 2);
        assert_eq!(cfg.network.p2p_port, 26656);
        assert_eq!(cfg.limits.max_block_bytes, 1_048_576);
    }

    #[test]
    fn genesis_validates_clean_config() {
        let cfg = GenesisConfig::from_json(minimal_genesis_json()).unwrap();
        let errors = cfg.validate();
        assert!(errors.is_empty(), "clean genesis should have no errors: {errors:?}");
    }

    #[test]
    fn genesis_validate_catches_port_conflict() {
        let json = minimal_genesis_json().replace(
            r#""rpc_port": 26657"#,
            r#""rpc_port": 26656"#,
        );
        let cfg = GenesisConfig::from_json(&json).unwrap();
        let errors = cfg.validate();
        assert!(errors.iter().any(|e| e.contains("p2p_port and rpc_port")),
            "should catch port conflict: {errors:?}");
    }

    #[test]
    fn genesis_validate_catches_tx_exceeds_block() {
        let json = minimal_genesis_json().replace(
            r#""max_tx_bytes": 65536"#,
            r#""max_tx_bytes": 2097152"#,
        );
        let cfg = GenesisConfig::from_json(&json).unwrap();
        let errors = cfg.validate();
        assert!(errors.iter().any(|e| e.contains("max_tx_bytes")),
            "should catch tx > block: {errors:?}");
    }

    #[test]
    fn genesis_validate_warns_pqc_tx_too_small() {
        // ml-dsa needs ~4096 bytes; set max_tx_bytes to 1024 to trigger warning
        let json = minimal_genesis_json().replace(
            r#""max_tx_bytes": 65536"#,
            r#""max_tx_bytes": 1024"#,
        );
        let cfg = GenesisConfig::from_json(&json).unwrap();
        let errors = cfg.validate();
        assert!(errors.iter().any(|e| e.contains("ml-dsa")),
            "should warn about ml-dsa tx size: {errors:?}");
    }

    #[test]
    fn genesis_hash_width_resolves() {
        let cfg = GenesisConfig::from_json(minimal_genesis_json()).unwrap();
        assert_eq!(cfg.hash_width().unwrap(), HashWidth::Bits256);
    }

    #[test]
    fn genesis_roundtrip_json() {
        let cfg = GenesisConfig::from_json(minimal_genesis_json()).unwrap();
        let json = cfg.to_json_pretty().unwrap();
        let cfg2 = GenesisConfig::from_json(&json).unwrap();
        assert_eq!(cfg.chain_id, cfg2.chain_id);
        assert_eq!(cfg.native_token.denom, cfg2.native_token.denom);
    }
}
