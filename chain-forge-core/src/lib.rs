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
    /// Pilot-phase sybil coordinator: the address authorized to call
    /// ConfirmSybil and ReverseSybil on-chain. None means coordinator
    /// authority is not set — attestation guard Phases C/D will reject
    /// ConfirmSybil and ReverseSybil until this is configured.
    /// Temporary centralization: see QCB-Attestation-Guard-Design.md §Coordinator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_coordinator: Option<String>,

    /// Optional Proof of Cryptographic Discovery configuration.
    ///
    /// When present and `enabled = true`, the node activates the PoCD mining
    /// module.  Stored as a raw JSON value here so `chain-forge-core` does
    /// not need to depend on `chain-forge-pocd`; the node deserialises it
    /// into `chain_forge_pocd::PoCDConfig` at startup.
    ///
    /// Minimal example:
    /// ```json
    /// "pocd": {
    ///   "enabled": true,
    ///   "chain_id": "qcb-devnet-1",
    ///   "challenge_tracks": ["Cryptography", "Mathematics"],
    ///   "reward_epoch_blocks": 720,
    ///   "require_verified_identity": false,
    ///   "min_seal_difficulty_bits": 16
    /// }
    /// ```
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pocd: Option<serde_json::Value>,

    /// Optional list of PoCD challenges to activate immediately at genesis.
    ///
    /// Stored as raw JSON so `chain-forge-core` does not depend on
    /// `chain-forge-pocd`.  The node crate deserializes this into
    /// `Vec<chain_forge_pocd::DiscoveryChallenge>` at startup.
    ///
    /// Example entry:
    /// ```json
    /// {
    ///   "challenge_id": "qcb-devnet-3node::Mathematics::pilot-1",
    ///   "chain_id": "qcb-devnet-3node",
    ///   "track": "Mathematics",
    ///   "name": "Pilot challenge",
    ///   "verification_criteria": "...",
    ///   "seal_difficulty_bits": 4,
    ///   "search_space_size": null,
    ///   "activated_at_block": null,
    ///   "status": "Active"
    /// }
    /// ```
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub genesis_challenges: Option<serde_json::Value>,

    /// Addresses authorized to submit `ClaimResearchReward` transactions
    /// on behalf of miners.  Analogous to `attestation_coordinator` for
    /// `ConfirmSybil`.
    ///
    /// Settlement operators:
    ///   - must hold ML-DSA-65 keys registered in the DIS (Digital Identity Stone)
    ///   - sign `ClaimResearchReward` txs with their ML-DSA-65 key; chain-ID
    ///     binding is enforced unconditionally by `verify_signature(tx, chain_id)`
    ///   - are responsible for verifying eligibility (canonical result, quorum,
    ///     budget) before submitting — the execution layer enforces state-key replay
    ///     prevention and recipient binding, not the full eligibility checks
    ///
    /// An empty list means no address can submit `ClaimResearchReward`.
    /// Change Set L: initial set populated at devnet genesis.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub settlement_operators: Vec<String>,

    /// Optional overrides for the permissionless stake-bond validator-
    /// onboarding module (`chain-forge-execution::validator_bond`) and the
    /// deterministic block-height validator-set epoch length
    /// (`chain-forge-node`'s `validator_epoch_blocks`).
    ///
    /// Entirely additive and backward compatible: omitting this field (as
    /// every genesis file predating it does) is identical to supplying
    /// `GenesisValidatorBonding { min_bond_amount: None, validator_epoch_blocks: None }`
    /// -- the engine falls back to its existing compiled-in defaults
    /// (`DEFAULT_MIN_BOND_UQCB`, `DEFAULT_VALIDATOR_EPOCH_BLOCKS`) exactly as
    /// it did before this field existed. No existing genesis JSON needs to
    /// change, and no running devnet needs to reset, to pick this change up.
    ///
    /// This is generic Chain Forge engine configuration, not a
    /// Qattice-specific policy: any chain built on Chain Forge that enables
    /// the "staking" module can set these independently of QCB's token
    /// economics. `chain-forge-core` deliberately does not depend on
    /// `chain-forge-execution` or `chain-forge-node`, so it cannot name
    /// their default constants directly -- it only carries the override;
    /// resolving "override, or the engine's own default" is the caller's
    /// job (see `chain-forge-node::Node::new_with_config`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validator_bonding: Option<GenesisValidatorBonding>,
}

/// See `GenesisConfig::validator_bonding`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisValidatorBonding {
    /// Minimum stake, in the chain's `native_token.denom`, a candidate must
    /// hold to be eligible for the active validator set. `None` means "use
    /// the engine's compiled-in default."
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_bond_amount: Option<u128>,

    /// Number of blocks per validator-set epoch. Every decision that can
    /// change validator membership, voting power, or quorum fires only at a
    /// height where `height % validator_epoch_blocks == 0`. `None` means
    /// "use the engine's compiled-in default."
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validator_epoch_blocks: Option<u64>,
}

// -- Modules ----------------------------------------------------------------------

/// Every module name a genesis may list, with what it switches on. This is
/// the single source of truth: the wizard should offer exactly these, and
/// the engine refuses any genesis that names something else. A module the
/// engine silently ignored would be worse than no option at all.
pub const KNOWN_MODULES: &[(&str, &str)] = &[
    ("bank",     "accounts, transfers and burns (always on)"),
    ("staking",  "Stake transactions"),
    ("identity", "proof of personhood: RegisterIdentity and web-of-trust Attest"),
    ("qrc",    "dormant legacy QRC-token purchase/spend/contribution/capacity paths -- not part of the active single-token ($QCB) protocol (requires identity)"),
    ("agents",   "sponsored agents (requires identity)"),
    ("market",   "resource job/escrow marketplace (LockQrcForJob, CreateJob..VerifyJob, etc.) -- not part of the active single-token ($QCB) protocol (requires identity)"),
    ("pocd",     "Proof-of-Compute-Discovery / Grand Challenge research rewards (RegisterMachine, SubmitUsefulWork, ClaimResearchReward) -- active, uqcb-denominated (requires identity)"),
];

/// Which optional engine modules a chain has switched on. The core (bank:
/// accounts, transfers, burns) is always on and isn't represented here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct EnabledModules {
    pub staking:  bool,
    pub identity: bool,
    /// Legacy QRC-token ops (QrcPurchase, QrcSpend, QrcContributionSettle,
    /// EpochOpen/EpochClose, RecordCapacity). Dormant in the single-token
    /// ($QCB-only) protocol -- see market/pocd for the active split-out paths.
    pub qrc:    bool,
    pub agents:   bool,
    /// The resource job/escrow marketplace (LockQrcForJob, ReleaseQrcForJob,
    /// RefundQrcForJob, CreateJob, AcceptJob, CompleteJob, VerifyJob,
    /// PurchaseQrc, CreditProvider). Not part of the active QCB-only protocol.
    pub market: bool,
    /// Proof-of-Compute-Discovery / Grand Challenge research-reward path
    /// (RegisterMachine, SubmitUsefulWork, ClaimResearchReward). Active,
    /// uqcb-denominated, and considered core to the protocol.
    pub pocd:   bool,
}

impl EnabledModules {
    /// Everything on -- every module this engine knows how to run.
    pub fn all() -> Self {
        Self {
            staking: true, identity: true, qrc: true, agents: true,
            market: true, pocd: true,
        }
    }
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
    /// Cap each validator's voting power per verified human (QCB's "one
    /// human, bounded power" rule). Off unless a genesis turns it on, and
    /// requires the identity module -- personhood needs an identity layer.
    /// Previously this was switched on implicitly by consensus_type
    /// "proof-of-stake", so any chain choosing PoS got it unknowingly.
    #[serde(default)]
    pub personhood_weighted: bool,
    /// BFT algorithm variant to use for this chain.
    /// One of: "tendermint" (default), "hotstuff", "xrpl".
    /// Omitting this field uses TendermintStyle, preserving backward
    /// compatibility with all existing genesis files.
    #[serde(default)]
    pub bft_variant: Option<String>,
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

    /// Address that collects all per-transaction fees (in the native denom).
    /// Defaults to `"treasury:fees"` when absent in genesis.
    #[serde(default)]
    pub fee_collector: Option<String>,
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
    /// Resolve `modules` into EnabledModules, or explain every problem.
    /// Unlike validate(), whose findings the node only logs, an error here
    /// must stop the node: it means the chain would run with different
    /// behaviour than its genesis describes.
    pub fn enabled_modules(&self) -> Result<EnabledModules, String> {
        let mut m = EnabledModules::default();
        let mut errors = Vec::new();
        let known: Vec<&str> = KNOWN_MODULES.iter().map(|(n, _)| *n).collect();

        for name in &self.modules {
            match name.as_str() {
                "bank"     => {}
                "staking"  => m.staking = true,
                "identity" => m.identity = true,
                "qrc"    => m.qrc = true,
                "agents"   => m.agents = true,
                "market"   => m.market = true,
                "pocd"     => m.pocd = true,
                other => errors.push(format!(
                    "unknown module \"{other}\" (known modules: {})", known.join(", ")
                )),
            }
        }
        for name in &self.custom_modules {
            errors.push(format!(
                "custom module \"{name}\": Chain Forge does not support custom modules yet; remove it from custom_modules"
            ));
        }
        if m.qrc && !m.identity {
            errors.push("module \"qrc\" requires \"identity\": legacy QRC-token ops are gated by verified identity".into());
        }
        if m.market && !m.identity {
            errors.push("module \"market\" requires \"identity\": the resource marketplace gates jobs and settlement by verified identity".into());
        }
        if m.pocd && !m.identity {
            errors.push("module \"pocd\" requires \"identity\": ClaimResearchReward settlement operators are verified DIS identities".into());
        }
        if self.consensus.personhood_weighted && !m.identity {
            errors.push("consensus.personhood_weighted requires the \"identity\" module: personhood needs an identity layer".into());
        }
        if m.agents && !m.identity {
            errors.push("module \"agents\" requires \"identity\": every agent needs a verified human sponsor".into());
        }

        if errors.is_empty() { Ok(m) } else { Err(errors.join("; ")) }
    }

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

    /// Hard validation (unlike `validate()` above, which only produces
    /// warnings today): every genesis account with `role == "validator"`
    /// must carry a well-formed `public_key`.
    ///
    /// This is the security-change-set fix for mandatory validator keys
    /// (Decision: Option B, "mandatory registered consensus keys... for
    /// all validators, including genesis validators" -- no devnet bypass).
    /// `chain-forge-node::Node::new` calls this as a hard error, before
    /// consensus begins, rather than folding it into `validate()`'s
    /// warning-only list: a chain that cannot seat any validator with real
    /// voting power is not a "proceed with a warning" situation.
    ///
    /// "Well-formed" here means structurally valid -- present, valid hex,
    /// and at least 32 bytes (the Ed25519/ML-DSA-class floor; this is a
    /// sanity floor, not a scheme-specific length check, since
    /// `cryptography.validator_scheme` can vary). It does NOT verify the
    /// key is a valid point on any particular curve, or that a matching
    /// private key exists anywhere -- that half of the check
    /// (`local private key corresponds to the registered public key`) is
    /// `Node::load_signing_key`'s job, once an operator's node starts up
    /// and loads its own key file.
    pub fn validate_validator_keys(&self) -> Result<(), String> {
        for acct in &self.genesis_accounts {
            if acct.role != "validator" {
                continue;
            }
            let hex = match &acct.public_key {
                None => {
                    return Err(format!(
                        "genesis validator {:?} ({}) has no public_key -- \
                         every validator must carry a registered consensus \
                         key before consensus begins (no keyless validators, \
                         genesis included)",
                        acct.label, acct.address
                    ));
                }
                Some(h) if h.is_empty() => {
                    return Err(format!(
                        "genesis validator {:?} ({}) has an empty public_key",
                        acct.label, acct.address
                    ));
                }
                Some(h) => h,
            };
            if hex.len() % 2 != 0 {
                return Err(format!(
                    "genesis validator {:?} ({}) public_key is not valid hex \
                     (odd length: {} characters)",
                    acct.label, acct.address, hex.len()
                ));
            }
            let bytes: Option<Vec<u8>> = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
                .collect();
            let bytes = match bytes {
                Some(b) => b,
                None => {
                    return Err(format!(
                        "genesis validator {:?} ({}) public_key is not valid hex",
                        acct.label, acct.address
                    ));
                }
            };
            if bytes.len() < 32 {
                return Err(format!(
                    "genesis validator {:?} ({}) public_key is only {} bytes \
                     -- too short to be a real consensus key (expected >= 32)",
                    acct.label, acct.address, bytes.len()
                ));
            }
        }
        Ok(())
    }

    /// Hard validation of the optional `validator_bonding` override block.
    /// Unlike `validate()`'s warning-only list, this stops the node before
    /// consensus begins: an accepted-but-nonsensical value here is not a
    /// "proceed with a warning" situation, the same reasoning as
    /// `validate_validator_keys()`.
    ///
    /// - `min_bond_amount: Some(0)` is rejected -- a minimum of zero is not
    ///   a minimum at all; it defeats the entire point of a stake-based
    ///   Sybil defense (ROADMAP "Validator Onboarding" design decision).
    /// - `validator_epoch_blocks: Some(0)` is rejected -- `chain-forge-node`
    ///   computes `height / validator_epoch_blocks` on every commit; zero
    ///   would be a division-by-zero panic at runtime, not a graceful
    ///   degradation.
    ///
    /// `None` for either field is always valid (falls back to the engine
    /// default), so a genesis file that omits `validator_bonding` entirely
    /// always passes this check.
    pub fn validate_validator_bonding(&self) -> Result<(), String> {
        let Some(ref vb) = self.validator_bonding else { return Ok(()); };

        if vb.min_bond_amount == Some(0) {
            return Err(
                "validator_bonding.min_bond_amount is 0 -- a zero minimum \
                 bond provides no Sybil-resistance; omit the field to use \
                 the engine default, or set a positive value".into()
            );
        }
        if vb.validator_epoch_blocks == Some(0) {
            return Err(
                "validator_bonding.validator_epoch_blocks is 0 -- epoch \
                 number is computed as height / validator_epoch_blocks, so \
                 zero would divide by zero at the first commit; omit the \
                 field to use the engine default, or set a positive value".into()
            );
        }
        Ok(())
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

    fn with_modules(modules: &[&str], custom: &[&str]) -> GenesisConfig {
        let mut cfg = GenesisConfig::from_json(minimal_genesis_json()).unwrap();
        cfg.modules = modules.iter().map(|s| s.to_string()).collect();
        cfg.custom_modules = custom.iter().map(|s| s.to_string()).collect();
        cfg
    }

    #[test]
    fn plain_chain_enables_no_optional_modules() {
        let m = with_modules(&["bank"], &[]).enabled_modules().unwrap();
        assert_eq!(m, EnabledModules::default());
    }

    #[test]
    fn qcb_module_set_enables_everything() {
        let m = with_modules(&["bank", "staking", "identity", "qrc", "agents", "market", "pocd"], &[]).enabled_modules().unwrap();
        assert_eq!(m, EnabledModules::all());
    }

    #[test]
    fn single_token_module_set_excludes_market_and_qrc() {
        // The active QCB-only protocol: identity, staking, agents, and PoCD
        // research rewards, but not the legacy QRC-token paths or the
        // resource job/escrow marketplace.
        let m = with_modules(&["bank", "staking", "identity", "agents", "pocd"], &[]).enabled_modules().unwrap();
        assert!(m.staking && m.identity && m.agents && m.pocd);
        assert!(!m.qrc && !m.market);
    }

    #[test]
    fn unknown_and_custom_modules_are_refused() {
        let e = with_modules(&["bank", "dex"], &[]).enabled_modules().unwrap_err();
        assert!(e.contains("unknown module \"dex\""));
        let e = with_modules(&["bank"], &["my_thing"]).enabled_modules().unwrap_err();
        assert!(e.contains("does not support custom modules"));
    }

    #[test]
    fn modules_that_need_identity_are_refused_without_it() {
        let e = with_modules(&["bank", "qrc", "agents", "market", "pocd"], &[]).enabled_modules().unwrap_err();
        assert!(e.contains("\"qrc\" requires \"identity\""));
        assert!(e.contains("\"agents\" requires \"identity\""));
        assert!(e.contains("\"market\" requires \"identity\""));
        assert!(e.contains("\"pocd\" requires \"identity\""));
    }

    #[test]
    fn personhood_weighting_is_off_by_default_and_needs_identity() {
        let mut cfg = with_modules(&["bank", "staking"], &[]);
        assert!(!cfg.consensus.personhood_weighted, "choosing PoS must not imply personhood");
        cfg.consensus.personhood_weighted = true;
        let e = cfg.enabled_modules().unwrap_err();
        assert!(e.contains("personhood_weighted requires"));

        let mut qcb = with_modules(&["bank", "staking", "identity", "qrc", "agents", "market", "pocd"], &[]);
        qcb.consensus.personhood_weighted = true;
        assert!(qcb.enabled_modules().is_ok());
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
    fn validate_validator_keys_rejects_missing_public_key() {
        // minimal_genesis_json()'s validator deliberately has no public_key
        // (the pre-migration Phase-0 fixture) -- validate_validator_keys()
        // must hard-reject it, unlike validate() which only warns.
        let cfg = GenesisConfig::from_json(minimal_genesis_json()).unwrap();
        let err = cfg.validate_validator_keys().expect_err(
            "a validator with no public_key must be a hard error"
        );
        assert!(err.contains("qcb1abc123"), "error should name the offending validator: {err}");
        assert!(err.contains("no public_key"), "error should say why: {err}");
    }

    #[test]
    fn validate_validator_keys_accepts_well_formed_key() {
        let json = minimal_genesis_json().replace(
            r#""role": "validator"
                },"#,
            &format!(
                "\"role\": \"validator\",\n                    \"public_key\": \"{}\"\n                }},",
                "aa".repeat(32)
            ),
        );
        let cfg = GenesisConfig::from_json(&json).unwrap();
        assert!(cfg.validate_validator_keys().is_ok());
    }

    #[test]
    fn validate_validator_keys_rejects_empty_string_key() {
        let json = minimal_genesis_json().replace(
            r#""role": "validator"
                },"#,
            "\"role\": \"validator\",\n                    \"public_key\": \"\"\n                },",
        );
        let cfg = GenesisConfig::from_json(&json).unwrap();
        let err = cfg.validate_validator_keys().expect_err("empty public_key must be rejected");
        assert!(err.contains("empty"), "{err}");
    }

    #[test]
    fn validate_validator_keys_rejects_invalid_hex() {
        let json = minimal_genesis_json().replace(
            r#""role": "validator"
                },"#,
            "\"role\": \"validator\",\n                    \"public_key\": \"not-hex!!\"\n                },",
        );
        let cfg = GenesisConfig::from_json(&json).unwrap();
        let err = cfg.validate_validator_keys().expect_err("non-hex public_key must be rejected");
        assert!(err.contains("not valid hex"), "{err}");
    }

    #[test]
    fn validate_validator_keys_rejects_too_short_key() {
        let json = minimal_genesis_json().replace(
            r#""role": "validator"
                },"#,
            "\"role\": \"validator\",\n                    \"public_key\": \"aabbcc\"\n                },",
        );
        let cfg = GenesisConfig::from_json(&json).unwrap();
        let err = cfg.validate_validator_keys().expect_err("a 3-byte key must be rejected as too short");
        assert!(err.contains("too short"), "{err}");
    }

    #[test]
    fn validate_validator_keys_ignores_non_validator_roles() {
        // The treasury account in minimal_genesis_json() has no public_key
        // either -- that's fine, the check is scoped to role == "validator".
        let cfg = GenesisConfig::from_json(minimal_genesis_json()).unwrap();
        let treasury_only = cfg.genesis_accounts.iter().all(|a| a.role == "validator" || a.public_key.is_none());
        assert!(treasury_only, "sanity: fixture's treasury account has no key either");
        // The only reason validate_validator_keys() fails on this fixture is
        // the validator's missing key, not the treasury's.
        let err = cfg.validate_validator_keys().unwrap_err();
        assert!(!err.contains("qcb1def456"), "must not flag the treasury account: {err}");
    }

    #[test]
    fn validator_bonding_defaults_to_none_when_omitted() {
        // minimal_genesis_json() predates this field entirely -- every
        // existing genesis file on disk looks like this. Confirms the
        // field is additive: absence parses fine and resolves to "no
        // override", not an error and not a forced value.
        let cfg = GenesisConfig::from_json(minimal_genesis_json()).unwrap();
        assert!(cfg.validator_bonding.is_none());
        assert!(cfg.validate_validator_bonding().is_ok());
    }

    #[test]
    fn validator_bonding_accepts_valid_overrides() {
        let json = minimal_genesis_json().replace(
            r#""modules": ["bank", "staking"],"#,
            r#""modules": ["bank", "staking"],
            "validator_bonding": { "min_bond_amount": 5000000, "validator_epoch_blocks": 50 },"#,
        );
        let cfg = GenesisConfig::from_json(&json).unwrap();
        let vb = cfg.validator_bonding.as_ref().expect("validator_bonding should parse");
        assert_eq!(vb.min_bond_amount, Some(5_000_000));
        assert_eq!(vb.validator_epoch_blocks, Some(50));
        assert!(cfg.validate_validator_bonding().is_ok());
    }

    #[test]
    fn validator_bonding_round_trips_through_json() {
        // Serialization check (change-set requirement #8): a config built
        // with an override survives to_json_pretty() -> from_json() with
        // the same values, and a config with no override omits the key
        // entirely rather than writing `"validator_bonding": null`.
        let json = minimal_genesis_json().replace(
            r#""modules": ["bank", "staking"],"#,
            r#""modules": ["bank", "staking"],
            "validator_bonding": { "min_bond_amount": 2500000, "validator_epoch_blocks": 200 },"#,
        );
        let cfg = GenesisConfig::from_json(&json).unwrap();
        let round_tripped_json = cfg.to_json_pretty().unwrap();
        let cfg2 = GenesisConfig::from_json(&round_tripped_json).unwrap();
        assert_eq!(cfg2.validator_bonding.unwrap().min_bond_amount, Some(2_500_000));

        let cfg_no_override = GenesisConfig::from_json(minimal_genesis_json()).unwrap();
        let no_override_json = cfg_no_override.to_json_pretty().unwrap();
        assert!(
            !no_override_json.contains("validator_bonding"),
            "omitted validator_bonding must not round-trip as an explicit null"
        );
    }

    #[test]
    fn validator_bonding_rejects_zero_min_bond_amount() {
        let json = minimal_genesis_json().replace(
            r#""modules": ["bank", "staking"],"#,
            r#""modules": ["bank", "staking"],
            "validator_bonding": { "min_bond_amount": 0 },"#,
        );
        let cfg = GenesisConfig::from_json(&json).unwrap();
        let err = cfg.validate_validator_bonding().expect_err("a zero minimum bond must be rejected");
        assert!(err.contains("min_bond_amount"), "{err}");
    }

    #[test]
    fn validator_bonding_rejects_zero_epoch_blocks() {
        let json = minimal_genesis_json().replace(
            r#""modules": ["bank", "staking"],"#,
            r#""modules": ["bank", "staking"],
            "validator_bonding": { "validator_epoch_blocks": 0 },"#,
        );
        let cfg = GenesisConfig::from_json(&json).unwrap();
        let err = cfg.validate_validator_bonding().expect_err("zero validator_epoch_blocks must be rejected (division by zero)");
        assert!(err.contains("validator_epoch_blocks"), "{err}");
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

// ── Workspace boundary ────────────────────────────────────────────────────────
//
// ValidatorId and ValidatorSetView live here so boundary crates such as
// chain-forge-personhood can depend on just this crate rather than the full
// chain-forge-consensus crate.

use std::fmt;

/// Opaque identifier for a validator.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash,
         serde::Serialize, serde::Deserialize)]
pub struct ValidatorId(pub String);

impl fmt::Display for ValidatorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Read-only view of a validator set — sufficient for quorum and key lookups.
///
/// Implemented by `chain_forge_consensus::ValidatorSet` and by test stubs.
/// Personhood and other crates accept `&dyn ValidatorSetView` so they don't
/// need to import the full consensus crate.
pub trait ValidatorSetView: Send + Sync {
    /// Sum of all validators' voting power.
    fn total_power(&self) -> u64;

    /// Minimum power that constitutes a quorum (2/3 * total_power + 1).
    fn quorum_power(&self) -> u64;

    /// Voting power of one validator; 0 if unknown.
    fn power_of(&self, id: &ValidatorId) -> u64;

    /// ML-DSA public key bytes for a validator; None if unknown.
    fn public_key_of(&self, id: &ValidatorId) -> Option<&[u8]>;

    /// All validator IDs in this set (order unspecified, owned for type safety).
    fn validator_ids(&self) -> Vec<ValidatorId>;
}

// ── Consensus primitive types ─────────────────────────────────────────────────
//
// BlockHeight, ValidatorInfo, and ValidatorSet live here (alongside ValidatorId)
// so that crates like chain-forge-vca-pq can depend on just chain-forge-core
// rather than creating a cycle through chain-forge-consensus.
//
// chain-forge-consensus re-exports these as `pub use chain_forge_core::*`.

/// Monotonically increasing block height. Genesis = 0.
pub type BlockHeight = u64;

/// A single validator's participation parameters at a given height.
///
/// `voting_power` is a relative weight. For QCB personhood-weighted BFT,
/// `chain-forge-vca-pq` computes and overwrites this field at epoch
/// boundaries so the consensus engine uses VCA-derived weights.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ValidatorInfo {
    pub id:           ValidatorId,
    pub voting_power: u64,
    /// Whether this validator holds a valid proof-of-personhood credential.
    pub pop_verified: bool,
    /// Ed25519 (or ML-DSA PQ) public key bytes.
    pub public_key:   Vec<u8>,
}

/// A snapshot of all active validators at a particular block height.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ValidatorSet {
    pub height:     BlockHeight,
    pub validators: Vec<ValidatorInfo>,
}

impl ValidatorSet {
    /// Total voting power across all validators.
    pub fn total_power(&self) -> u64 {
        self.validators.iter().map(|v| v.voting_power).sum()
    }

    /// Classical BFT safety threshold: floor(2n/3) + 1 of total power.
    pub fn quorum_power(&self) -> u64 {
        let total = self.total_power();
        (total * 2 / 3) + 1
    }

    /// Voting power for a specific validator; 0 if not in this set.
    pub fn power_of(&self, id: &ValidatorId) -> u64 {
        self.validators.iter()
            .find(|v| &v.id == id)
            .map(|v| v.voting_power)
            .unwrap_or(0)
    }

    /// Ed25519 public key for a validator. Empty slice if not registered.
    pub fn public_key_of(&self, id: &ValidatorId) -> &[u8] {
        self.validators.iter()
            .find(|v| &v.id == id)
            .map(|v| v.public_key.as_slice())
            .unwrap_or(&[])
    }

    /// True if the given map of (validator → power) meets the quorum.
    pub fn has_quorum(&self, votes: &std::collections::BTreeMap<ValidatorId, u64>) -> bool {
        let voted: u64 = votes.values().sum();
        voted >= self.quorum_power()
    }

    /// Number of Byzantine validators the set can tolerate (floor(n/3) - 1).
    pub fn byzantine_fault_tolerance(&self) -> usize {
        let n = self.validators.len();
        if n < 4 { 0 } else { n / 3 - 1 }
    }
}

impl ValidatorSetView for ValidatorSet {
    fn total_power(&self) -> u64 { self.total_power() }
    fn quorum_power(&self) -> u64 { self.quorum_power() }
    fn power_of(&self, id: &ValidatorId) -> u64 { self.power_of(id) }
    fn public_key_of(&self, id: &ValidatorId) -> Option<&[u8]> {
        let s = ValidatorSet::public_key_of(self, id);
        if s.is_empty() { None } else { Some(s) }
    }
    fn validator_ids(&self) -> Vec<ValidatorId> {
        self.validators.iter().map(|v| v.id.clone()).collect()
    }
}
