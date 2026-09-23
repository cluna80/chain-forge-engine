/// chain-forge-state
///
/// Merkle state tree and account balance layer for Chain Forge.
///
/// What lives here:
///   - AccountState: balance + nonce per address
///   - StateStore: the canonical in-memory state trie
///   - MerkleNode / StateRoot: Jellyfish Merkle Tree (JMT) implementation
///     sufficient for Phase 0 testnet (full JMT optimisations are a TODO)
///   - GenesisState: seeds initial balances from the wizard's genesis config
///   - Snapshot: immutable state at a given block height for sync/rollback
///
/// Whitepaper refs:
///   - Section 6.2 ($CIRFI balance tracking, demurrage)
///   - Section 6.3 ($QCB balance tracking, BME burns)
///   - Section 7.6 (Chain Forge state layer, JMT)
///   - Open Question 4 (reserve strategy / stability backing)

use std::collections::{BTreeMap, HashMap};
use serde::{Deserialize, Serialize};
use chain_forge_core::{ChainHash, GenesisConfig, HashWidth};
use chain_forge_identity::IntrinsicCharm;

// -- Error --------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("account {0} not found")]
    AccountNotFound(String),

    #[error("insufficient balance: account {account} has {have} but {need} required")]
    InsufficientBalance { account: String, have: u128, need: u128 },

    #[error("nonce mismatch: account {account} expects {expected} but got {got}")]
    NonceMismatch { account: String, expected: u64, got: u64 },

    #[error("genesis error: {0}")]
    GenesisError(String),

    #[error("snapshot at height {0} not found")]
    SnapshotNotFound(u64),

    #[error("state root mismatch: expected {expected}, computed {computed}")]
    RootMismatch { expected: String, computed: String },

    #[error("internal state error: {0}")]
    Internal(String),
}

pub type StateResult<T> = Result<T, StateError>;

// -- Account state ------------------------------------------------------------

/// The on-chain state for a single account.
/// Balances are stored as u128 to avoid overflow on large supplies.
/// The denom is stored per-account so multi-token chains work naturally.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountState {
    pub address: String,
    /// Balances keyed by token denom (e.g. "uqcb", "ucirfi").
    pub balances: BTreeMap<String, u128>,
    /// Transaction nonce. Prevents replay attacks.
    pub nonce: u64,
    /// Account role from genesis (validator/treasury/faucet/user).
    /// Informational only -- enforcement is the governance layer's job.
    pub role: String,
    /// IntrinsicCharm: verification tier, decay-exemption credits, liveness.
    /// Whitepaper Section 5.2: "properties treated as inherent to a piece of
    /// state or identity, traveling with it rather than being externally assigned."
    /// None for non-human accounts (treasury, faucet, agent accounts).
    pub charm: Option<IntrinsicCharm>,
    /// Ed25519 public key bound to this account. Set from genesis, or bound
    /// by the executor on the account's first successful signed transaction
    /// (only possible when the address is derived from that key). Once set,
    /// every transaction from this account must be signed by this key.
    #[serde(default)]
    pub public_key: Option<Vec<u8>>,
}

impl AccountState {
    pub fn new(address: String, role: String) -> Self {
        Self {
            address,
            balances: BTreeMap::new(),
            nonce: 0,
            role,
            charm: None,
            public_key: None,
        }
    }

    /// Create a human account with IntrinsicCharm attached.
    /// Used when a verified human account is created at genesis or
    /// when an account is first linked to an identity (Section 5.2).
    pub fn new_human(address: String, role: String, current_epoch: u64) -> Self {
        Self {
            address,
            balances: BTreeMap::new(),
            nonce: 0,
            role,
            charm: Some(IntrinsicCharm::provisional(current_epoch)),
            public_key: None,
        }
    }

    /// Attach an IntrinsicCharm to an existing account.
    /// Called when an account is linked to a verified identity.
    pub fn attach_charm(&mut self, charm: IntrinsicCharm) {
        self.charm = Some(charm);
    }

    /// Whether this account has a verified identity attached (Section 5.2).
    pub fn is_human(&self) -> bool {
        self.charm.as_ref()
            .map(|c| c.tier.grants_full_ubi())
            .unwrap_or(false)
    }

    /// Current verification tier. None for non-human accounts.
    pub fn verification_tier(&self) -> Option<&chain_forge_identity::VerificationTier> {
        self.charm.as_ref().map(|c| &c.tier)
    }

    /// Decay-exemption days remaining. 0 for non-human accounts.
    pub fn exemption_days(&self) -> u32 {
        self.charm.as_ref()
            .map(|c| c.decay_exemption.days)
            .unwrap_or(0)
    }

    /// Record a spend for decay-exemption tracking (Section 6.2).
    /// Only applies to human accounts with charm attached.
    pub fn record_spend_for_exemption(&mut self, epoch: u64) {
        if let Some(charm) = &mut self.charm {
            charm.decay_exemption.record_spend(epoch);
        }
    }

    /// Record participation for liveness tracking (Q24).
    pub fn record_participation(&mut self, epoch: u64) {
        if let Some(charm) = &mut self.charm {
            charm.record_participation(epoch);
        }
    }

    /// Balance for a specific denom. Returns 0 if not held.
    pub fn balance_of(&self, denom: &str) -> u128 {
        self.balances.get(denom).copied().unwrap_or(0)
    }

    /// Credit an amount. Saturates at u128::MAX (practically unreachable).
    pub fn credit(&mut self, denom: &str, amount: u128) {
        *self.balances.entry(denom.to_string()).or_insert(0) += amount;
    }

    /// Debit an amount. Returns Err if balance is insufficient.
    pub fn debit(&mut self, denom: &str, amount: u128) -> StateResult<()> {
        let bal = self.balance_of(denom);
        if bal < amount {
            return Err(StateError::InsufficientBalance {
                account: self.address.clone(),
                have: bal,
                need: amount,
            });
        }
        *self.balances.get_mut(denom).unwrap() -= amount;
        Ok(())
    }

    /// Increment nonce after a transaction is accepted.
    pub fn increment_nonce(&mut self) {
        self.nonce += 1;
    }

    /// Canonical byte serialisation for Merkle hashing.
    /// Format: address|nonce|tier|denom1=bal1|denom2=bal2|...
    /// BTreeMap iteration is sorted so this is deterministic.
    /// IntrinsicCharm tier is included so identity changes affect state root.
    pub fn to_leaf_bytes(&self) -> Vec<u8> {
        let tier_str = self.charm.as_ref()
            .map(|c| c.tier.to_string())
            .unwrap_or_else(|| "none".to_string());
        let mut parts = vec![
            self.address.clone(),
            self.nonce.to_string(),
            tier_str,
        ];
        for (denom, bal) in &self.balances {
            parts.push(format!("{denom}={bal}"));
        }
        // Key binding is consensus state: nodes must agree which key controls
        // an account. Appended only when present, so accounts without a
        // bound key keep exactly the leaf bytes (and state roots) they had.
        if let Some(pk) = &self.public_key {
            let hex: String = pk.iter().map(|b| format!("{b:02x}")).collect();
            parts.push(format!("pk={hex}"));
        }
        parts.join("|").into_bytes()
    }
}

/// Decode a hex string (even length, 0-9a-fA-F). None on any malformed input.
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 { return None; }
    (0..s.len()).step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

// -- Merkle state tree (Phase 0 JMT) -----------------------------------------

/// A Merkle leaf: the hash of one account's canonical bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleLeaf {
    pub key:  String,    // account address
    pub hash: String,    // hex hash of leaf bytes
}

/// A Phase-0 Jellyfish Merkle Tree node.
/// Full JMT uses prefix-compressed sparse tries; this implementation uses
/// a simple sorted-leaf Merkle tree which gives correct state roots and
/// proofs at the cost of O(n) updates. Good enough for testnet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleTree {
    pub leaves: Vec<MerkleLeaf>,   // sorted by key
    pub root:   Option<String>,    // hex root hash; None for empty tree
    pub width:  HashWidth,
}

impl MerkleTree {
    pub fn new(width: HashWidth) -> Self {
        Self { leaves: Vec::new(), root: None, width }
    }

    /// Insert or update a leaf. Recomputes the root immediately.
    pub fn upsert(&mut self, key: String, leaf_bytes: &[u8]) {
        let hash = ChainHash::digest(leaf_bytes, self.width).to_hex();
        match self.leaves.binary_search_by_key(&key.as_str(), |l| l.key.as_str()) {
            Ok(idx)  => self.leaves[idx].hash = hash,
            Err(idx) => self.leaves.insert(idx, MerkleLeaf { key, hash }),
        }
        self.recompute_root();
    }

    /// Remove a leaf. Recomputes root.
    pub fn remove(&mut self, key: &str) {
        if let Ok(idx) = self.leaves.binary_search_by_key(&key, |l| l.key.as_str()) {
            self.leaves.remove(idx);
            self.recompute_root();
        }
    }

    /// Recompute the Merkle root from current leaves.
    /// Uses a standard binary Merkle tree reduction.
    fn recompute_root(&mut self) {
        if self.leaves.is_empty() {
            self.root = None;
            return;
        }

        // Start with leaf hashes
        let mut level: Vec<Vec<u8>> = self.leaves
            .iter()
            .map(|l| ChainHash::from_hex(&l.hash).unwrap_or_else(|_| ChainHash::zero(self.width)).as_bytes().to_vec())
            .collect();

        // Reduce pairwise until we reach the root
        while level.len() > 1 {
            let mut next = Vec::new();
            let mut i = 0;
            while i < level.len() {
                if i + 1 < level.len() {
                    let combined = ChainHash::digest2(&level[i], &level[i+1], self.width);
                    next.push(combined.as_bytes().to_vec());
                } else {
                    // Odd leaf: hash it with itself (standard practice)
                    let combined = ChainHash::digest2(&level[i], &level[i], self.width);
                    next.push(combined.as_bytes().to_vec());
                }
                i += 2;
            }
            level = next;
        }

        self.root = Some(ChainHash::from_hex(
            &level[0].iter().map(|b| format!("{b:02x}")).collect::<String>()
        ).unwrap_or_else(|_| ChainHash::zero(self.width)).to_hex());
    }

    pub fn root_hex(&self) -> Option<&str> {
        self.root.as_deref()
    }
}

// -- State root ---------------------------------------------------------------

/// The committed state root at a given block height.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateRoot {
    pub height:    u64,
    pub root_hash: String,   // hex
    pub timestamp_ms: u64,
}

// -- Snapshot -----------------------------------------------------------------

/// An immutable snapshot of the full account state at a given height.
/// Used for sync (new nodes can fast-sync to a recent snapshot) and
/// for rollback if a block is rejected post-execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSnapshot {
    pub height:    u64,
    pub root_hash: String,
    pub accounts:  HashMap<String, AccountState>,
}

// -- State store --------------------------------------------------------------

/// The canonical, mutable state of the chain.
///
/// Holds all account states in memory (Phase 0 — persistence via WAL/RocksDB
/// is a later phase). After each block commits, the Merkle tree is updated
/// and a new StateRoot is recorded.
pub struct StateStore {
    accounts:  HashMap<String, AccountState>,
    tree:      MerkleTree,
    roots:     Vec<StateRoot>,
    height:    u64,
    width:     HashWidth,
    /// Snapshots keyed by height. Kept for the last N blocks.
    snapshots: BTreeMap<u64, StateSnapshot>,
    max_snapshots: usize,
}

impl StateStore {
    pub fn new(width: HashWidth) -> Self {
        Self {
            accounts:      HashMap::new(),
            tree:          MerkleTree::new(width),
            roots:         Vec::new(),
            height:        0,
            width,
            snapshots:     BTreeMap::new(),
            max_snapshots: 128,
        }
    }

    /// Seed the state from a genesis config.
    /// Called once at chain startup before any blocks are processed.
    pub fn apply_genesis(&mut self, genesis: &GenesisConfig) -> StateResult<()> {
        let denom = genesis.native_token.denom.clone();

        for acct in &genesis.genesis_accounts {
            let amount: u128 = acct.balance.parse().map_err(|_| {
                StateError::GenesisError(format!(
                    "invalid balance for {}: {}",
                    acct.label, acct.balance
                ))
            })?;

            let mut state = AccountState::new(acct.address.clone(), acct.role.clone());
            state.credit(&denom, amount);
            if let Some(hex) = &acct.public_key {
                state.public_key = Some(decode_hex(hex).ok_or_else(|| StateError::GenesisError(
                    format!("invalid public_key hex for {}", acct.label)
                ))?);
            }
            self.upsert_account(state);
        }

        tracing::info!(
            accounts = self.accounts.len(),
            denom,
            "genesis state applied"
        );
        Ok(())
    }

    /// Insert or replace an account state and update the Merkle tree.
    pub fn upsert_account(&mut self, account: AccountState) {
        let leaf_bytes = account.to_leaf_bytes();
        self.tree.upsert(account.address.clone(), &leaf_bytes);
        self.accounts.insert(account.address.clone(), account);
    }

    /// Get an account by address.
    pub fn get_account(&self, address: &str) -> StateResult<&AccountState> {
        self.accounts.get(address)
            .ok_or_else(|| StateError::AccountNotFound(address.to_string()))
    }

    /// Get a mutable account by address.
    pub fn get_account_mut(&mut self, address: &str) -> StateResult<&mut AccountState> {
        self.accounts.get_mut(address)
            .ok_or_else(|| StateError::AccountNotFound(address.to_string()))
    }

    /// Recompute an account's Merkle leaf after it was mutated in place via
    /// get_account_mut. Without this, in-place changes (nonce, bound key,
    /// charm) never reach the state root: only transfer, burn and
    /// upsert_account refresh leaves themselves. No-op if absent.
    pub fn refresh_leaf(&mut self, address: &str) {
        if let Some(acct) = self.accounts.get(address) {
            let leaf = acct.to_leaf_bytes();
            self.tree.upsert(address.to_string(), &leaf);
        }
    }

    /// Transfer tokens between accounts.
    pub fn transfer(
        &mut self,
        from:   &str,
        to:     &str,
        denom:  &str,
        amount: u128,
    ) -> StateResult<()> {
        // Check sender exists and has sufficient balance before mutating.
        {
            let sender = self.get_account(from)?;
            let bal = sender.balance_of(denom);
            if bal < amount {
                return Err(StateError::InsufficientBalance {
                    account: from.to_string(),
                    have: bal,
                    need: amount,
                });
            }
        }

        // Debit sender
        {
            let sender = self.get_account_mut(from)?;
            sender.debit(denom, amount)?;
            sender.increment_nonce();
            let leaf = sender.to_leaf_bytes();
            let addr = sender.address.clone();
            self.tree.upsert(addr, &leaf);
        }

        // Credit receiver (create account if it doesn't exist)
        if !self.accounts.contains_key(to) {
            let new_acct = AccountState::new(to.to_string(), "user".to_string());
            self.upsert_account(new_acct);
        }
        {
            let receiver = self.get_account_mut(to)?;
            receiver.credit(denom, amount);
            let leaf = receiver.to_leaf_bytes();
            let addr = receiver.address.clone();
            self.tree.upsert(addr, &leaf);
        }

        Ok(())
    }

    /// Burn tokens (remove from supply permanently). Used by BME mechanism.
    /// Whitepaper Section 6.3: merchant fees buy and burn $QCB.
    pub fn burn(&mut self, address: &str, denom: &str, amount: u128) -> StateResult<()> {
        let account = self.get_account_mut(address)?;
        account.debit(denom, amount)?;
        account.increment_nonce();
        let leaf = account.to_leaf_bytes();
        let addr = account.address.clone();
        self.tree.upsert(addr, &leaf);
        tracing::info!(address, denom, amount, "tokens burned (BME)");
        Ok(())
    }

    /// Commit the current state after a block.
    /// Records the state root and optionally takes a snapshot.
    pub fn commit(&mut self, height: u64, timestamp_ms: u64, take_snapshot: bool) -> StateRoot {
        let root_hash = self.tree.root_hex()
            .unwrap_or("0000000000000000")
            .to_string();

        let root = StateRoot { height, root_hash: root_hash.clone(), timestamp_ms };
        self.roots.push(root.clone());
        self.height = height;

        if take_snapshot {
            let snap = StateSnapshot {
                height,
                root_hash,
                accounts: self.accounts.clone(),
            };
            self.snapshots.insert(height, snap);

            // Prune old snapshots beyond the max
            while self.snapshots.len() > self.max_snapshots {
                if let Some(oldest_key) = self.snapshots.keys().next().copied() {
                    self.snapshots.remove(&oldest_key);
                }
            }
        }

        tracing::debug!(height, root_hash = %self.roots.last().unwrap().root_hash, "state committed");
        root
    }

    /// Get the latest state root.
    pub fn latest_root(&self) -> Option<&StateRoot> {
        self.roots.last()
    }

    /// Get a historical snapshot for sync.
    pub fn snapshot_at(&self, height: u64) -> StateResult<&StateSnapshot> {
        self.snapshots.get(&height)
            .ok_or(StateError::SnapshotNotFound(height))
    }

    /// Restore state from a snapshot (used during fast-sync).
    pub fn restore_snapshot(&mut self, snapshot: StateSnapshot) {
        self.accounts = snapshot.accounts.clone();
        // Rebuild the Merkle tree from restored accounts
        self.tree = MerkleTree::new(self.width);
        for account in self.accounts.values() {
            let leaf = account.to_leaf_bytes();
            self.tree.upsert(account.address.clone(), &leaf);
        }
        self.height = snapshot.height;
        tracing::info!(height = snapshot.height, "state restored from snapshot");
    }

    /// Iterator over all accounts in the store.
    pub fn all_accounts(&self) -> impl Iterator<Item = &AccountState> {
        self.accounts.values()
    }

    pub fn account_count(&self) -> usize {
        self.accounts.len()
    }

    pub fn current_height(&self) -> u64 {
        self.height
    }

    pub fn current_root(&self) -> Option<&str> {
        self.tree.root_hex()
    }
}

// -- Tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chain_forge_core::{GenesisConfig, HashWidth};

    fn genesis_json() -> &'static str {
        r#"{
            "chain_id": "qcb-testnet-1",
            "chain_name": "QuarkCharmBit",
            "engine_version": "0.1.0",
            "genesis_time": "2026-09-16T00:00:00Z",
            "environment": { "mode": "testnet", "faucet_enabled": true, "relaxed_limits": true },
            "native_token": { "name": "QuarkCharm", "symbol": "QCB", "denom": "uqcb", "max_supply": "210000000" },
            "address_prefix": "qcb",
            "consensus": { "type": "proof-of-stake", "validator_set_size": 4, "block_time_ms": 5000 },
            "execution": { "state_model": "account", "parallel_execution": false, "gas_model": "dynamic" },
            "cryptography": { "signature_scheme": "hybrid", "pqc_algorithm": "ml-dsa", "migration_trigger": "nist-guidance", "hash_width": 256, "validator_scheme": "pqc-native" },
            "network": { "network_id": "qcb-testnet-1-net", "p2p_port": 26656, "rpc_port": 26657, "bootstrap_nodes": [], "peer_discovery": "both", "max_peers": 50 },
            "limits": { "max_block_bytes": 1048576, "max_tx_bytes": 65536, "block_gas_limit": 10000000, "mempool_size": 5000, "mempool_ttl_seconds": 300 },
            "modules": ["bank", "staking"],
            "custom_modules": [],
            "genesis_accounts": [
                { "label": "Validator 1", "address": "qcb1validator", "balance": "1000000", "role": "validator" },
                { "label": "Treasury",    "address": "qcb1treasury",  "balance": "9000000", "role": "treasury"  }
            ]
        }"#
    }

    fn make_store() -> StateStore {
        StateStore::new(HashWidth::Bits256)
    }

    #[test]
    fn account_credit_and_debit() {
        let mut acct = AccountState::new("qcb1test".into(), "user".into());
        acct.credit("uqcb", 1_000_000);
        assert_eq!(acct.balance_of("uqcb"), 1_000_000);

        acct.debit("uqcb", 400_000).unwrap();
        assert_eq!(acct.balance_of("uqcb"), 600_000);
    }

    #[test]
    fn debit_rejects_insufficient_balance() {
        let mut acct = AccountState::new("qcb1test".into(), "user".into());
        acct.credit("uqcb", 100);
        assert!(acct.debit("uqcb", 200).is_err());
    }

    #[test]
    fn nonce_increments_on_debit() {
        let mut acct = AccountState::new("qcb1test".into(), "user".into());
        acct.credit("uqcb", 1000);
        assert_eq!(acct.nonce, 0);
        acct.debit("uqcb", 100).unwrap();
        // Note: debit alone does not increment nonce -- the store does via
        // increment_nonce(). Here we call it manually.
        acct.increment_nonce();
        assert_eq!(acct.nonce, 1);
    }

    #[test]
    fn refresh_leaf_makes_in_place_changes_reach_the_root() {
        let mut s = StateStore::new(HashWidth::Bits256);
        s.upsert_account(AccountState::new("qcb1abc".into(), "user".into()));
        let before = s.tree.root_hex().unwrap().to_string();

        s.get_account_mut("qcb1abc").unwrap().public_key = Some(vec![1, 2, 3]);
        assert_eq!(s.tree.root_hex().unwrap(), before, "in-place edit alone is invisible to the root");

        s.refresh_leaf("qcb1abc");
        assert_ne!(s.tree.root_hex().unwrap(), before, "refresh_leaf must fold it into the root");
    }

    #[test]
    fn bound_public_key_is_part_of_leaf_bytes() {
        let mut a = AccountState::new("qcb1abc".into(), "user".into());
        let before = a.to_leaf_bytes();
        a.public_key = Some(vec![0xab, 0xcd]);
        let after = a.to_leaf_bytes();
        assert_ne!(before, after, "binding a key must change the state root");
        assert!(String::from_utf8(after).unwrap().ends_with("|pk=abcd"));
    }

    #[test]
    fn decode_hex_rejects_malformed_input() {
        assert_eq!(decode_hex("0aff"), Some(vec![0x0a, 0xff]));
        assert_eq!(decode_hex("abc"), None);
        assert_eq!(decode_hex("zz"), None);
    }

    #[test]
    fn leaf_bytes_are_deterministic() {
        let mut a = AccountState::new("qcb1abc".into(), "user".into());
        a.credit("uqcb", 500);
        let b1 = a.to_leaf_bytes();
        let b2 = a.to_leaf_bytes();
        assert_eq!(b1, b2);
    }

    #[test]
    fn merkle_root_changes_on_update() {
        let mut tree = MerkleTree::new(HashWidth::Bits256);
        tree.upsert("qcb1a".into(), b"account_a_data");
        let root1 = tree.root_hex().unwrap().to_string();

        tree.upsert("qcb1b".into(), b"account_b_data");
        let root2 = tree.root_hex().unwrap().to_string();

        assert_ne!(root1, root2, "root should change when a leaf is added");
    }

    #[test]
    fn merkle_root_is_deterministic() {
        let mut t1 = MerkleTree::new(HashWidth::Bits256);
        let mut t2 = MerkleTree::new(HashWidth::Bits256);

        for (key, data) in [("qcb1a", b"data_a" as &[u8]), ("qcb1b", b"data_b")] {
            t1.upsert(key.into(), data);
            t2.upsert(key.into(), data);
        }

        assert_eq!(t1.root_hex(), t2.root_hex(), "same leaves must produce same root");
    }

    #[test]
    fn merkle_root_changes_on_removal() {
        let mut tree = MerkleTree::new(HashWidth::Bits256);
        tree.upsert("qcb1a".into(), b"data_a");
        tree.upsert("qcb1b".into(), b"data_b");
        let root_before = tree.root_hex().unwrap().to_string();

        tree.remove("qcb1b");
        let root_after = tree.root_hex().unwrap().to_string();

        assert_ne!(root_before, root_after);
    }

    #[test]
    fn genesis_seeds_balances_correctly() {
        let genesis = GenesisConfig::from_json(genesis_json()).unwrap();
        let mut store = make_store();
        store.apply_genesis(&genesis).unwrap();

        assert_eq!(store.account_count(), 2);

        let validator = store.get_account("qcb1validator").unwrap();
        assert_eq!(validator.balance_of("uqcb"), 1_000_000);
        assert_eq!(validator.role, "validator");

        let treasury = store.get_account("qcb1treasury").unwrap();
        assert_eq!(treasury.balance_of("uqcb"), 9_000_000);
    }

    #[test]
    fn transfer_moves_tokens() {
        let genesis = GenesisConfig::from_json(genesis_json()).unwrap();
        let mut store = make_store();
        store.apply_genesis(&genesis).unwrap();

        store.transfer("qcb1treasury", "qcb1validator", "uqcb", 500_000).unwrap();

        assert_eq!(store.get_account("qcb1treasury").unwrap().balance_of("uqcb"), 8_500_000);
        assert_eq!(store.get_account("qcb1validator").unwrap().balance_of("uqcb"), 1_500_000);
    }

    #[test]
    fn transfer_creates_new_account() {
        let genesis = GenesisConfig::from_json(genesis_json()).unwrap();
        let mut store = make_store();
        store.apply_genesis(&genesis).unwrap();

        store.transfer("qcb1treasury", "qcb1newuser", "uqcb", 100_000).unwrap();

        let new_acct = store.get_account("qcb1newuser").unwrap();
        assert_eq!(new_acct.balance_of("uqcb"), 100_000);
    }

    #[test]
    fn transfer_rejects_insufficient_funds() {
        let genesis = GenesisConfig::from_json(genesis_json()).unwrap();
        let mut store = make_store();
        store.apply_genesis(&genesis).unwrap();

        let result = store.transfer("qcb1validator", "qcb1treasury", "uqcb", 999_999_999);
        assert!(result.is_err());
    }

    #[test]
    fn burn_reduces_supply() {
        let genesis = GenesisConfig::from_json(genesis_json()).unwrap();
        let mut store = make_store();
        store.apply_genesis(&genesis).unwrap();

        store.burn("qcb1treasury", "uqcb", 1_000_000).unwrap();
        assert_eq!(store.get_account("qcb1treasury").unwrap().balance_of("uqcb"), 8_000_000);
    }

    #[test]
    fn commit_produces_state_root() {
        let genesis = GenesisConfig::from_json(genesis_json()).unwrap();
        let mut store = make_store();
        store.apply_genesis(&genesis).unwrap();

        let root = store.commit(1, 1_000_000, false);
        assert_eq!(root.height, 1);
        assert!(!root.root_hash.is_empty());
        assert!(store.latest_root().is_some());
    }

    #[test]
    fn state_root_changes_after_transfer() {
        let genesis = GenesisConfig::from_json(genesis_json()).unwrap();
        let mut store = make_store();
        store.apply_genesis(&genesis).unwrap();

        let root1 = store.commit(1, 1_000, false).root_hash;
        store.transfer("qcb1treasury", "qcb1validator", "uqcb", 1).unwrap();
        let root2 = store.commit(2, 2_000, false).root_hash;

        assert_ne!(root1, root2, "state root must change after a transfer");
    }

    #[test]
    fn snapshot_and_restore() {
        let genesis = GenesisConfig::from_json(genesis_json()).unwrap();
        let mut store = make_store();
        store.apply_genesis(&genesis).unwrap();

        let root1 = store.commit(1, 1_000, true);

        // Modify state after snapshot
        store.transfer("qcb1treasury", "qcb1validator", "uqcb", 500_000).unwrap();
        store.commit(2, 2_000, false);

        // Restore snapshot at height 1
        let snap = store.snapshot_at(1).unwrap().clone();
        store.restore_snapshot(snap);

        // State should be back to genesis balances
        assert_eq!(
            store.get_account("qcb1treasury").unwrap().balance_of("uqcb"),
            9_000_000
        );
        assert_eq!(store.current_height(), 1);
        assert_eq!(store.current_root().unwrap(), root1.root_hash);
    }

    #[test]
    fn multi_denom_balances() {
        let mut store = make_store();
        let mut acct = AccountState::new("qcb1multi".into(), "user".into());
        acct.credit("uqcb",   1_000_000);
        acct.credit("ucirfi", 500_000);
        store.upsert_account(acct);

        let a = store.get_account("qcb1multi").unwrap();
        assert_eq!(a.balance_of("uqcb"),   1_000_000);
        assert_eq!(a.balance_of("ucirfi"), 500_000);
        assert_eq!(a.balance_of("uother"), 0);
    }

    // -- IntrinsicCharm integration tests ------------------------------------

    #[test]
    fn new_account_has_no_charm() {
        let acct = AccountState::new("qcb1plain".into(), "user".into());
        assert!(acct.charm.is_none());
        assert!(!acct.is_human());
        assert_eq!(acct.exemption_days(), 0);
        assert!(acct.verification_tier().is_none());
    }

    #[test]
    fn human_account_has_charm() {
        let acct = AccountState::new_human("qcb1human".into(), "user".into(), 0);
        assert!(acct.charm.is_some());
        assert!(!acct.is_human()); // Provisional -- not yet Verified
        assert_eq!(acct.exemption_days(), 0);
    }

    #[test]
    fn attach_charm_makes_account_human() {
        use chain_forge_identity::IntrinsicCharm;
        let mut acct = AccountState::new("qcb1acct".into(), "user".into());
        assert!(!acct.is_human());

        let mut charm = IntrinsicCharm::provisional(0);
        charm.verify(1); // upgrade to Verified
        acct.attach_charm(charm);

        assert!(acct.is_human());
        assert_eq!(
            acct.verification_tier(),
            Some(&chain_forge_identity::VerificationTier::Verified)
        );
    }

    #[test]
    fn spend_earns_exemption_credit() {
        let mut acct = AccountState::new_human("qcb1human".into(), "user".into(), 0);
        assert_eq!(acct.exemption_days(), 0);

        acct.record_spend_for_exemption(1);
        assert_eq!(acct.exemption_days(), 1);

        acct.record_spend_for_exemption(2);
        assert_eq!(acct.exemption_days(), 2);
    }

    #[test]
    fn non_human_account_ignores_spend_exemption() {
        let mut acct = AccountState::new("qcb1treasury".into(), "treasury".into());
        acct.record_spend_for_exemption(1); // should be a no-op
        assert_eq!(acct.exemption_days(), 0);
    }

    #[test]
    fn charm_tier_included_in_merkle_leaf() {
        use chain_forge_identity::IntrinsicCharm;

        let acct_plain = AccountState::new("qcb1a".into(), "user".into());
        let mut acct_human = AccountState::new("qcb1a".into(), "user".into());
        let charm = IntrinsicCharm::provisional(0);
        acct_human.attach_charm(charm);

        // Same address + nonce + balances but different charm tier
        // -> different leaf bytes -> different Merkle contribution
        assert_ne!(
            acct_plain.to_leaf_bytes(),
            acct_human.to_leaf_bytes(),
            "charm tier must affect Merkle leaf bytes"
        );
    }

    #[test]
    fn state_root_changes_on_verification() {
        use chain_forge_identity::IntrinsicCharm;

        let mut store = make_store();
        let mut acct = AccountState::new_human("qcb1h1".into(), "user".into(), 0);
        acct.credit("ucirfi", 1_000_000);
        store.upsert_account(acct);
        let root1 = store.commit(1, 1000, false).root_hash;

        // Verify the identity -- upgrade charm tier then re-upsert
        let mut charm = IntrinsicCharm::provisional(0);
        charm.verify(1);
        let mut updated = store.get_account("qcb1h1").unwrap().clone();
        updated.charm = Some(charm);
        store.upsert_account(updated);
        let root2 = store.commit(2, 2000, false).root_hash;

        assert_ne!(root1, root2,
            "state root must change when identity tier changes");
    }
}
