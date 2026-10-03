/// Jellyfish Merkle Tree (JMT) — production-grade sparse state trie.
///
/// Architecture
/// ────────────
/// The JMT is a sparse binary Merkle trie over a 256-bit key space.
/// Keys are SHA3-256(account_address) — a 32-byte path into the trie.
///
/// Nodes
/// ─────
/// Each node is one of:
///   Internal(left_child, right_child)   — branch on the next bit of the key
///   Leaf(key_suffix, value_hash)        — compressed path leaf
///   Null                                — absent subtree (hashes to ZERO)
///
/// This matches the original JMT paper (Ateniese et al., Diem/Aptos lineage)
/// with path-compression on leaf nodes, so the tree depth equals the number
/// of bits shared between keys — typically much less than 256.
///
/// Root hashing
/// ────────────
/// The root hash commits to the full key-value mapping:
///   H(Internal) = SHA3(0x01 || H(left) || H(right))
///   H(Leaf)     = SHA3(0x00 || key_path[32] || value_hash[32])
///   H(Null)     = 0x00..00 (32 zero bytes)
///
/// Proofs
/// ──────
/// An inclusion proof for key K is the sibling hashes along the path from
/// root to K's leaf, in root-to-leaf order.
/// A non-inclusion proof is an inclusion proof for the nearest existing leaf
/// (or a null subtree), proving K would live there but doesn't.
///
/// Versioning
/// ──────────
/// The NodeStore holds nodes keyed by (version, NodeKey).  After a batch
/// write the version counter increments.  Old versions are kept until
/// explicitly pruned, enabling O(1) rollback by moving the `current_version`
/// pointer.  This mirrors the Diem/Aptos JMT node-cache design.
///
/// Batch writes
/// ────────────
/// `JmtWriter` collects (key, value_bytes) pairs and flushes them to the
/// store atomically.  The root is computed exactly once per flush, not once
/// per key.  This is the critical performance property for block execution:
/// processing 10 000 transfers per block costs ~10 000 × O(depth) hash ops
/// with a single root recomputation at the end.
///
/// WAL entries
/// ───────────
/// Every flush appends a `WriteAheadEntry` to the WAL buffer.  The buffer is
/// in-memory here; a persistence layer plugs in by draining it to RocksDB or
/// a flat file.  The WAL is append-only and sequenced by version, so crash
/// recovery replays entries in order to rebuild the node store.

use std::collections::BTreeMap;
use sha3::{Sha3_256, Digest};
use serde::{Deserialize, Serialize};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Domain separator for Internal nodes.
const TAG_INTERNAL: u8 = 0x01;
/// Domain separator for Leaf nodes.
const TAG_LEAF:     u8 = 0x00;
/// Domain separator for value hashing (H(value_bytes) before storing in leaf).
const TAG_VALUE:    u8 = 0x02;

// ── Hash primitives ───────────────────────────────────────────────────────────

/// A 32-byte SHA3-256 hash.  Used for all node and value hashes.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Hash32(pub [u8; 32]);

impl Hash32 {
    /// All-zero hash: sentinel for "null / absent" subtree.
    pub const ZERO: Hash32 = Hash32([0u8; 32]);

    pub fn is_zero(&self) -> bool { self.0 == [0u8; 32] }

    /// SHA3-256 of arbitrary bytes.
    pub fn digest(data: &[u8]) -> Self {
        let mut h = Sha3_256::new();
        h.update(data);
        let out = h.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&out);
        Hash32(arr)
    }

    /// SHA3-256 with a 1-byte domain tag prepended.
    pub fn digest_tagged(tag: u8, a: &[u8], b: &[u8]) -> Self {
        let mut h = Sha3_256::new();
        h.update([tag]);
        h.update(a);
        h.update(b);
        let out = h.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&out);
        Hash32(arr)
    }

    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    pub fn from_hex(s: &str) -> Option<Self> {
        let s = s.trim();
        if s.len() != 64 { return None; }
        let mut arr = [0u8; 32];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            let hi = hex_val(chunk[0])?;
            let lo = hex_val(chunk[1])?;
            arr[i] = (hi << 4) | lo;
        }
        Some(Hash32(arr))
    }
}

impl std::fmt::Debug for Hash32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Hash32({}…)", &self.to_hex()[..8])
    }
}

impl std::fmt::Display for Hash32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ── Key path (256-bit) ────────────────────────────────────────────────────────

/// A 256-bit trie key derived from SHA3-256(account_address).
/// Bit 0 = MSB of byte 0.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct KeyPath(pub [u8; 32]);

impl KeyPath {
    /// Derive a trie key from an account address string.
    pub fn from_address(address: &str) -> Self {
        KeyPath(Hash32::digest(address.as_bytes()).0)
    }

    /// Derive a trie key from raw bytes (useful in tests).
    pub fn from_bytes(b: &[u8]) -> Self {
        KeyPath(Hash32::digest(b).0)
    }

    /// Get bit at position `depth` (0 = MSB of byte 0).
    pub fn bit(&self, depth: usize) -> bool {
        debug_assert!(depth < 256);
        let byte = self.0[depth / 8];
        let bit  = 7 - (depth % 8);
        (byte >> bit) & 1 == 1
    }

    /// Number of common leading bits shared with `other`.
    pub fn common_prefix_len(&self, other: &KeyPath) -> usize {
        for i in 0..256 {
            if self.bit(i) != other.bit(i) {
                return i;
            }
        }
        256
    }

    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }
}

impl std::fmt::Debug for KeyPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeyPath({}…)", &self.to_hex()[..8])
    }
}

// ── Node types ────────────────────────────────────────────────────────────────

/// A node in the JMT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JmtNode {
    /// Absent subtree.  Hashes to `Hash32::ZERO`.
    Null,
    /// Compressed-path leaf.
    Leaf {
        /// Full 256-bit key (to verify suffix matches).
        key:        KeyPath,
        /// SHA3-256 of the serialised account state bytes.
        value_hash: Hash32,
    },
    /// Internal branch.
    Internal {
        left_hash:  Hash32,
        right_hash: Hash32,
    },
}

impl JmtNode {
    /// Hash of this node, used as the child pointer from its parent.
    pub fn hash(&self) -> Hash32 {
        match self {
            JmtNode::Null => Hash32::ZERO,
            JmtNode::Leaf { key, value_hash } =>
                Hash32::digest_tagged(TAG_LEAF, &key.0, &value_hash.0),
            JmtNode::Internal { left_hash, right_hash } =>
                Hash32::digest_tagged(TAG_INTERNAL, &left_hash.0, &right_hash.0),
        }
    }

    pub fn is_null(&self) -> bool { matches!(self, JmtNode::Null) }
    pub fn is_leaf(&self) -> bool { matches!(self, JmtNode::Leaf { .. }) }
}

/// Hash a raw value (account leaf bytes) before storing in the tree.
pub fn hash_value(value_bytes: &[u8]) -> Hash32 {
    Hash32::digest_tagged(TAG_VALUE, value_bytes, &[])
}

// ── Node key (version + path prefix) ─────────────────────────────────────────

/// The node store key: (version, depth, path_prefix_bytes).
/// `depth` is the bit-depth this node sits at (0 = root).
/// `path_prefix` holds the first ⌈depth/8⌉ bytes of the key path
/// with the trailing partial byte masked to `depth % 8` significant bits.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct NodeKey {
    pub version:     u64,
    pub depth:       u16,
    pub path_prefix: Vec<u8>,  // length = (depth + 7) / 8
}

impl NodeKey {
    pub fn root(version: u64) -> Self {
        NodeKey { version, depth: 0, path_prefix: vec![] }
    }

    /// Child key at `depth + 1`, taking the left (0) or right (1) branch.
    pub fn child(&self, bit: bool) -> Self {
        let new_depth = self.depth + 1;
        let mut prefix = self.path_prefix.clone();
        let byte_idx   = self.depth as usize / 8;
        let bit_idx    = 7 - (self.depth as usize % 8);

        // Ensure the byte is allocated.
        if prefix.len() <= byte_idx {
            prefix.push(0u8);
        }
        if bit {
            prefix[byte_idx] |= 1 << bit_idx;
        }
        NodeKey { version: self.version, depth: new_depth, path_prefix: prefix }
    }
}

// ── WAL entry ─────────────────────────────────────────────────────────────────

/// One write-ahead log entry per JMT version flush.
/// A persistence layer consumes these to durably record the node changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteAheadEntry {
    pub version:     u64,
    pub root_hash:   Hash32,
    /// Nodes written in this version.  The persistence layer upserts all of
    /// them into its backing store (RocksDB column family, flat file, etc.).
    pub written:     Vec<(NodeKey, JmtNode)>,
    /// Node keys that became unreachable (garbage) in this version.
    /// The persistence layer may defer deletion for safety.
    pub stale_keys:  Vec<NodeKey>,
}

// ── Proof types ───────────────────────────────────────────────────────────────

/// A single sibling hash on the path from root to a leaf.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofSibling {
    pub depth:    u16,
    pub hash:     Hash32,
}

/// Inclusion proof: proves that `key` maps to `value_hash` in the tree
/// whose root is `root_hash`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InclusionProof {
    pub root_hash:  Hash32,
    pub key:        KeyPath,
    pub value_hash: Hash32,
    /// Sibling hashes from the root to the leaf, in root→leaf order.
    pub siblings:   Vec<ProofSibling>,
}

impl InclusionProof {
    /// Verify the inclusion proof against a known root.
    pub fn verify(&self, expected_root: &Hash32) -> bool {
        if &self.root_hash != expected_root { return false; }

        // Recompute up from the leaf.
        let mut current = Hash32::digest_tagged(TAG_LEAF, &self.key.0, &self.value_hash.0);

        for sib in self.siblings.iter().rev() {
            let bit = self.key.bit(sib.depth as usize);
            current = if !bit {
                // We are left child, sibling is right.
                Hash32::digest_tagged(TAG_INTERNAL, &current.0, &sib.hash.0)
            } else {
                // We are right child, sibling is left.
                Hash32::digest_tagged(TAG_INTERNAL, &sib.hash.0, &current.0)
            };
        }
        current == self.root_hash
    }
}

/// Non-inclusion proof: proves that `key` is NOT in the tree.
/// Contains the leaf (or null) that would be displaced if `key` were inserted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NonInclusionProof {
    /// The trie position for `key` is occupied by a *different* leaf.
    /// The sibling path leads to `existing_key` ≠ `key`.
    Displaced {
        root_hash:    Hash32,
        absent_key:   KeyPath,
        existing_key: KeyPath,
        existing_value_hash: Hash32,
        siblings:     Vec<ProofSibling>,
    },
    /// The trie position for `key` is a Null subtree.
    NullSubtree {
        root_hash:  Hash32,
        absent_key: KeyPath,
        /// Depth at which the null was found.
        depth:      u16,
        siblings:   Vec<ProofSibling>,
    },
}

impl NonInclusionProof {
    pub fn verify(&self, expected_root: &Hash32) -> bool {
        match self {
            NonInclusionProof::Displaced {
                root_hash, absent_key, existing_key,
                existing_value_hash, siblings,
            } => {
                if root_hash != expected_root { return false; }
                if absent_key == existing_key  { return false; } // would be inclusion

                let mut current = Hash32::digest_tagged(
                    TAG_LEAF, &existing_key.0, &existing_value_hash.0
                );
                for sib in siblings.iter().rev() {
                    let bit = existing_key.bit(sib.depth as usize);
                    current = if !bit {
                        Hash32::digest_tagged(TAG_INTERNAL, &current.0, &sib.hash.0)
                    } else {
                        Hash32::digest_tagged(TAG_INTERNAL, &sib.hash.0, &current.0)
                    };
                }
                current == *root_hash
            }
            NonInclusionProof::NullSubtree {
                root_hash, absent_key, depth, siblings,
            } => {
                if root_hash != expected_root { return false; }
                let mut current = Hash32::ZERO; // null hash
                for sib in siblings.iter().rev() {
                    let bit = absent_key.bit(sib.depth as usize);
                    current = if !bit {
                        Hash32::digest_tagged(TAG_INTERNAL, &current.0, &sib.hash.0)
                    } else {
                        Hash32::digest_tagged(TAG_INTERNAL, &sib.hash.0, &current.0)
                    };
                }
                let _ = depth; // depth is informational
                current == *root_hash
            }
        }
    }
}

// ── In-memory node store ──────────────────────────────────────────────────────

/// Versioned in-memory node store.
/// Maps `NodeKey → JmtNode` with version-based read isolation.
/// The WAL buffer accumulates `WriteAheadEntry`s for a persistence layer.
pub struct NodeStore {
    /// All live nodes, keyed by (version, path).
    nodes:   BTreeMap<NodeKey, JmtNode>,
    /// Current committed version.
    version: u64,
    /// Uncommitted WAL entries (drained by the persistence layer).
    wal:     Vec<WriteAheadEntry>,
}

impl NodeStore {
    pub fn new() -> Self {
        // Seed version-0 with a root Null node.
        let mut nodes = BTreeMap::new();
        nodes.insert(NodeKey::root(0), JmtNode::Null);
        Self { nodes, version: 0, wal: vec![] }
    }

    pub fn current_version(&self) -> u64 { self.version }

    /// Get the node at the current version along a path.
    pub fn get(&self, key: &NodeKey) -> &JmtNode {
        // Walk versions backwards until we find the node (copy-on-write semantics).
        for v in (0..=key.version).rev() {
            let probe = NodeKey { version: v, ..key.clone() };
            if let Some(n) = self.nodes.get(&probe) {
                return n;
            }
        }
        &JmtNode::Null
    }

    /// Get a node at a specific version (for rollback / proof generation).
    pub fn get_at(&self, key: &NodeKey, version: u64) -> &JmtNode {
        for v in (0..=version).rev() {
            let probe = NodeKey { version: v, ..key.clone() };
            if let Some(n) = self.nodes.get(&probe) {
                return n;
            }
        }
        &JmtNode::Null
    }

    /// Insert or update a node at the current version.
    fn put(&mut self, key: NodeKey, node: JmtNode) {
        self.nodes.insert(key, node);
    }

    /// Drain the WAL buffer for the persistence layer.
    pub fn drain_wal(&mut self) -> Vec<WriteAheadEntry> {
        std::mem::take(&mut self.wal)
    }

    /// Prune all nodes belonging to versions older than `keep_from`.
    pub fn prune_before(&mut self, keep_from: u64) {
        self.nodes.retain(|k, _| k.version >= keep_from);
    }

    /// Node count (for diagnostics).
    pub fn node_count(&self) -> usize { self.nodes.len() }
}

impl Default for NodeStore { fn default() -> Self { Self::new() } }

// ── JMT writer (batch update) ─────────────────────────────────────────────────

/// A pending batch of (key_path, value_hash) updates to apply atomically.
/// Call `flush()` to write them to the `NodeStore` and get the new root hash.
pub struct JmtWriter<'a> {
    store:   &'a mut NodeStore,
    /// Pending upserts: key_path → value_hash.
    pending: BTreeMap<KeyPath, Option<Hash32>>,  // None = delete
}

impl<'a> JmtWriter<'a> {
    pub fn new(store: &'a mut NodeStore) -> Self {
        Self { store, pending: BTreeMap::new() }
    }

    /// Stage an upsert: key → SHA3-256(value_bytes).
    pub fn upsert(&mut self, address: &str, value_bytes: &[u8]) {
        let key  = KeyPath::from_address(address);
        let hash = hash_value(value_bytes);
        self.pending.insert(key, Some(hash));
    }

    /// Stage a deletion (remove the key from the trie).
    pub fn delete(&mut self, address: &str) {
        let key = KeyPath::from_address(address);
        self.pending.insert(key, None);
    }

    /// Flush all pending changes.  Returns the new root hash.
    /// Increments the store's version counter.
    pub fn flush(self) -> Hash32 {
        if self.pending.is_empty() {
            // Nothing changed — return current root without incrementing version.
            let root_key = NodeKey::root(self.store.version);
            return self.store.get(&root_key).hash();
        }

        let new_version = self.store.version + 1;
        let mut written:    Vec<(NodeKey, JmtNode)> = Vec::new();
        let mut stale_keys: Vec<NodeKey>             = Vec::new();

        // Rebuild the affected subtrees bottom-up.
        let root_hash = rebuild_subtree(
            self.store,
            &NodeKey::root(self.store.version),
            new_version,
            0,
            &self.pending,
            &mut written,
            &mut stale_keys,
        );

        // Write new nodes to the store.
        for (k, n) in &written {
            self.store.put(k.clone(), n.clone());
        }

        // Append WAL entry.
        self.store.wal.push(WriteAheadEntry {
            version:    new_version,
            root_hash,
            written,
            stale_keys,
        });

        self.store.version = new_version;
        root_hash
    }
}

/// Recursive subtree rebuild.
/// Returns the hash of the (possibly new) node at this position.
fn rebuild_subtree(
    store:       &NodeStore,
    node_key:    &NodeKey,
    new_version: u64,
    depth:       usize,
    pending:     &BTreeMap<KeyPath, Option<Hash32>>,
    written:     &mut Vec<(NodeKey, JmtNode)>,
    stale:       &mut Vec<NodeKey>,
) -> Hash32 {
    // Collect all pending keys that belong to this subtree.
    let subtree_keys: Vec<(&KeyPath, &Option<Hash32>)> = pending
        .iter()
        .filter(|(k, _)| subtree_match(k, node_key, depth))
        .collect();

    if subtree_keys.is_empty() {
        // No changes in this subtree — return the existing node's hash unchanged.
        return store.get(node_key).hash();
    }

    // Mark the old node as stale.
    if !store.get(node_key).is_null() {
        stale.push(node_key.clone());
    }

    let existing_node = store.get(node_key).clone();

    match &existing_node {
        JmtNode::Null => {
            // Inserting into an empty subtree.
            if subtree_keys.len() == 1 {
                let (key, val_opt) = subtree_keys[0];
                match val_opt {
                    None => {
                        // Deleting from null — nothing to do.
                        let new_key = NodeKey { version: new_version, ..node_key.clone() };
                        let node    = JmtNode::Null;
                        let hash    = node.hash();
                        written.push((new_key, node));
                        return hash;
                    }
                    Some(value_hash) => {
                        let new_key = NodeKey { version: new_version, ..node_key.clone() };
                        let node    = JmtNode::Leaf { key: *key, value_hash: *value_hash };
                        let hash    = node.hash();
                        written.push((new_key, node));
                        return hash;
                    }
                }
            }
            // Multiple keys — need to create a real internal node.
            create_internal_node(
                store, node_key, new_version, depth,
                pending, subtree_keys, written, stale,
            )
        }

        JmtNode::Leaf { key: existing_key, value_hash: existing_value_hash } => {
            let existing_key       = *existing_key;
            let existing_value_hash = *existing_value_hash;

            // Does the update target the exact same key?
            if subtree_keys.len() == 1 && subtree_keys[0].0 == &existing_key {
                let new_key = NodeKey { version: new_version, ..node_key.clone() };
                let node = match subtree_keys[0].1 {
                    None           => JmtNode::Null,  // delete
                    Some(val_hash) => JmtNode::Leaf {
                        key:        existing_key,
                        value_hash: *val_hash,
                    },
                };
                let hash = node.hash();
                written.push((new_key, node));
                return hash;
            }

            // Keys diverge: replace the leaf with an internal node, then
            // re-insert the existing leaf and new keys.
            let mut extended_pending = pending.clone();
            // Re-insert the existing leaf into the pending set so it
            // gets placed into the correct child subtree.
            extended_pending.entry(existing_key)
                .or_insert(Some(existing_value_hash));

            let subtree_keys_ext: Vec<(&KeyPath, &Option<Hash32>)> = extended_pending
                .iter()
                .filter(|(k, _)| subtree_match(k, node_key, depth))
                .collect();

            create_internal_node(
                store, node_key, new_version, depth,
                &extended_pending, subtree_keys_ext, written, stale,
            )
        }

        JmtNode::Internal { left_hash: _, right_hash: _ } => {
            create_internal_node(
                store, node_key, new_version, depth,
                pending, subtree_keys, written, stale,
            )
        }
    }
}

/// Create (or recreate) an internal node, recursing into each child.
fn create_internal_node(
    store:        &NodeStore,
    node_key:     &NodeKey,
    new_version:  u64,
    depth:        usize,
    pending:      &BTreeMap<KeyPath, Option<Hash32>>,
    _subtree_keys: Vec<(&KeyPath, &Option<Hash32>)>,
    written:      &mut Vec<(NodeKey, JmtNode)>,
    stale:        &mut Vec<NodeKey>,
) -> Hash32 {
    let left_child_key  = node_key.child(false);
    let right_child_key = node_key.child(true);

    let left_hash  = rebuild_subtree(
        store, &left_child_key,  new_version, depth + 1, pending, written, stale
    );
    let right_hash = rebuild_subtree(
        store, &right_child_key, new_version, depth + 1, pending, written, stale
    );

    // If both children are null, this node becomes null too (compression).
    if left_hash.is_zero() && right_hash.is_zero() {
        let new_key = NodeKey { version: new_version, ..node_key.clone() };
        let node    = JmtNode::Null;
        let hash    = node.hash();
        written.push((new_key, node));
        return hash;
    }

    // If exactly one child is a leaf and the other is null, compress:
    // this node becomes that leaf (path compression).
    let left_node  = store.get(&NodeKey { version: new_version, ..left_child_key.clone() });
    let right_node = store.get(&NodeKey { version: new_version, ..right_child_key.clone() });

    // Check written nodes first (they were just added).
    let left_written  = written.iter().rev().find(|(k, _)| k.depth == left_child_key.depth  && k.path_prefix == left_child_key.path_prefix  && k.version == new_version).map(|(_, n)| n.clone());
    let right_written = written.iter().rev().find(|(k, _)| k.depth == right_child_key.depth && k.path_prefix == right_child_key.path_prefix && k.version == new_version).map(|(_, n)| n.clone());

    let left_node  = left_written.as_ref().unwrap_or(left_node);
    let right_node = right_written.as_ref().unwrap_or(right_node);

    if left_hash.is_zero() {
        if let JmtNode::Leaf { key, value_hash } = right_node {
            let new_key = NodeKey { version: new_version, ..node_key.clone() };
            let node    = JmtNode::Leaf { key: *key, value_hash: *value_hash };
            let hash    = node.hash();
            written.push((new_key, node));
            return hash;
        }
    }
    if right_hash.is_zero() {
        if let JmtNode::Leaf { key, value_hash } = left_node {
            let new_key = NodeKey { version: new_version, ..node_key.clone() };
            let node    = JmtNode::Leaf { key: *key, value_hash: *value_hash };
            let hash    = node.hash();
            written.push((new_key, node));
            return hash;
        }
    }

    let new_key = NodeKey { version: new_version, ..node_key.clone() };
    let node    = JmtNode::Internal { left_hash, right_hash };
    let hash    = node.hash();
    written.push((new_key, node));
    hash
}

/// True if `key` falls within the subtree rooted at `node_key` at `depth`.
fn subtree_match(key: &KeyPath, node_key: &NodeKey, depth: usize) -> bool {
    // Check that the first `depth` bits of `key` match `node_key.path_prefix`.
    for i in 0..depth {
        let key_bit      = key.bit(i);
        let prefix_byte  = node_key.path_prefix.get(i / 8).copied().unwrap_or(0);
        let prefix_bit   = (prefix_byte >> (7 - (i % 8))) & 1 == 1;
        if key_bit != prefix_bit { return false; }
    }
    true
}

// ── JMT reader (lookup + proofs) ─────────────────────────────────────────────

/// Read-only accessor for the JMT.
pub struct JmtReader<'a> {
    store:   &'a NodeStore,
    version: u64,
}

impl<'a> JmtReader<'a> {
    /// Read at the store's current (latest) version.
    pub fn current(store: &'a NodeStore) -> Self {
        Self { store, version: store.version }
    }

    /// Read at a specific historical version (for rollback / audit).
    pub fn at_version(store: &'a NodeStore, version: u64) -> Self {
        Self { store, version }
    }

    /// Current root hash.
    pub fn root_hash(&self) -> Hash32 {
        self.store.get_at(&NodeKey::root(self.version), self.version).hash()
    }

    /// Look up a value hash for `address`.  Returns `None` if absent.
    pub fn get(&self, address: &str) -> Option<Hash32> {
        let key = KeyPath::from_address(address);
        self.get_by_key(&key)
    }

    fn get_by_key(&self, target: &KeyPath) -> Option<Hash32> {
        let mut depth    = 0usize;
        let mut node_key = NodeKey::root(self.version);

        loop {
            match self.store.get_at(&node_key, self.version) {
                JmtNode::Null => return None,
                JmtNode::Leaf { key, value_hash } => {
                    return if key == target { Some(*value_hash) } else { None };
                }
                JmtNode::Internal { .. } => {
                    let bit = target.bit(depth);
                    node_key = node_key.child(bit);
                    depth   += 1;
                }
            }
        }
    }

    /// Generate an inclusion proof for `address`.
    /// Returns `None` if the key is absent (use `prove_non_inclusion` instead).
    pub fn prove_inclusion(&self, address: &str) -> Option<InclusionProof> {
        let target   = KeyPath::from_address(address);
        let root_key = NodeKey::root(self.version);
        let mut siblings = Vec::new();
        let mut depth    = 0usize;
        let mut node_key = root_key;

        loop {
            match self.store.get_at(&node_key, self.version) {
                JmtNode::Null => return None,
                JmtNode::Leaf { key, value_hash } => {
                    if key != &target { return None; }
                    return Some(InclusionProof {
                        root_hash:  self.root_hash(),
                        key:        target,
                        value_hash: *value_hash,
                        siblings,
                    });
                }
                JmtNode::Internal { left_hash, right_hash } => {
                    let bit = target.bit(depth);
                    let sib_hash = if bit { *left_hash } else { *right_hash };
                    siblings.push(ProofSibling { depth: depth as u16, hash: sib_hash });
                    node_key = node_key.child(bit);
                    depth   += 1;
                }
            }
        }
    }

    /// Generate a non-inclusion proof for `address`.
    /// Returns `None` if the key IS present.
    pub fn prove_non_inclusion(&self, address: &str) -> Option<NonInclusionProof> {
        let target   = KeyPath::from_address(address);
        let root_key = NodeKey::root(self.version);
        let mut siblings = Vec::new();
        let mut depth    = 0usize;
        let mut node_key = root_key;

        loop {
            match self.store.get_at(&node_key, self.version) {
                JmtNode::Null => {
                    return Some(NonInclusionProof::NullSubtree {
                        root_hash:  self.root_hash(),
                        absent_key: target,
                        depth:      depth as u16,
                        siblings,
                    });
                }
                JmtNode::Leaf { key, value_hash } => {
                    if key == &target { return None; } // It IS present.
                    return Some(NonInclusionProof::Displaced {
                        root_hash:           self.root_hash(),
                        absent_key:          target,
                        existing_key:        *key,
                        existing_value_hash: *value_hash,
                        siblings,
                    });
                }
                JmtNode::Internal { left_hash, right_hash } => {
                    let bit = target.bit(depth);
                    let sib_hash = if bit { *left_hash } else { *right_hash };
                    siblings.push(ProofSibling { depth: depth as u16, hash: sib_hash });
                    node_key = node_key.child(bit);
                    depth   += 1;
                }
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_store() -> NodeStore { NodeStore::new() }

    fn upsert(store: &mut NodeStore, addr: &str, data: &[u8]) -> Hash32 {
        let mut w = JmtWriter::new(store);
        w.upsert(addr, data);
        w.flush()
    }

    fn batch_upsert(store: &mut NodeStore, items: &[(&str, &[u8])]) -> Hash32 {
        let mut w = JmtWriter::new(store);
        for (addr, data) in items { w.upsert(addr, data); }
        w.flush()
    }

    fn delete(store: &mut NodeStore, addr: &str) -> Hash32 {
        let mut w = JmtWriter::new(store);
        w.delete(addr);
        w.flush()
    }

    // ── Basic operations ───────────────────────────────────────────────────

    #[test]
    fn empty_tree_has_zero_root() {
        let store = make_store();
        let r = JmtReader::current(&store);
        assert_eq!(r.root_hash(), Hash32::ZERO);
    }

    #[test]
    fn single_insert_produces_nonzero_root() {
        let mut store = make_store();
        let root = upsert(&mut store, "qcb1alice", b"alice_state");
        assert_ne!(root, Hash32::ZERO);
    }

    #[test]
    fn root_changes_on_update() {
        let mut store = make_store();
        let r1 = upsert(&mut store, "qcb1alice", b"state_v1");
        let r2 = upsert(&mut store, "qcb1alice", b"state_v2");
        assert_ne!(r1, r2, "different value must produce different root");
    }

    #[test]
    fn root_unchanged_when_same_value_reinserted() {
        let mut store = make_store();
        let r1 = upsert(&mut store, "qcb1alice", b"state_v1");
        let r2 = upsert(&mut store, "qcb1alice", b"state_v1");
        assert_eq!(r1, r2, "same key+value must produce identical root");
    }

    #[test]
    fn two_keys_produce_different_root_than_one() {
        let mut store = make_store();
        let r1 = upsert(&mut store, "qcb1alice", b"alice");
        let r2 = {
            let mut w = JmtWriter::new(&mut store);
            w.upsert("qcb1bob", b"bob");
            w.flush()
        };
        assert_ne!(r1, r2);
    }

    #[test]
    fn root_is_deterministic_regardless_of_insertion_order() {
        // Insert alice then bob.
        let mut s1 = make_store();
        upsert(&mut s1, "qcb1alice", b"alice_data");
        let root_ab = upsert(&mut s1, "qcb1bob",   b"bob_data");

        // Insert bob then alice.
        let mut s2 = make_store();
        upsert(&mut s2, "qcb1bob",   b"bob_data");
        let root_ba = upsert(&mut s2, "qcb1alice", b"alice_data");

        assert_eq!(root_ab, root_ba,
            "root must be order-independent (content-addressed)");
    }

    #[test]
    fn batch_write_produces_same_root_as_sequential() {
        let addrs: &[(&str, &[u8])] = &[
            ("qcb1alice",   b"alice"),
            ("qcb1bob",     b"bob"),
            ("qcb1charlie", b"charlie"),
            ("qcb1dave",    b"dave"),
        ];

        // Sequential.
        let mut s1 = make_store();
        for (a, d) in addrs { upsert(&mut s1, a, d); }
        let seq_root = JmtReader::current(&s1).root_hash();

        // Batch.
        let mut s2  = make_store();
        let batch_root = batch_upsert(&mut s2, addrs);

        assert_eq!(seq_root, batch_root,
            "batch and sequential inserts must produce the same root");
    }

    #[test]
    fn delete_key_returns_to_prior_root() {
        let mut store = make_store();
        let root_empty = JmtReader::current(&store).root_hash();

        upsert(&mut store, "qcb1alice", b"alice");
        let root_after_delete = delete(&mut store, "qcb1alice");

        assert_eq!(root_empty, root_after_delete,
            "deleting the only key must restore the empty-tree root");
    }

    #[test]
    fn delete_nonexistent_key_is_idempotent() {
        let mut store = make_store();
        upsert(&mut store, "qcb1alice", b"alice");
        let r1 = JmtReader::current(&store).root_hash();

        let r2 = delete(&mut store, "qcb1nobody"); // key does not exist
        assert_eq!(r1, r2, "deleting absent key must not change the root");
    }

    // ── Lookup ────────────────────────────────────────────────────────────

    #[test]
    fn lookup_returns_value_hash_after_insert() {
        let mut store = make_store();
        upsert(&mut store, "qcb1alice", b"alice_state");

        let r      = JmtReader::current(&store);
        let found  = r.get("qcb1alice").expect("key must be found");
        let expect = hash_value(b"alice_state");
        assert_eq!(found, expect);
    }

    #[test]
    fn lookup_absent_key_returns_none() {
        let mut store = make_store();
        upsert(&mut store, "qcb1alice", b"alice");

        let r = JmtReader::current(&store);
        assert!(r.get("qcb1nobody").is_none());
    }

    #[test]
    fn lookup_after_delete_returns_none() {
        let mut store = make_store();
        upsert(&mut store, "qcb1alice", b"alice");
        delete(&mut store, "qcb1alice");

        let r = JmtReader::current(&store);
        assert!(r.get("qcb1alice").is_none(), "deleted key must not be found");
    }

    #[test]
    fn lookup_is_isolated_by_version() {
        let mut store = make_store();
        upsert(&mut store, "qcb1alice", b"v1");
        let v1 = store.current_version();

        upsert(&mut store, "qcb1alice", b"v2");

        let r_v1 = JmtReader::at_version(&store, v1);
        assert_eq!(r_v1.get("qcb1alice"), Some(hash_value(b"v1")),
            "historical read must return the value at that version");

        let r_v2 = JmtReader::current(&store);
        assert_eq!(r_v2.get("qcb1alice"), Some(hash_value(b"v2")));
    }

    // ── Inclusion proofs ──────────────────────────────────────────────────

    #[test]
    fn inclusion_proof_verifies_for_present_key() {
        let mut store = make_store();
        batch_upsert(&mut store, &[
            ("qcb1alice", b"alice"),
            ("qcb1bob",   b"bob"),
            ("qcb1carol", b"carol"),
        ]);

        let r     = JmtReader::current(&store);
        let proof = r.prove_inclusion("qcb1alice")
            .expect("alice must be present");

        assert!(proof.verify(&r.root_hash()),
            "inclusion proof must verify against current root");
    }

    #[test]
    fn inclusion_proof_for_absent_key_returns_none() {
        let mut store = make_store();
        upsert(&mut store, "qcb1alice", b"alice");

        let r = JmtReader::current(&store);
        assert!(r.prove_inclusion("qcb1nobody").is_none(),
            "no inclusion proof for absent key");
    }

    #[test]
    fn inclusion_proof_fails_with_wrong_root() {
        let mut store = make_store();
        upsert(&mut store, "qcb1alice", b"alice");

        let r     = JmtReader::current(&store);
        let proof = r.prove_inclusion("qcb1alice").unwrap();
        let wrong_root = hash_value(b"not the root");

        assert!(!proof.verify(&wrong_root),
            "inclusion proof must fail with a wrong root");
    }

    #[test]
    fn inclusion_proof_survives_multiple_keys() {
        let addrs: &[(&str, &[u8])] = &[
            ("qcb1v1", b"v1"), ("qcb1v2", b"v2"), ("qcb1v3", b"v3"),
            ("qcb1v4", b"v4"), ("qcb1v5", b"v5"), ("qcb1v6", b"v6"),
            ("qcb1v7", b"v7"), ("qcb1v8", b"v8"),
        ];
        let mut store = make_store();
        batch_upsert(&mut store, addrs);

        let r = JmtReader::current(&store);
        let root = r.root_hash();
        for (addr, _) in addrs {
            let proof = r.prove_inclusion(addr)
                .unwrap_or_else(|| panic!("proof missing for {addr}"));
            assert!(proof.verify(&root), "proof must verify for {addr}");
        }
    }

    // ── Non-inclusion proofs ──────────────────────────────────────────────

    #[test]
    fn non_inclusion_proof_verifies_for_absent_key() {
        let mut store = make_store();
        batch_upsert(&mut store, &[
            ("qcb1alice", b"alice"),
            ("qcb1bob",   b"bob"),
        ]);

        let r     = JmtReader::current(&store);
        let proof = r.prove_non_inclusion("qcb1nobody")
            .expect("non-inclusion proof must be generated for absent key");

        assert!(proof.verify(&r.root_hash()),
            "non-inclusion proof must verify against current root");
    }

    #[test]
    fn non_inclusion_proof_absent_on_present_key() {
        let mut store = make_store();
        upsert(&mut store, "qcb1alice", b"alice");

        let r = JmtReader::current(&store);
        assert!(r.prove_non_inclusion("qcb1alice").is_none(),
            "no non-inclusion proof for key that IS present");
    }

    #[test]
    fn non_inclusion_proof_on_empty_tree() {
        let store = make_store();
        let r     = JmtReader::current(&store);
        let proof = r.prove_non_inclusion("qcb1alice")
            .expect("empty tree must prove non-inclusion");
        assert!(proof.verify(&r.root_hash()));
    }

    // ── Versioning + WAL ──────────────────────────────────────────────────

    #[test]
    fn version_increments_on_each_flush() {
        let mut store = make_store();
        assert_eq!(store.current_version(), 0);

        upsert(&mut store, "qcb1a", b"a");
        assert_eq!(store.current_version(), 1);

        upsert(&mut store, "qcb1b", b"b");
        assert_eq!(store.current_version(), 2);
    }

    #[test]
    fn empty_flush_does_not_increment_version() {
        let mut store = make_store();
        upsert(&mut store, "qcb1a", b"a");
        let v_before = store.current_version();

        // Flush with no pending changes.
        let w = JmtWriter::new(&mut store);
        w.flush();

        assert_eq!(store.current_version(), v_before,
            "empty flush must not advance the version");
    }

    #[test]
    fn wal_entry_emitted_on_flush() {
        let mut store = make_store();
        upsert(&mut store, "qcb1alice", b"alice");

        let wal = store.drain_wal();
        assert_eq!(wal.len(), 1, "one WAL entry per flush");
        assert_eq!(wal[0].version, 1);
        assert!(!wal[0].written.is_empty(), "WAL entry must contain written nodes");
    }

    #[test]
    fn wal_drain_clears_buffer() {
        let mut store = make_store();
        upsert(&mut store, "qcb1alice", b"alice");

        store.drain_wal();
        let second_drain = store.drain_wal();
        assert!(second_drain.is_empty(), "drain must clear the buffer");
    }

    #[test]
    fn historical_root_matches_wal_root_hash() {
        let mut store = make_store();
        upsert(&mut store, "qcb1alice", b"alice");
        let wal_root = store.drain_wal()[0].root_hash;

        let r = JmtReader::at_version(&store, 1);
        assert_eq!(r.root_hash(), wal_root,
            "WAL root hash must match historical reader root");
    }

    #[test]
    fn rollback_to_earlier_version_gives_old_root() {
        let mut store = make_store();
        upsert(&mut store, "qcb1alice", b"v1");
        let root_v1 = JmtReader::at_version(&store, 1).root_hash();

        upsert(&mut store, "qcb1alice", b"v2");
        upsert(&mut store, "qcb1bob",   b"bob");

        // "Roll back" by reading at version 1.
        let rolled = JmtReader::at_version(&store, 1).root_hash();
        assert_eq!(rolled, root_v1, "historical read gives old root (O(1) rollback)");
    }

    // ── Hash correctness ──────────────────────────────────────────────────

    #[test]
    fn null_node_hashes_to_zero() {
        assert_eq!(JmtNode::Null.hash(), Hash32::ZERO);
    }

    #[test]
    fn leaf_hash_is_deterministic() {
        let key  = KeyPath::from_address("qcb1test");
        let vh   = hash_value(b"some state bytes");
        let node = JmtNode::Leaf { key, value_hash: vh };
        assert_eq!(node.hash(), node.hash());
    }

    #[test]
    fn internal_hash_depends_on_both_children() {
        let h1 = hash_value(b"left");
        let h2 = hash_value(b"right");

        let n1 = JmtNode::Internal { left_hash: h1, right_hash: h2 }.hash();
        let n2 = JmtNode::Internal { left_hash: h2, right_hash: h1 }.hash(); // swapped
        assert_ne!(n1, n2, "left and right must be asymmetric in the hash");
    }

    #[test]
    fn value_tag_prevents_collision_with_leaf_tag() {
        // hash_value(x) ≠ SHA3(TAG_LEAF || ...) for same x,
        // because value hashing uses TAG_VALUE.
        let data    = b"some bytes";
        let val_h   = hash_value(data);
        let leaf_h  = Hash32::digest_tagged(TAG_LEAF, data, &[]);
        assert_ne!(val_h, leaf_h);
    }

    // ── KeyPath ────────────────────────────────────────────────────────────

    #[test]
    fn keypath_bit_extraction() {
        // Byte 0x80 = 0b10000000 → bit 0 is 1, bit 1 is 0.
        let mut k = KeyPath([0u8; 32]);
        k.0[0] = 0x80;
        assert!(k.bit(0),  "MSB of byte 0 is 1");
        assert!(!k.bit(1), "second bit is 0");
    }

    #[test]
    fn keypath_common_prefix_len() {
        let a = KeyPath::from_address("qcb1alice");
        let b = KeyPath::from_address("qcb1alice"); // same
        assert_eq!(a.common_prefix_len(&b), 256);

        let c = KeyPath::from_address("qcb1bob");
        let shared = a.common_prefix_len(&c);
        assert!(shared < 256, "different addresses share < 256 prefix bits");
    }

    #[test]
    fn large_batch_deterministic_root() {
        let items: Vec<(String, Vec<u8>)> = (0..100)
            .map(|i| (format!("qcb1addr{i:04}"), format!("state_{i}").into_bytes()))
            .collect();

        let as_refs: Vec<(&str, &[u8])> = items.iter()
            .map(|(a, d)| (a.as_str(), d.as_slice()))
            .collect();

        let mut s1 = make_store();
        let mut s2 = make_store();

        // Insert in forward order.
        for (a, d) in &as_refs { upsert(&mut s1, a, d); }
        let r1 = JmtReader::current(&s1).root_hash();

        // Insert in reverse order.
        for (a, d) in as_refs.iter().rev() { upsert(&mut s2, a, d); }
        let r2 = JmtReader::current(&s2).root_hash();

        assert_eq!(r1, r2,
            "100-key tree must have order-independent root");
    }
}
