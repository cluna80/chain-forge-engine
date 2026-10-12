//! # Beacon — BTC-Block-Hash Seeded Deterministic Job Assignment (Change Set Q)
//!
//! ## Design
//!
//! Instead of the scheduler *choosing* which task a miner receives, the miner
//! *derives* its own work slice from a public Bitcoin block hash beacon, then
//! *claims* that slice.  The scheduler validates the claim atomically but does
//! not make the assignment decision itself.
//!
//! ## Seed derivation
//!
//! ```text
//! job_seed = SHA-256(
//!     "QCB-BEACON-v1\x00"
//!     || beacon_hash[0..32]          // 32 bytes — raw BTC block hash
//!     || challenge_id_utf8           // variable length
//!     || "\x00"
//!     || machine_id_utf8             // variable length
//! )
//! ```
//!
//! ## Task selection
//!
//! ```text
//! task_index = u64::from_le_bytes(job_seed[0..8]) % task_count
//! ```
//!
//! If the derived task is already taken, the miner increments an internal
//! `collision_round` counter and re-derives using a salted seed:
//!
//! ```text
//! retry_seed = SHA-256(job_seed || collision_round_le64)
//! ```
//!
//! ## Backward compatibility
//!
//! The `/scheduler/miners/{id}/task` endpoint accepts an optional
//! `?btc_hash=<hex>` query param.  When absent, it falls back to the legacy
//! FIFO-random assignment path — no existing miners break.
//!
//! ## BTC beacon fetch
//!
//! The scheduler exposes `GET /scheduler/beacon` so miners without a BTC RPC
//! node can obtain the latest beacon slot from the scheduler itself.  The
//! scheduler can optionally be wired to a real BTC node via `--btc-rpc-url`;
//! otherwise it uses a stub that re-hashes a counter to simulate advancing
//! block hashes (useful for devnet without internet access).

use sha2::{Digest, Sha256};

// ── Domain prefix ─────────────────────────────────────────────────────────────

const BEACON_DOMAIN: &[u8] = b"QCB-BEACON-v1\x00";

// ── Beacon slot ───────────────────────────────────────────────────────────────

/// A single BTC block used as an entropy source for task selection.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BeaconSlot {
    /// Raw 32-byte BTC block hash (big-endian as returned by Bitcoin JSON-RPC).
    /// Hex-encoded for JSON transport.
    pub block_hash: String,
    /// Bitcoin block height this hash belongs to.
    pub block_height: u64,
    /// Source description — "btc-mainnet", "btc-stub", etc.
    pub source: String,
}

impl BeaconSlot {
    /// Decode `block_hash` hex to raw bytes.  Returns an error if the hex is
    /// malformed or not exactly 32 bytes.
    pub fn hash_bytes(&self) -> Result<[u8; 32], BeaconError> {
        let bytes = hex::decode(&self.block_hash)
            .map_err(|_| BeaconError::InvalidHash(self.block_hash.clone()))?;
        bytes
            .try_into()
            .map_err(|_| BeaconError::InvalidHash(self.block_hash.clone()))
    }
}

// ── Beacon source ─────────────────────────────────────────────────────────────

/// Controls where the scheduler fetches beacon data from.
#[derive(Clone, Debug)]
pub enum BeaconSource {
    /// A real Bitcoin node reachable over HTTP (JSON-RPC).
    ///
    /// The scheduler calls `getblockchaininfo` to get the chain tip, then
    /// `getblockhash` + `getblockheader` to fetch the hash bytes.
    BtcNode { rpc_url: String },

    /// Counter-based stub for devnet / tests.
    ///
    /// On each `fetch()` call the internal counter is NOT advanced — callers
    /// can advance it manually via `BeaconService::advance_stub`.  This keeps
    /// the devnet deterministic across restarts unless you explicitly tick it.
    Stub,
}

// ── Beacon service ────────────────────────────────────────────────────────────

/// Shared handle to the beacon service.  Clone-cheap (`Arc` internally).
#[derive(Clone)]
pub struct BeaconService {
    inner: std::sync::Arc<BeaconInner>,
}

struct BeaconInner {
    source: BeaconSource,
    /// Used by the Stub source — protected by a mutex so callers can advance
    /// it without &mut self.
    stub_epoch: std::sync::Mutex<u64>,
}

impl BeaconService {
    /// Create a service backed by a real BTC node.
    pub fn with_btc_node(rpc_url: impl Into<String>) -> Self {
        Self {
            inner: std::sync::Arc::new(BeaconInner {
                source:     BeaconSource::BtcNode { rpc_url: rpc_url.into() },
                stub_epoch: std::sync::Mutex::new(0),
            }),
        }
    }

    /// Create a stub service for devnet / tests.
    ///
    /// The returned slot hash is `SHA-256(b"qcb-devnet-stub\x00" || epoch_le64)`.
    /// Epoch 0 is the initial value; call `advance_stub()` to simulate a new block.
    pub fn stub() -> Self {
        Self {
            inner: std::sync::Arc::new(BeaconInner {
                source:     BeaconSource::Stub,
                stub_epoch: std::sync::Mutex::new(0),
            }),
        }
    }

    /// Advance the stub epoch by one (simulates a new BTC block arriving).
    /// No-op when backed by a real BTC node.
    pub fn advance_stub(&self) {
        if matches!(self.inner.source, BeaconSource::Stub) {
            let mut ep = self.inner.stub_epoch.lock().unwrap();
            *ep += 1;
        }
    }

    /// Fetch the current beacon slot.
    ///
    /// * **Stub mode** — always succeeds, derives a deterministic hash from the
    ///   current epoch counter.
    /// * **BTC node mode** — hits `getblockchaininfo` then `getblockhash`.
    ///   Returns `BeaconError::FetchFailed` on any network or RPC error.
    pub async fn fetch(&self) -> Result<BeaconSlot, BeaconError> {
        match &self.inner.source {
            BeaconSource::Stub => {
                let epoch = *self.inner.stub_epoch.lock().unwrap();
                Ok(stub_slot(epoch))
            }
            BeaconSource::BtcNode { rpc_url } => {
                fetch_btc_slot(rpc_url).await
            }
        }
    }
}

// ── Deterministic seed derivation ─────────────────────────────────────────────

/// Derive a 32-byte job seed from a beacon hash + identifiers.
///
/// ```text
/// job_seed = SHA-256("QCB-BEACON-v1\x00" || beacon_hash || challenge_id || "\x00" || machine_id)
/// ```
///
/// This is a pure function — it has no side effects and is testable without
/// any network calls.
pub fn derive_job_seed(
    beacon_hash:  &[u8; 32],
    challenge_id: &str,
    machine_id:   &str,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(BEACON_DOMAIN);
    hasher.update(beacon_hash);
    hasher.update(challenge_id.as_bytes());
    hasher.update(b"\x00");
    hasher.update(machine_id.as_bytes());
    hasher.finalize().into()
}

/// Derive a retry seed when the primary derived task is already claimed.
///
/// ```text
/// retry_seed = SHA-256(prev_seed || collision_round_le64)
/// ```
pub fn derive_retry_seed(prev_seed: &[u8; 32], collision_round: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(prev_seed);
    hasher.update(collision_round.to_le_bytes());
    hasher.finalize().into()
}

/// Select a task index from a seed and the current number of available tasks.
///
/// ```text
/// task_index = u64::from_le_bytes(seed[0..8]) % task_count
/// ```
///
/// Returns `None` when `task_count == 0` (no tasks available).
pub fn select_task_index(seed: &[u8; 32], task_count: usize) -> Option<usize> {
    if task_count == 0 {
        return None;
    }
    let n = u64::from_le_bytes(seed[0..8].try_into().unwrap());
    Some((n % task_count as u64) as usize)
}

// ── BTC JSON-RPC helpers ──────────────────────────────────────────────────────

/// Fetch the latest BTC block hash and height from a Bitcoin JSON-RPC node.
///
/// Uses `getblockchaininfo` (single call) which returns both `blocks` (height)
/// and `bestblockhash` (hex hash).  This is one fewer round-trip than calling
/// `getblockcount` + `getblockhash`.
async fn fetch_btc_slot(rpc_url: &str) -> Result<BeaconSlot, BeaconError> {
    // Build a minimal JSON-RPC 1.0 call body.
    let body = serde_json::json!({
        "jsonrpc": "1.0",
        "id": "qcb-beacon",
        "method": "getblockchaininfo",
        "params": []
    });

    let client = reqwest::Client::new();
    let resp = client
        .post(rpc_url)
        .json(&body)
        .send()
        .await
        .map_err(|e| BeaconError::FetchFailed(e.to_string()))?;

    if !resp.status().is_success() {
        return Err(BeaconError::FetchFailed(format!(
            "BTC RPC returned HTTP {}",
            resp.status()
        )));
    }

    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| BeaconError::FetchFailed(e.to_string()))?;

    let result = json.get("result").ok_or_else(|| {
        BeaconError::FetchFailed("BTC RPC response missing 'result' field".into())
    })?;

    let best_hash = result
        .get("bestblockhash")
        .and_then(|v| v.as_str())
        .ok_or_else(|| BeaconError::FetchFailed("missing 'bestblockhash'".into()))?
        .to_string();

    let height = result
        .get("blocks")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| BeaconError::FetchFailed("missing 'blocks'".into()))?;

    // Validate the hash is 32 bytes (64 hex chars).
    if best_hash.len() != 64 {
        return Err(BeaconError::InvalidHash(best_hash));
    }

    Ok(BeaconSlot {
        block_hash:   best_hash,
        block_height: height,
        source:       "btc-mainnet".into(),
    })
}

// ── Stub helpers ──────────────────────────────────────────────────────────────

/// Produce a deterministic stub beacon slot for a given epoch.
pub fn stub_slot(epoch: u64) -> BeaconSlot {
    let mut hasher = Sha256::new();
    hasher.update(b"qcb-devnet-stub\x00");
    hasher.update(epoch.to_le_bytes());
    let hash: [u8; 32] = hasher.finalize().into();
    BeaconSlot {
        block_hash:   hex::encode(hash),
        block_height: 800_000 + epoch, // plausible BTC height range
        source:       "btc-stub".into(),
    }
}

// ── Error type ────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum BeaconError {
    #[error("Failed to fetch BTC beacon: {0}")]
    FetchFailed(String),
    #[error("Invalid beacon hash (not 32 bytes): {0}")]
    InvalidHash(String),
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod beacon_tests {
    use super::*;

    #[test]
    fn derive_job_seed_is_deterministic() {
        let hash = [0xABu8; 32];
        let s1 = derive_job_seed(&hash, "obj-001", "miner-a");
        let s2 = derive_job_seed(&hash, "obj-001", "miner-a");
        assert_eq!(s1, s2);
    }

    #[test]
    fn different_machines_get_different_seeds() {
        let hash = [0xABu8; 32];
        let s_a = derive_job_seed(&hash, "obj-001", "miner-a");
        let s_b = derive_job_seed(&hash, "obj-001", "miner-b");
        assert_ne!(s_a, s_b);
    }

    #[test]
    fn different_challenges_get_different_seeds() {
        let hash = [0xABu8; 32];
        let s1 = derive_job_seed(&hash, "obj-001", "miner-a");
        let s2 = derive_job_seed(&hash, "obj-002", "miner-a");
        assert_ne!(s1, s2);
    }

    #[test]
    fn different_beacons_get_different_seeds() {
        let h1 = [0xAAu8; 32];
        let h2 = [0xBBu8; 32];
        let s1 = derive_job_seed(&h1, "obj-001", "miner-a");
        let s2 = derive_job_seed(&h2, "obj-001", "miner-a");
        assert_ne!(s1, s2);
    }

    #[test]
    fn select_task_index_zero_count_returns_none() {
        let seed = [0u8; 32];
        assert_eq!(select_task_index(&seed, 0), None);
    }

    #[test]
    fn select_task_index_within_bounds() {
        let seed = [0xFFu8; 32];
        let idx = select_task_index(&seed, 100).unwrap();
        assert!(idx < 100);
    }

    #[test]
    fn retry_seed_differs_from_primary() {
        let seed = [0x42u8; 32];
        let retry = derive_retry_seed(&seed, 1);
        assert_ne!(seed, retry);
    }

    #[test]
    fn stub_slot_is_deterministic() {
        let s0a = stub_slot(0);
        let s0b = stub_slot(0);
        assert_eq!(s0a.block_hash, s0b.block_hash);
        assert_eq!(s0a.block_height, s0b.block_height);
    }

    #[test]
    fn stub_slot_advances_with_epoch() {
        let s0 = stub_slot(0);
        let s1 = stub_slot(1);
        assert_ne!(s0.block_hash, s1.block_hash);
        assert_eq!(s1.block_height, s0.block_height + 1);
    }

    #[tokio::test]
    async fn beacon_service_stub_fetch_succeeds() {
        let svc = BeaconService::stub();
        let slot = svc.fetch().await.unwrap();
        assert_eq!(slot.source, "btc-stub");
        assert_eq!(slot.block_hash.len(), 64);
    }

    #[tokio::test]
    async fn beacon_service_stub_advance_changes_hash() {
        let svc = BeaconService::stub();
        let s1 = svc.fetch().await.unwrap();
        svc.advance_stub();
        let s2 = svc.fetch().await.unwrap();
        assert_ne!(s1.block_hash, s2.block_hash);
    }

    #[test]
    fn beacon_slot_hash_bytes_roundtrip() {
        let slot = stub_slot(42);
        let bytes = slot.hash_bytes().unwrap();
        assert_eq!(hex::encode(bytes), slot.block_hash);
    }
}
