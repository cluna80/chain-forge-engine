//! Test-only fault injection (cargo feature `fault-injection`; never in a
//! default build). Delays the *arrival* of a chosen validator's precommits at
//! this node, as a slow or lossy network path would, so tests can measure how
//! the liveness evidence pipeline treats a late-but-live validator.
//!
//! Control is a file named by `CF_FAULT_CONTROL_FILE`, re-read on every
//! precommit, holding `<validator-id> <delay-ms>` (or empty / `off`). Changing
//! the file changes the delay without restarting the node.
//!
//! Receiver-side delay is deliberate: each node also re-gossips votes every
//! `2 x block_time`, which would silently undo a sender-side delay.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use chain_forge_consensus::{Vote, VoteType};
use chain_forge_p2p::GossipMessage;
use tracing::info;

type Key = (String, u64, u32);

pub struct FaultInjection {
    control_file: Option<std::path::PathBuf>,
    pending:  Vec<(Instant, Key, GossipMessage)>,
    seen:     HashMap<Key, Instant>,
    released: HashSet<Key>,
}

impl FaultInjection {
    pub fn from_env() -> Self {
        let control_file = std::env::var_os("CF_FAULT_CONTROL_FILE").map(std::path::PathBuf::from);
        if let Some(p) = &control_file {
            info!(target: "cf_fault", control_file = ?p, "fault injection ACTIVE (precommit arrival delay)");
        }
        Self { control_file, pending: vec![], seen: HashMap::new(), released: HashSet::new() }
    }

    fn delay_for(&self, validator: &str) -> Option<Duration> {
        let text = std::fs::read_to_string(self.control_file.as_ref()?).ok()?;
        let mut parts = text.split_whitespace();
        if parts.next()? != validator { return None; }
        let ms: u64 = parts.next()?.parse().ok()?;
        (ms > 0).then(|| Duration::from_millis(ms))
    }

    /// Returns true when the precommit was deferred (the caller drops it for now).
    pub fn on_vote(&mut self, vote: &Vote, msg: &GossipMessage) -> bool {
        if vote.vote_type != VoteType::Precommit { return false; }
        let key: Key = (vote.validator.0.clone(), vote.height, vote.round);
        if self.released.remove(&key) {
            info!(target: "cf_fault", validator = %key.0, height = key.1, round = key.2, "deliver precommit");
            return false;
        }
        let first_sight = !self.seen.contains_key(&key);
        if first_sight {
            self.seen.insert(key.clone(), Instant::now());
            info!(target: "cf_fault", validator = %key.0, height = key.1, round = key.2, "recv precommit");
        }
        let Some(delay) = self.delay_for(&key.0) else { return false };
        if self.pending.iter().any(|(_, k, _)| *k == key) { return true; }
        info!(target: "cf_fault", validator = %key.0, height = key.1, round = key.2,
              delay_ms = delay.as_millis() as u64, "defer precommit");
        self.pending.push((Instant::now() + delay, key, msg.clone()));
        true
    }

    /// Deferred precommits whose delay has elapsed; the caller re-feeds them.
    pub fn take_due(&mut self) -> Vec<GossipMessage> {
        let now = Instant::now();
        self.seen.retain(|_, t| now.duration_since(*t) < Duration::from_secs(120));
        let (due, later): (Vec<_>, Vec<_>) = std::mem::take(&mut self.pending)
            .into_iter().partition(|(at, _, _)| *at <= now);
        self.pending = later;
        due.into_iter().map(|(_, key, msg)| { self.released.insert(key); msg }).collect()
    }
}
