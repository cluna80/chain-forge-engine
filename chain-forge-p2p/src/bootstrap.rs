//! Bounded redial of bootstrap addresses, with exponential backoff.
//!
//! Before this module the node dialled every `--bootstrap` address ONCE at startup and discarded the result. A node that started
//! before its bootstrap peer was listening therefore never connected: its API answered, `peer_count` stayed 0 and no block was
//! produced (measured on a four-node devnet: 4 of 6 simultaneous starts stalled).
//!
//! This is a pure scheduler (no libp2p, no clock of its own): the swarm loop asks `due(now)` which addresses to dial again and
//! reports `mark_connected(addr)` when an outbound connection to one succeeds. It is bounded: an address is dialled again at most
//! `max_attempts` times, with delays `initial, 2*initial, 4*initial, …` capped at `max_delay`, and never again after it connected.

use std::time::Duration;

/// How often and for how long a bootstrap address is dialled again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Delay before the first redial.
    pub initial: Duration,
    /// Upper bound of any single delay.
    pub max_delay: Duration,
    /// Redials per address after the initial dial (the bound).
    pub max_attempts: u32,
}

impl Default for RetryPolicy {
    /// 1 s, 2 s, 4 s, 8 s, 16 s, then 30 s each; 20 redials, about 8 minutes in all.
    fn default() -> Self {
        Self { initial: Duration::from_secs(1), max_delay: Duration::from_secs(30), max_attempts: 20 }
    }
}

impl RetryPolicy {
    /// The delay after `done` redials have been made (`done = 0`: the delay before the first redial).
    pub fn delay_after(&self, done: u32) -> Duration {
        let _ = done;
        Duration::ZERO // scaffold: real backoff not implemented yet
    }
}

/// Strip a trailing `/p2p/<peer id>` so `"/ip4/1.2.3.4/tcp/9"` and `"/ip4/1.2.3.4/tcp/9/p2p/12D3…"` name the same dial target.
pub fn normalize(addr: &str) -> String {
    addr.to_string() // scaffold: real normalisation not implemented yet
}

#[derive(Debug)]
struct Entry {
    addr: String,
    key: String,
    done_attempts: u32,
    next_at: Duration,
    finished: bool,
}

/// Tracks which bootstrap addresses still need a redial.
#[derive(Debug)]
pub struct BootstrapRetry {
    policy: RetryPolicy,
    entries: Vec<Entry>,
}

impl BootstrapRetry {
    /// `now` is the time of the initial dial (any monotonic offset, e.g. `Instant::elapsed()` of the loop start).
    pub fn new<I: IntoIterator<Item = String>>(addrs: I, policy: RetryPolicy, now: Duration) -> Self {
        let mut entries: Vec<Entry> = vec![];
        for a in addrs {
            let key = normalize(&a);
            if entries.iter().any(|e| e.key == key) { continue; }
            entries.push(Entry { addr: a, key, done_attempts: 0, next_at: now + policy.delay_after(0), finished: false });
        }
        Self { policy, entries }
    }

    /// Addresses to dial again at `now`. Each returned address counts as one redial and is rescheduled (or finished, at the bound).
    pub fn due(&mut self, now: Duration) -> Vec<String> {
        let _ = now;
        Vec::new() // scaffold: never redials
    }

    /// An outbound connection to `addr` succeeded: stop redialling it.
    pub fn mark_connected(&mut self, addr: &str) {
        let _ = addr; // scaffold
    }

    /// Addresses that may still be redialled.
    pub fn pending(&self) -> usize { self.entries.iter().filter(|e| !e.finished).count() }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: fn(u64) -> Duration = Duration::from_secs;
    fn pol() -> RetryPolicy { RetryPolicy { initial: S(1), max_delay: S(30), max_attempts: 7 } }
    fn one(addr: &str) -> BootstrapRetry { BootstrapRetry::new([addr.to_string()], pol(), S(0)) }

    #[test]
    fn nothing_is_due_before_the_first_delay() {
        let mut r = one("/ip4/127.0.0.1/tcp/1");
        assert!(r.due(S(0)).is_empty());
        assert!(r.due(Duration::from_millis(999)).is_empty());
    }

    #[test]
    fn the_delays_double_and_are_capped() {
        let p = pol();
        let d: Vec<u64> = (0..8).map(|k| p.delay_after(k).as_secs()).collect();
        assert_eq!(d, vec![1, 2, 4, 8, 16, 30, 30, 30]);
    }

    #[test]
    fn redials_happen_at_the_backoff_times_and_stop_at_the_bound() {
        let mut r = one("/ip4/127.0.0.1/tcp/1");
        let mut when = vec![];
        let mut t = Duration::ZERO;
        while t < S(1000) {
            if !r.due(t).is_empty() { when.push(t.as_secs()); }
            t += Duration::from_millis(100);
        }
        // 7 redials: at 1, 3 (=1+2), 7, 15, 31, 61, 91 seconds; then never again.
        assert_eq!(when, vec![1, 3, 7, 15, 31, 61, 91]);
        assert_eq!(r.pending(), 0, "bounded: the address is finished after max_attempts");
    }

    #[test]
    fn an_address_is_returned_once_per_due_time_not_on_every_poll() {
        let mut r = one("/ip4/127.0.0.1/tcp/1");
        assert_eq!(r.due(S(1)).len(), 1);
        assert!(r.due(S(1)).is_empty(), "the same instant must not return it twice");
        assert!(r.due(Duration::from_millis(2999)).is_empty());
        assert_eq!(r.due(S(3)).len(), 1);
    }

    #[test]
    fn a_connected_address_is_never_redialled() {
        let mut r = one("/ip4/127.0.0.1/tcp/1");
        r.mark_connected("/ip4/127.0.0.1/tcp/1");
        assert_eq!(r.pending(), 0);
        for t in 0..200 { assert!(r.due(S(t)).is_empty()); }
    }

    #[test]
    fn a_connection_reported_with_a_peer_id_suffix_still_matches() {
        assert_eq!(normalize("/ip4/127.0.0.1/tcp/1/p2p/12D3KooWAbc"), "/ip4/127.0.0.1/tcp/1");
        assert_eq!(normalize("/ip4/127.0.0.1/tcp/1"), "/ip4/127.0.0.1/tcp/1");
        let mut r = one("/ip4/127.0.0.1/tcp/1");
        r.mark_connected("/ip4/127.0.0.1/tcp/1/p2p/12D3KooWAbc");
        assert_eq!(r.pending(), 0);
    }

    #[test]
    fn addresses_are_independent_and_duplicates_are_collapsed() {
        let mut r = BootstrapRetry::new(
            ["/ip4/127.0.0.1/tcp/1".to_string(), "/ip4/127.0.0.1/tcp/2".to_string(), "/ip4/127.0.0.1/tcp/1/p2p/X".to_string()], pol(), S(0));
        assert_eq!(r.pending(), 2, "the duplicate (same target, with a peer id) is one address");
        r.mark_connected("/ip4/127.0.0.1/tcp/1");
        assert_eq!(r.pending(), 1);
        assert_eq!(r.due(S(1)), vec!["/ip4/127.0.0.1/tcp/2".to_string()]);
    }

    #[test]
    fn the_schedule_is_relative_to_the_start_time() {
        let mut r = BootstrapRetry::new(["/ip4/127.0.0.1/tcp/1".to_string()], pol(), S(100));
        assert!(r.due(S(100)).is_empty());
        assert_eq!(r.due(S(101)).len(), 1);
    }

    #[test]
    fn no_addresses_means_nothing_to_do() {
        let mut r = BootstrapRetry::new(Vec::<String>::new(), pol(), S(0));
        assert_eq!(r.pending(), 0);
        assert!(r.due(S(1_000)).is_empty());
    }
}
