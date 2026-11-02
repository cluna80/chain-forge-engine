//! H0-11B evidence integrity (policy layer): can the liveness window jail a
//! validator that is actually healthy?
//!
//! Drives the REAL `LivenessWindow::record` / `robust_missed_pct` with the
//! production defaults used by `validator_jail_live` (100-block window, 20%
//! threshold, Byzantine discount f = 1 for a 4-validator set) over synthetic
//! omission patterns. The patterns stand in for "a healthy validator's
//! precommit missed the proposer's collection window"; the node-level test
//! `late_precommit_*` shows that mechanism really exists, and
//! `validator_liveness_integrity_live` measures how often it happens on a real
//! network. This file shows what the POLICY does with a given miss pattern.
//!
//! It makes no claim about real-network delay distributions. Run with
//! `--nocapture` to see the table.
//!
//!   cargo test -p chain-forge-slashing --test liveness_false_positive -- --nocapture

use chain_forge_slashing::LivenessWindow;

const WINDOW: usize = 100;
const THRESHOLD: u32 = 20;
const F: usize = 1;
const PROPOSERS: u64 = 4;
const BLOCKS: u64 = 2_000;
const TRIALS: u32 = 400;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        self.0 = x;
        x
    }
    fn chance(&mut self, p: f64) -> bool { ((self.next() >> 11) as f64 / (1u64 << 53) as f64) < p }
    fn below(&mut self, n: u64) -> u64 { self.next() % n }
}

/// First block at which the validator would be jailed, if any. `missed(h, proposer)`
/// says whether the evidence published by `proposer` for block `h` omitted it.
fn first_jail(blocks: u64, mut missed: impl FnMut(u64, u64) -> bool) -> Option<u64> {
    let mut w = LivenessWindow::new(WINDOW);
    for h in 0..blocks {
        let proposer = h % PROPOSERS;
        w.record(!missed(h, proposer), &format!("p{proposer}"));
        if w.filled && w.robust_missed_pct(F) > THRESHOLD { return Some(h); }
    }
    None
}

fn jail_rate(mut scenario: impl FnMut(&mut Rng) -> Option<u64>) -> f64 {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let jailed = (0..TRIALS).filter(|_| scenario(&mut rng).is_some()).count();
    jailed as f64 / TRIALS as f64
}

/// FP-02/FP-03: a healthy validator is omitted from each block's evidence
/// independently with probability `p` (late precommits).
fn independent(p: f64) -> f64 {
    jail_rate(|rng| first_jail(BLOCKS, |_, _| rng.chance(p)))
}

#[test]
fn fp03_independent_late_precommits() {
    println!("\nFP-03  independent omission, {TRIALS} trials x {BLOCKS} blocks, window {WINDOW}, threshold {THRESHOLD}%, f={F}");
    println!("       p(omitted/block)   P(falsely jailed within {BLOCKS} blocks)");
    let mut rates = vec![];
    for p in [0.0, 0.02, 0.05, 0.10, 0.15, 0.20, 0.25, 0.30, 0.40] {
        let r = independent(p);
        println!("       {:>5.0}%             {:>6.1}%", p * 100.0, r * 100.0);
        rates.push((p, r));
    }
    assert_eq!(rates[0].1, 0.0, "a validator never omitted must never be jailed");
    assert!(rates.windows(2).all(|w| w[1].1 + 0.02 >= w[0].1), "jail probability must not fall as omissions rise: {rates:?}");
    assert!(rates.iter().find(|(p, _)| *p == 0.05).unwrap().1 < 0.01, "5% random omission is well inside the threshold");
    assert!(rates.last().unwrap().1 > 0.99, "40% omission is certain to be jailed");
}

/// FP-03: a healthy validator that drops off for `len` consecutive blocks
/// (a network hiccup, a GC pause, a restart). Outages start in the first half
/// of every 200-block period, so no 100-block window ever holds two of them.
fn burst(len: u64) -> f64 {
    jail_rate(|rng| {
        let mut start = 0;
        let mut next_period = 0;
        first_jail(BLOCKS, |h, _| {
            if h >= next_period { start = next_period + rng.below(WINDOW as u64 - len + 1); next_period += 2 * WINDOW as u64; }
            h >= start && h < start + len
        })
    })
}

#[test]
fn fp03_bursty_unavailability() {
    println!("\nFP-03  an isolated outage of N consecutive blocks (every proposer omits), at most one per 100-block window");
    println!("       outage length   P(jailed)    (at 2 s/block, 21 blocks = 42 s)");
    let mut out = vec![];
    for len in [3u64, 10, 15, 20, 21, 25, 30, 50] {
        let r = burst(len);
        println!("       {len:>4} blocks      {:>6.1}%", r * 100.0);
        out.push((len, r));
    }
    let at = |l: u64| out.iter().find(|(x, _)| *x == l).unwrap().1;
    assert_eq!(at(10), 0.0, "a 10-block hiccup per window must not jail");
    assert!(at(30) > 0.99, "a 30-block outage in a window is jailed");
    assert!(out.windows(2).all(|w| w[1].1 + 0.02 >= w[0].1), "longer outages must not be safer: {out:?}");
}

/// FP-04: `k` proposers ALWAYS omit the victim, everyone else never does.
#[test]
fn fp04_byzantine_proposers_and_the_discount() {
    println!("\nFP-04  k of 4 proposers always omit a healthy validator (f = {F} discounted)");
    for (k, noise) in [(0u64, 0.0), (1, 0.0), (1, 0.05), (1, 0.10), (2, 0.0), (3, 0.0)] {
        let r = jail_rate(|rng| first_jail(BLOCKS, |_, proposer| proposer < k || rng.chance(noise)));
        println!("       {k} omitting proposer(s) + {:>2.0}% honest-slow noise  -> P(jailed) {:>5.1}%", noise * 100.0, r * 100.0);
        match (k, noise) {
            (0, _) => assert_eq!(r, 0.0),
            (1, n) if n <= 0.05 => assert_eq!(r, 0.0, "one Byzantine proposer (<= f) must not get a healthy validator jailed"),
            (2, _) | (3, _) => assert!(r > 0.99, "more than f omitting proposers defeat the discount"),
            _ => {}
        }
    }
    println!("       => the discount protects against up to f = {F} malicious proposers, not against f + 1.");
}

/// FP-05: a genuinely absent validator is still caught, and how fast.
#[test]
fn fp05_genuine_outage_is_detected() {
    println!("\nFP-05  validator goes fully offline at block T (omitted by every proposer)");
    for t in [0u64, 10, 150, 301, 1_000] {
        let jailed = first_jail(BLOCKS, |h, _| h >= t);
        let at = jailed.expect("a validator offline for the rest of the run must be jailed");
        println!("       offline from block {t:>5} -> jailed at block {at:>5} ({} blocks after it left)", at - t);
        assert!(at >= WINDOW as u64 - 1, "never before the window fills");
        assert!(at - t <= WINDOW as u64, "detected within one window of going offline");
    }
}

/// Per-human-day exposure at the measured omission rate, for the record: a
/// threshold of 20% over 100 blocks means a validator needs >= 21 misses in
/// ANY 100-block stretch after the window has filled.
#[test]
fn fp03_minimum_misses_to_be_jailed() {
    let mut w = LivenessWindow::new(WINDOW);
    for h in 0..WINDOW as u64 { w.record(true, &format!("p{}", h % PROPOSERS)); }
    let mut misses = 0;
    for h in 0..WINDOW as u64 {
        w.record(false, &format!("p{}", h % PROPOSERS));
        misses += 1;
        if w.robust_missed_pct(F) > THRESHOLD { break; }
    }
    println!("\nFP-03  a healthy validator is jailed after {misses} consecutive missed blocks once the window is full");
    assert!((20..=40).contains(&misses), "unexpected minimum {misses}");
}
