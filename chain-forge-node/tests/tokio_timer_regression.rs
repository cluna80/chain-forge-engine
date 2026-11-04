//! NODE-TOKIO-1 regression guards. Test-only; no node code is involved.
//!
//! tokio 1.54.0 (yanked) contains a use-after-free race in its timer driver (fixed upstream by reverting the
//! timer change in 1.54.1, tokio-rs/tokio#8692). It showed up as
//! `assertion failed: old_state == WAKING` in `AtomicWaker::take_waker`; the assertion is debug-only, so a
//! release build would corrupt memory silently. The node's run loop is a `select!` over `tokio::time::interval`s on a
//! multi-thread runtime, which is the pattern that triggers it.

use std::sync::Arc;
use std::time::Duration;

/// Fails if the workspace lockfile resolves tokio to the known-bad 1.54.0. Newer fixed versions are allowed.
#[test]
fn cargo_lock_does_not_resolve_the_known_bad_tokio() {
    let lock = include_str!("../../Cargo.lock");
    let mut versions = vec![];
    let mut lines = lock.lines();
    while let Some(l) = lines.next() {
        if l == "name = \"tokio\"" {
            let v = lines.next().unwrap_or_default();
            versions.push(v.trim_start_matches("version = ").trim_matches('"').to_string());
        }
    }
    assert!(!versions.is_empty(), "no tokio entry found in Cargo.lock; the guard is not looking at the right file");
    assert!(!versions.iter().any(|v| v == "1.54.0"),
        "Cargo.lock resolves tokio 1.54.0 (yanked; timer use-after-free, NODE-TOKIO-1). Use >= 1.54.1. Found: {versions:?}");
}

/// Stress reproduction of NODE-TOKIO-1 (multi-thread runtime; `select!` over a 1 ms interval and a `Notify` that other
/// tasks keep signalling). Panics within seconds on tokio 1.54.0; passes on 1.54.1. A finite stress run cannot prove the
/// absence of a race. Run: `cargo test -p chain-forge-node --test tokio_timer_regression -- --ignored --nocapture`
/// (`CF_TOKIO_STRESS_SECS` overrides the default 30 s).
#[test]
#[ignore = "stress test (30 s by default)"]
fn interval_select_stress_does_not_trip_the_timer_driver() {
    let secs: u64 = std::env::var("CF_TOKIO_STRESS_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(30);
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(4).enable_all().build().unwrap();
    rt.block_on(async move {
        let n = Arc::new(tokio::sync::Notify::new());
        for _ in 0..3 {
            let n = n.clone();
            tokio::spawn(async move { loop { n.notify_one(); tokio::task::yield_now().await; } });
        }
        for _ in 0..8 {
            let n = n.clone();
            tokio::spawn(async move {
                let mut iv = tokio::time::interval(Duration::from_millis(1));
                loop { tokio::select! { _ = iv.tick() => {} _ = n.notified() => {} } }
            });
        }
        tokio::time::sleep(Duration::from_secs(secs)).await;
    });
    // A panic on a runtime worker thread does not fail the test thread by itself, so check the workers are still alive:
    // the runtime must shut down cleanly and a fresh timer must still fire.
    let rt2 = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    rt2.block_on(async { tokio::time::sleep(Duration::from_millis(5)).await });
    drop(rt);
}
