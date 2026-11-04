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
///
/// What makes it fail: (1) any panic in the process during the run, including one on a runtime worker thread (the
/// NODE-TOKIO-1 panic happens inside the timer driver, not inside a task, so no `JoinHandle` would report it), via a
/// panic hook; (2) any task that panics or ends early (every task is an endless loop, so only cancellation by this test is
/// a normal ending); (3) any task that stops making progress in the second half of the run.
#[test]
#[ignore = "stress test (30 s by default)"]
fn interval_select_stress_does_not_trip_the_timer_driver() {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    static PANICKED: AtomicBool = AtomicBool::new(false);
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| { PANICKED.store(true, Ordering::SeqCst); previous(info); }));

    let secs: u64 = std::env::var("CF_TOKIO_STRESS_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(30).max(2);
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(4).enable_all().build().unwrap();
    let (outcome, problems) = rt.block_on(async move {
        let n = Arc::new(tokio::sync::Notify::new());
        let mut handles = vec![];
        let mut progress: Vec<Arc<AtomicU64>> = vec![];
        for _ in 0..3 {
            let n = n.clone();
            let c = Arc::new(AtomicU64::new(0)); progress.push(c.clone());
            handles.push(tokio::spawn(async move { loop { n.notify_one(); c.fetch_add(1, Ordering::Relaxed); tokio::task::yield_now().await; } }));
        }
        for _ in 0..8 {
            let n = n.clone();
            let c = Arc::new(AtomicU64::new(0)); progress.push(c.clone());
            handles.push(tokio::spawn(async move {
                let mut iv = tokio::time::interval(Duration::from_millis(1));
                loop { tokio::select! { _ = iv.tick() => { c.fetch_add(1, Ordering::Relaxed); } _ = n.notified() => {} } }
            }));
        }
        tokio::time::sleep(Duration::from_secs(secs / 2)).await;
        let mid: Vec<u64> = progress.iter().map(|c| c.load(Ordering::Relaxed)).collect();
        tokio::time::sleep(Duration::from_secs(secs - secs / 2)).await;
        let mut problems: Vec<String> = vec![];
        for (i, c) in progress.iter().enumerate() {
            if c.load(Ordering::Relaxed) <= mid[i] { problems.push(format!("task {i} made no progress in the second half of the run")); }
        }
        // Cancel everything, then inspect how each task ended.
        for h in &handles { h.abort(); }
        let mut outcome = vec![];
        for (i, h) in handles.into_iter().enumerate() {
            match h.await {
                Ok(()) => problems.push(format!("task {i} ended early (its loop never returns)")),
                Err(e) if e.is_panic() => problems.push(format!("task {i} panicked")),
                Err(e) if e.is_cancelled() => outcome.push(i),
                Err(e) => problems.push(format!("task {i} failed unexpectedly: {e}")),
            }
        }
        (outcome, problems)
    });
    rt.shutdown_timeout(Duration::from_secs(10));
    assert!(!PANICKED.load(Ordering::SeqCst), "a panic occurred during the stress run (see the output above); NODE-TOKIO-1 has regressed");
    assert!(problems.is_empty(), "stress run failed: {problems:?}");
    assert_eq!(outcome.len(), 11, "every task must end only by cancellation");
}
