/// H0-3 — Atomic State Persistence and Safe Crash Recovery
///
/// Security invariants under test:
///   H0-3-I1: A node MUST NOT silently restart from genesis after any persist failure.
///   H0-3-I2: A corrupted or truncated state file MUST produce an explicit error,
///             not a silent fallback to block 0.
///   H0-3-I3: A partial write (crash between file 1 and file 8 of persist_state)
///             MUST NOT produce a mixed-height snapshot that loads successfully.
///   H0-3-I4: After a clean restart from a valid snapshot, height, balances,
///             identity bindings, validator state, and state root MUST all match
///             the pre-restart values.
///   H0-3-I5: The consensus double-sign guard height MUST be consistent with the
///             restored state height.
///
/// Test sequence:
///   C-01  Clean round-trip: commit blocks, restart, verify full state match.
///   C-02  Corrupted state.json: node must refuse, not fall back to genesis.
///   C-03  Truncated state.json: refuse, not genesis.
///   C-04  Partial write — state.json present, identity.json absent: detected.
///   C-05  Partial write — state.json height N, chain_store.json height N-1: detected.
///   C-06  Double-sign guard height < restored state height: detected/corrected.
///   C-07  Four-node network: crash-restart of one node, state roots converge.

#[cfg(test)]
mod h0_3_crash_recovery_live {
    use std::io::{BufRead, Write as IoWrite};
    use std::net::TcpStream;
    use std::path::PathBuf;
    use std::time::Duration;

    // ── shared HTTP helpers (no external crates, matches devnet_4node style) ──

    fn api_get_json(port: u16, path: &str) -> Option<serde_json::Value> {
        let mut stream =
            TcpStream::connect(format!("127.0.0.1:{port}")).ok()?;
        stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
        let req = format!(
            "GET {path} HTTP/1.0\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(req.as_bytes()).ok()?;
        let mut body = String::new();
        let reader = std::io::BufReader::new(stream);
        let mut past = false;
        for line in reader.lines() {
            let line = line.ok()?;
            if past { body.push_str(&line); } else if line.is_empty() { past = true; }
        }
        serde_json::from_str(&body).ok()
    }

    fn poll_status(port: u16) -> Option<serde_json::Value> {
        api_get_json(port, "/api/status")
    }

    fn wait_for_height(port: u16, target: u64, timeout: Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            if let Some(j) = poll_status(port) {
                if j["height"].as_u64().unwrap_or(0) >= target { return true; }
            }
            std::thread::sleep(Duration::from_millis(300));
        }
        false
    }

    // ── C-01: clean round-trip ───────────────────────────────────────────────

    /// C-01 is the baseline restart test — must pass both before and after
    /// H0-3. The full single-node harness is wired in once C-02..C-06 are
    /// green, so we can run a clean CI sequence end-to-end.
    #[test]
    fn c_01_clean_restart_preserves_state() {
        todo!("C-01: wire single-node genesis restart harness \
               (implement during H0-3 — after commit-marker scheme is in place)")
    }

    // ── C-02: corrupted state.json ───────────────────────────────────────────

    /// C-02: Write garbage bytes into persist/state.json.
    /// Restarting the node MUST NOT fall back to genesis.
    /// Required post-H0-3: load_persisted_state returns PersistError::Corrupted
    ///   (or equivalent), and the node exits with a non-zero status rather than
    ///   continuing at height 0.
    ///
    /// Current behaviour (pre-H0-3): serde_json parse fails → warn + genesis. WRONG.
    #[test]
    fn c_02_corrupted_state_json_refuses_start() {
        let dir = tempfile::tempdir().expect("tempdir");
        let persist = dir.path().join("persist");
        std::fs::create_dir_all(&persist).unwrap();

        // Syntactically invalid JSON — simulates a torn write leaving garbage.
        let corrupt = b"{ \"height\": 999, \"accounts\": CORRUPT_NOT_JSON }";
        std::fs::write(persist.join("state.json"), corrupt).unwrap();

        // Post-H0-3: reading a corrupted state.json must be a fatal error.
        // This assertion will fail until the implementation is complete.
        panic!(
            "C-02 FAILING (expected pre-implementation): \
             corrupted state.json must not allow genesis fallback — \
             implement explicit PersistError::Corrupted in load_persisted_state"
        );
    }

    // ── C-03: truncated state.json ───────────────────────────────────────────

    /// C-03: Truncate persist/state.json to a partial prefix.
    /// Same invariant as C-02: MUST refuse, not fall back to genesis.
    #[test]
    fn c_03_truncated_state_json_refuses_start() {
        let dir = tempfile::tempdir().expect("tempdir");
        let persist = dir.path().join("persist");
        std::fs::create_dir_all(&persist).unwrap();

        // Truncated mid-write: valid JSON prefix with no closing brace.
        let truncated = b"{ \"height\": 5, \"accounts\": { \"qcb1alice\": { \"address\": \"qcb1alice\"";
        std::fs::write(persist.join("state.json"), truncated).unwrap();

        panic!(
            "C-03 FAILING (expected pre-implementation): \
             truncated state.json must not allow genesis fallback"
        );
    }

    // ── C-04: missing identity.json (partial write) ──────────────────────────

    /// C-04: state.json at height 10, identity.json absent.
    /// Simulates a crash after file 1 (state.json) was written but before
    /// file 2 (identity.json) was written.
    ///
    /// Required: commit manifest must list all files; missing any listed file
    ///   is a fatal error, not a silent partial restore.
    #[test]
    fn c_04_partial_write_missing_identity_detected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let persist = dir.path().join("persist");
        std::fs::create_dir_all(&persist).unwrap();

        let state_json = serde_json::json!({
            "height": 10,
            "accounts": {},
            "metadata": { "commit-height": "10" },
            "state_root": "aaaa"
        });
        std::fs::write(
            persist.join("state.json"),
            serde_json::to_string(&state_json).unwrap(),
        ).unwrap();
        // identity.json deliberately absent — partial write simulation.

        panic!(
            "C-04 FAILING (expected pre-implementation): \
             missing identity.json with present state.json must be detected \
             via commit manifest — implement manifest.json write in persist_state"
        );
    }

    // ── C-05: chain_store.json height mismatch ───────────────────────────────

    /// C-05: state.json says height 10, chain_store.json only has blocks 1-9.
    /// This is the canonical FM-1 failure: a crash after state.json was written
    /// but before chain_store.json was updated.
    ///
    /// Required: cross-file height consistency check on load.
    #[test]
    fn c_05_height_mismatch_state_vs_chain_store_detected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let persist = dir.path().join("persist");
        std::fs::create_dir_all(&persist).unwrap();

        let state_json = serde_json::json!({
            "height": 10,
            "accounts": {},
            "metadata": {},
            "state_root": "bbbb"
        });
        std::fs::write(
            persist.join("state.json"),
            serde_json::to_string(&state_json).unwrap(),
        ).unwrap();

        // chain_store with highest key = 9 (one behind state.json height).
        let mut chain_store = serde_json::Map::new();
        chain_store.insert("9".to_string(), serde_json::json!([null, {"height": 9, "tx_data": ""}]));
        std::fs::write(
            persist.join("chain_store.json"),
            serde_json::to_string(&chain_store).unwrap(),
        ).unwrap();

        panic!(
            "C-05 FAILING (expected pre-implementation): \
             height mismatch between state.json (10) and chain_store.json max-height (9) \
             must be detected — implement cross-file consistency check in load_persisted_state"
        );
    }

    // ── C-06: double-sign guard height below restored state height ────────────

    /// C-06: consensus_signing.json reports last_height=14, state.json is at
    /// height 15. A restarted validator MUST NOT be permitted to sign at a
    /// height it already finalized.
    ///
    /// Required: load_persisted_state must detect guard_height < state_height
    ///   and advance the guard (or refuse to start).
    #[test]
    fn c_06_sign_guard_height_consistent_after_restart() {
        let dir = tempfile::tempdir().expect("tempdir");
        let persist = dir.path().join("persist");
        std::fs::create_dir_all(&persist).unwrap();

        let state_json = serde_json::json!({
            "height": 15,
            "accounts": {},
            "metadata": {},
            "state_root": "cccc"
        });
        std::fs::write(
            persist.join("state.json"),
            serde_json::to_string(&state_json).unwrap(),
        ).unwrap();

        // Guard is one block behind — would allow re-signing at height 15.
        let guard_json = serde_json::json!({
            "last_height": 14,
            "last_round": 0,
            "last_step": "Precommit"
        });
        std::fs::write(
            persist.join("consensus_signing.json"),
            serde_json::to_string(&guard_json).unwrap(),
        ).unwrap();

        panic!(
            "C-06 FAILING (expected pre-implementation): \
             consensus signing guard height (14) < restored state height (15) — \
             must be detected and corrected (advance guard to state_height) or rejected"
        );
    }

    // ── C-07: four-node crash restart, state root convergence ────────────────

    /// C-07: In a 4-node devnet, SIGKILL one node mid-run (simulating an OS
    /// crash, not a clean shutdown), restart it, and verify:
    ///   - it catches up to the canonical height
    ///   - its state_root matches the three surviving peers
    ///   - no "starting from genesis" line in its log
    ///
    /// This is the live cross-node integration gate for H0-3.
    #[test]
    fn c_07_four_node_crash_restart_converges() {
        todo!(
            "C-07: wire 4-node SIGKILL crash-restart harness — \
             implement after C-01..C-06 unit tests pass"
        )
    }
}
