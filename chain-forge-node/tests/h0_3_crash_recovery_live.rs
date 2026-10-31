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
///   C-06  Double-sign guard ahead of restored state height: signing blocked.
///   C-06b Double-sign guard behind restored state height: reports GuardBehindState
///         (not an error — the consensus engine advances the guard before signing).
///   C-07  Four-node network: crash-restart of one node, state roots converge.
///   C-08  Crash-during-write: previous generation survives, CURRENT unchanged.
///   C-09  Generation pruning: gen-N-2 pruned, gen-N-1 retained.
///   C-10  Manifest hash mismatch: load_snapshot returns HashMismatch error.

#[cfg(test)]
mod h0_3_crash_recovery_live {
    use std::io::{BufRead, Write as IoWrite};
    use std::net::TcpStream;
    use std::time::Duration;
    use chain_forge_node::persistence::{
        self, PersistError, SigningCompatibility, SNAPSHOT_FILES,
        gen_label, write_snapshot, load_snapshot, check_signing_compatibility,
    };

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

    // ── helper: build a minimal valid snapshot content set ──────────────────

    fn make_state_json(height: u64) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "height": height,
            "accounts": {},
            "metadata": {},
        })).unwrap()
    }

    fn make_chain_store_json(height: u64) -> Vec<u8> {
        if height == 0 {
            return serde_json::to_vec(&serde_json::json!({})).unwrap();
        }
        let mut m = serde_json::Map::new();
        m.insert(height.to_string(), serde_json::json!([null, {"height": height, "tx_data": ""}]));
        serde_json::to_vec(&m).unwrap()
    }

    fn valid_contents(height: u64) -> Vec<(&'static str, Vec<u8>)> {
        SNAPSHOT_FILES.iter().map(|&name| {
            let bytes = match name {
                "state.json"       => make_state_json(height),
                "chain_store.json" => make_chain_store_json(height),
                other              => format!("{{\"_file\":\"{other}\"}}").into_bytes(),
            };
            (name, bytes)
        }).collect()
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

    /// C-02: A committed snapshot whose state.json contains invalid JSON
    /// must return HashMismatch (the manifest hash won't match the garbage
    /// bytes), NOT a silent genesis fallback.
    ///
    /// Implementation: write a valid snapshot, then corrupt state.json in
    /// the generation directory. load_snapshot must return Err(HashMismatch).
    #[test]
    fn c_02_corrupted_state_json_refuses_start() {
        let dir = tempfile::tempdir().expect("tempdir");

        // Write a valid generation-based snapshot.
        write_snapshot(dir.path(), 5, &valid_contents(5)).unwrap();

        // Corrupt state.json in the committed generation directory.
        let corrupt = b"{ \"height\": 999, \"accounts\": CORRUPT_NOT_JSON }";
        let gen_dir = dir.path().join("snapshots").join("gen-000001");
        std::fs::write(gen_dir.join("state.json"), corrupt).unwrap();

        // load_snapshot must detect the hash mismatch and refuse.
        let result = load_snapshot(dir.path());
        assert!(
            matches!(result, Err(PersistError::HashMismatch { .. })),
            "corrupted state.json must produce HashMismatch, got: {:?}",
            result.as_ref().err().map(|e| e.to_string())
                  .unwrap_or_else(|| "Ok(...)".into())
        );
    }

    // ── C-03: truncated state.json ───────────────────────────────────────────

    /// C-03: Truncate state.json to a partial prefix — simulates a torn
    /// write that leaves a valid JSON prefix but no closing brace.
    /// load_snapshot must return HashMismatch (size/hash won't match
    /// manifest), never Ok().
    #[test]
    fn c_03_truncated_state_json_refuses_start() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_snapshot(dir.path(), 5, &valid_contents(5)).unwrap();

        // Overwrite with a truncated prefix.
        let truncated = b"{ \"height\": 5, \"accounts\": {";
        let gen_dir = dir.path().join("snapshots").join("gen-000001");
        std::fs::write(gen_dir.join("state.json"), truncated).unwrap();

        let result = load_snapshot(dir.path());
        assert!(
            matches!(result, Err(PersistError::HashMismatch { .. })),
            "truncated state.json must produce HashMismatch, got: {:?}",
            result.as_ref().err().map(|e| e.to_string())
                  .unwrap_or_else(|| "Ok(...)".into())
        );
    }

    // ── C-04: missing identity.json (partial write) ──────────────────────────

    /// C-04: Write a generation where state.json is present but
    /// identity.json was never written. The manifest lists identity.json
    /// so load_snapshot must return MissingFile.
    ///
    /// Simulates a crash after the first file was fsynced but before
    /// the whole generation was committed.  CURRENT never advances in
    /// this test — the incomplete generation is ignored.
    #[test]
    fn c_04_partial_write_missing_identity_detected() {
        let dir = tempfile::tempdir().expect("tempdir");

        // Write a valid gen-000001 first so CURRENT exists.
        write_snapshot(dir.path(), 5, &valid_contents(5)).unwrap();

        // Simulate a partial gen-000002: create the directory and write
        // state.json but never write identity.json or the manifest.
        // Because CURRENT still points at gen-000001, this test is really
        // about what happens if gen-000001 was somehow written partially.
        // To simulate that, directly tamper with gen-000001.
        let gen_dir = dir.path().join("snapshots").join("gen-000001");
        std::fs::remove_file(gen_dir.join("identity.json")).unwrap();

        let result = load_snapshot(dir.path());
        assert!(
            matches!(result, Err(PersistError::MissingFile { .. })),
            "missing identity.json must produce MissingFile, got: {:?}",
            result.as_ref().err().map(|e| e.to_string())
                  .unwrap_or_else(|| "Ok(...)".into())
        );
    }

    // ── C-05: chain_store.json height mismatch ───────────────────────────────

    /// C-05: state.json says height 10, chain_store.json only has blocks 1-9.
    /// This simulates FM-1: a crash after state.json was written but before
    /// chain_store.json was updated.
    ///
    /// In the generation-based scheme this is caught by the manifest hash
    /// check (chain_store.json bytes have changed) OR by the height cross-check.
    /// Either way, load_snapshot must return an error.
    #[test]
    fn c_05_height_mismatch_state_vs_chain_store_detected() {
        let dir = tempfile::tempdir().expect("tempdir");

        // Write a valid snapshot at height 10 then tamper with chain_store.
        write_snapshot(dir.path(), 10, &valid_contents(10)).unwrap();
        let gen_dir = dir.path().join("snapshots").join("gen-000001");

        // Overwrite chain_store.json with height-9 data (mismatches manifest hash).
        let chain_store_9 = make_chain_store_json(9);
        std::fs::write(gen_dir.join("chain_store.json"), &chain_store_9).unwrap();

        let result = load_snapshot(dir.path());
        assert!(
            matches!(
                result,
                Err(PersistError::HashMismatch { .. }) | Err(PersistError::HeightMismatch { .. })
            ),
            "height mismatch between state.json (10) and chain_store.json (9) \
             must produce HashMismatch or HeightMismatch, got: {:?}",
            result.as_ref().err().map(|e| e.to_string())
                  .unwrap_or_else(|| "Ok(...)".into())
        );
    }

    // ── C-06: signing guard ahead of state height ─────────────────────────────

    /// C-06a: consensus_signing.json reports last_height=15, state snapshot
    /// is at height 10. The guard is AHEAD of state — this validator may
    /// have voted on blocks 11–15 that are not reflected in the snapshot.
    ///
    /// check_signing_compatibility must return GuardAheadOfState.
    /// main.rs's startup handler maps that to PersistStartup::SigningBlocked
    /// and exits rather than starting the validator.
    #[test]
    fn c_06_sign_guard_ahead_of_state_is_blocked() {
        let guard = serde_json::json!({
            "last_height": 15,
            "last_round": 0,
            "last_step": "Precommit"
        });
        let result = check_signing_compatibility(&guard, 10).unwrap();
        assert!(
            matches!(
                result,
                SigningCompatibility::GuardAheadOfState {
                    guard_height: 15,
                    state_height: 10
                }
            ),
            "guard(15) > state(10) must produce GuardAheadOfState"
        );
    }

    // ── C-06b: signing guard behind state height ──────────────────────────────

    /// C-06b: guard at height 14, state at height 15. The guard is BEHIND
    /// state — the signing file was not updated on the last block.
    ///
    /// check_signing_compatibility must return GuardBehindState (not an error
    /// — the consensus engine can safely advance the guard to state_height
    /// before resuming signing, because it cannot re-sign at heights it
    /// already committed by definition of the committed snapshot).
    #[test]
    fn c_06b_sign_guard_height_consistent_after_restart() {
        let guard = serde_json::json!({
            "last_height": 14,
            "last_round": 0,
            "last_step": "Precommit"
        });
        let result = check_signing_compatibility(&guard, 15).unwrap();
        assert!(
            matches!(
                result,
                SigningCompatibility::GuardBehindState {
                    guard_height: 14,
                    state_height: 15
                }
            ),
            "guard(14) < state(15) must produce GuardBehindState"
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

    // ── C-08: crash-during-write — previous generation survives ──────────────

    /// C-08: A crash mid-write (before CURRENT is updated) must leave the
    /// previous committed generation intact and readable.
    ///
    /// Invariant: CURRENT is only updated after the new generation directory
    /// is fully written and fsynced. A partial new generation is never
    /// committed and is ignored on restart.
    #[test]
    fn c_08_crash_during_write_previous_generation_survives() {
        let dir = tempfile::tempdir().expect("tempdir");

        // Write gen-000001 successfully.
        write_snapshot(dir.path(), 5, &valid_contents(5)).unwrap();

        // Simulate a crash during gen-000002: create the directory and write
        // some files, but do NOT call write_snapshot (CURRENT stays at gen-000001).
        let partial = dir.path().join("snapshots").join("gen-000002");
        std::fs::create_dir_all(&partial).unwrap();
        std::fs::write(partial.join("state.json"), b"partial content").unwrap();
        // manifest.json is deliberately absent — the crash happened before it
        // was written.

        // On restart, load_snapshot must serve gen-000001 (the last committed
        // generation), not the partial gen-000002.
        let snap = load_snapshot(dir.path())
            .expect("load must succeed")
            .expect("committed snapshot must be found");
        assert_eq!(snap.generation, "gen-000001", "must load the committed generation");
        assert_eq!(snap.height, 5);
    }

    // ── C-09: generation pruning ──────────────────────────────────────────────

    /// C-09: After three successful snapshots, gen-N-2 (the oldest) must be
    /// pruned from disk. gen-N-1 (one back) is retained as a fallback.
    #[test]
    fn c_09_generation_pruning_retains_n_minus_1() {
        let dir = tempfile::tempdir().expect("tempdir");

        write_snapshot(dir.path(), 1, &valid_contents(1)).unwrap(); // gen-000001
        write_snapshot(dir.path(), 2, &valid_contents(2)).unwrap(); // gen-000002
        write_snapshot(dir.path(), 3, &valid_contents(3)).unwrap(); // gen-000003

        // gen-000001 (N-2) must be gone.
        assert!(
            !dir.path().join("snapshots").join("gen-000001").exists(),
            "gen-000001 (N-2) must be pruned after gen-000003 is committed"
        );
        // gen-000002 (N-1) must still be present.
        assert!(
            dir.path().join("snapshots").join("gen-000002").exists(),
            "gen-000002 (N-1) must be retained as a fallback"
        );
        // gen-000003 (N) is the live committed generation.
        let snap = load_snapshot(dir.path()).unwrap().unwrap();
        assert_eq!(snap.generation, "gen-000003");
        assert_eq!(snap.height, 3);
    }

    // ── C-10: manifest hash mismatch ─────────────────────────────────────────

    /// C-10: After writing a valid generation, overwrite a non-critical file
    /// (agents.json) with different content. load_snapshot must detect the
    /// hash mismatch and return Err(HashMismatch), not silently load.
    #[test]
    fn c_10_manifest_hash_mismatch_is_detected() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_snapshot(dir.path(), 7, &valid_contents(7)).unwrap();

        let gen_dir = dir.path().join("snapshots").join("gen-000001");
        // Overwrite agents.json with different content (same size to pass
        // a naive size check, but different hash).
        std::fs::write(gen_dir.join("agents.json"), b"{\"_tampered\":true}").unwrap();

        let result = load_snapshot(dir.path());
        assert!(
            matches!(result, Err(PersistError::HashMismatch { .. })),
            "tampered agents.json must produce HashMismatch"
        );
    }
}
