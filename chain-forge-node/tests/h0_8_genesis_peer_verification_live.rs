/// H0-8 — Genesis-Hash Peer Verification and Cross-Chain Replay Protection
///
/// ## Security invariants under test
///
///   H0-8-I1: A node MUST NOT accept consensus messages from a peer on a
///             different chain, even when that peer shares the same chain_id.
///             The genesis hash is the canonical chain identity.
///
///   H0-8-I2: A transaction signed on chain A MUST NOT be accepted as valid
///             on chain B, even when A and B share the same chain_id and
///             the same validator set was created from identical key material.
///
///   H0-8-I3: A peer whose genesis hash differs from the local node's genesis
///             hash MUST be disconnected and placed on a deny list.  Subsequent
///             reconnection attempts from the same peer MUST be refused without
///             retrying the handshake.
///
///   H0-8-I4: Matching chain_id alone is NOT sufficient to accept a peer.
///             A node MAY share chain_id with a different chain (e.g. a fork
///             started at height 0 with different initial accounts) but MUST
///             reject it if its genesis hash differs.
///
///   H0-8-I5: A valid peer on the same chain (matching chain_id AND genesis
///             hash) MUST be accepted normally.  The protection MUST NOT
///             break same-chain connectivity.
///
/// ## Test sequence
///
///   G-01  Genesis hash is stable: compute_genesis_hash returns the same value
///         for the same genesis file, and a different value for any mutation.
///   G-02  Peer with wrong genesis hash is rejected at the protocol layer and
///         does not appear in the trusted peer set.
///   G-03  Cross-chain transaction replay: a transaction signed on chain A is
///         rejected when replayed on chain B (same chain_id, different genesis).
///         The signing domain MUST cover the genesis hash, not just chain_id.
///   G-04  Same chain_id, different genesis hash: peer rejected.
///   G-05  Previously rejected peer (on deny list) cannot reconnect.
///   G-06  Valid same-chain peer is accepted normally.
///   G-07  Four-node live network: a fifth node from a different genesis cannot
///         join the network or inject consensus messages.

#[cfg(test)]
mod h0_8_genesis_peer_verification_live {
    use std::io::{BufRead, Write as IoWrite};
    use std::net::{TcpListener, TcpStream};
    use std::time::Duration;
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};

    // ── Imports that WILL fail until H0-8 is implemented ────────────────────
    //
    // G-01 requires:
    use chain_forge_core::{GenesisConfig, compute_genesis_hash};
    //
    // G-02, G-04, G-05, G-06 require:
    use chain_forge_p2p::{PeerInfo, PeerManager, PeerId};
    //
    // G-03 requires (added to chain_forge_execution as part of H0-8):
    use chain_forge_execution::TransactionDomain;
    //
    // G-03 also uses (already exist):
    use chain_forge_crypto::{MlDsaScheme, SignatureScheme};

    // ── HTTP helpers (same pattern as other live tests) ──────────────────────

    fn api_get_json(port: u16, path: &str) -> Option<serde_json::Value> {
        let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).ok()?;
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

    fn poll_height(port: u16) -> u64 {
        api_get_json(port, "/api/status")
            .and_then(|j| j["height"].as_u64())
            .unwrap_or(0)
    }

    fn wait_for_height(port: u16, target: u64, timeout: Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            if poll_height(port) >= target { return true; }
            std::thread::sleep(Duration::from_millis(300));
        }
        false
    }

    fn free_port() -> u16 {
        TcpListener::bind("127.0.0.1:0")
            .expect("free_port: bind failed")
            .local_addr()
            .expect("free_port: addr")
            .port()
    }

    fn node_binary() -> Option<PathBuf> {
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let repo = manifest.parent().unwrap().to_path_buf();
        let target = std::env::var("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| repo.join("target"));
        let exe = format!("chain-forge-node{}", std::env::consts::EXE_SUFFIX);
        let debug   = target.join("debug").join(&exe);
        let release = target.join("release").join(&exe);
        match (debug.metadata().and_then(|m| m.modified()),
               release.metadata().and_then(|m| m.modified())) {
            (Ok(dt), Ok(rt)) => Some(if dt >= rt { debug } else { release }),
            (Ok(_), Err(_))  => Some(debug),
            (Err(_), Ok(_))  => Some(release),
            _                => None,
        }
    }

    fn genesis_4node_mldsa_path() -> PathBuf {
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        manifest.join("tests/devnet/genesis-4node-mldsa.json")
    }

    fn keys_dir() -> PathBuf {
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        manifest.join("tests/devnet/keys")
    }

    struct NodeGuard { child: Child }
    impl Drop for NodeGuard {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    fn spawn_node(
        bin:       &PathBuf,
        genesis:   &PathBuf,
        validator: &str,
        key_file:  &PathBuf,
        data_dir:  &PathBuf,
        api_port:  u16,
        p2p_port:  u16,
        bootstrap: Option<&str>,
        log_path:  &PathBuf,
    ) -> NodeGuard {
        let log_file = std::fs::File::create(log_path).expect("create log file");
        let mut cmd = Command::new(bin);
        cmd.args([
            "--genesis",   genesis.to_str().unwrap(),
            "--validator", validator,
            "--key-file",  key_file.to_str().unwrap(),
            "--data-dir",  data_dir.to_str().unwrap(),
            "--api-port",  &api_port.to_string(),
            "--p2p-port",  &p2p_port.to_string(),
        ]);
        if let Some(b) = bootstrap {
            cmd.args(["--bootstrap", b]);
        }
        cmd.stdout(Stdio::from(log_file.try_clone().unwrap()))
           .stderr(Stdio::from(log_file));
        NodeGuard { child: cmd.spawn().expect("spawn node") }
    }

    // ── Genesis fixtures ──────────────────────────────────────────────────────
    //
    // Chain A: the canonical ML-DSA devnet genesis.
    // Chain B: same chain_id as A, different genesis_time → different genesis hash.
    //          This is the critical attack scenario: matching chain_id must NOT
    //          be sufficient to accept a peer.

    /// Returns the genesis-A JSON, or None if the devnet file is not present
    /// (e.g. on a freshly-cloned machine that hasn't run `make devnet-keys`).
    /// Tests that depend on this file skip themselves when it returns None.
    fn genesis_a_json() -> Option<String> {
        let path = genesis_4node_mldsa_path();
        if !path.exists() {
            println!("SKIP: genesis-4node-mldsa.json not found at {path:?}");
            return None;
        }
        Some(std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("cannot read genesis A at {path:?}: {e}")))
    }

    /// Chain B shares chain_id with chain A but differs in genesis_time.
    /// compute_genesis_hash(B) must ≠ compute_genesis_hash(A).
    fn genesis_b_json(a_json: &str) -> String {
        let mut v: serde_json::Value = serde_json::from_str(a_json).unwrap();
        v["genesis_time"] = serde_json::json!("2099-01-01T00:00:00Z");
        serde_json::to_string_pretty(&v).unwrap()
    }

    /// Chain C has a distinct chain_id (used in G-01 sanity check).
    fn genesis_c_json(a_json: &str) -> String {
        let mut v: serde_json::Value = serde_json::from_str(a_json).unwrap();
        v["chain_id"]     = serde_json::json!("different-chain-id-999");
        v["genesis_time"] = serde_json::json!("2099-06-01T00:00:00Z");
        serde_json::to_string_pretty(&v).unwrap()
    }

    // ══════════════════════════════════════════════════════════════════════════
    // G-01 — compute_genesis_hash is deterministic and mutation-sensitive
    // ══════════════════════════════════════════════════════════════════════════

    /// G-01: compute_genesis_hash returns the same hash for the same input and
    /// a different hash for any canonical mutation.
    ///
    /// FAILS UNTIL: compute_genesis_hash() is added to chain-forge-core.
    #[test]
    fn g_01_genesis_hash_is_stable_and_mutation_sensitive() {
        let Some(a_json) = genesis_a_json() else { return; };
        let genesis_a: GenesisConfig = serde_json::from_str(&a_json).unwrap();
        let genesis_b: GenesisConfig = serde_json::from_str(&genesis_b_json(&a_json)).unwrap();
        let genesis_c: GenesisConfig = serde_json::from_str(&genesis_c_json(&a_json)).unwrap();

        let hash_a1 = compute_genesis_hash(&genesis_a);
        let hash_a2 = compute_genesis_hash(&genesis_a);
        let hash_b  = compute_genesis_hash(&genesis_b);
        let hash_c  = compute_genesis_hash(&genesis_c);

        // Deterministic: same genesis → same hash.
        assert_eq!(hash_a1, hash_a2,
            "G-01: compute_genesis_hash must be deterministic");

        // Mutation-sensitive: different genesis_time → different hash.
        assert_ne!(hash_a1, hash_b,
            "G-01: chain A and chain B share chain_id but differ in genesis_time — \
             their genesis hashes MUST differ");

        // Different chain_id → different hash.
        assert_ne!(hash_a1, hash_c,
            "G-01: chain A and chain C have different chain_id — genesis hashes MUST differ");

        // Hash is a 64-character lowercase hex string (SHA-256).
        assert_eq!(hash_a1.len(), 64,
            "G-01: genesis hash must be a 64-character lowercase hex string (SHA-256); \
             got len={}", hash_a1.len());
        assert!(hash_a1.chars().all(|c| c.is_ascii_hexdigit()),
            "G-01: genesis hash must contain only hex digits; got {:?}", &hash_a1);
    }

    // ══════════════════════════════════════════════════════════════════════════
    // G-02 — peer with wrong genesis hash is rejected
    // ══════════════════════════════════════════════════════════════════════════

    /// G-02: When a peer advertises the correct chain_id but a different genesis
    /// hash, the local node must reject it and NOT add it to the trusted peer set.
    ///
    /// FAILS UNTIL:
    ///   - PeerInfo gains a `genesis_hash: Option<String>` field
    ///   - PeerManager gains set_local_genesis_hash() and try_accept_peer()
    #[test]
    fn g_02_peer_with_wrong_genesis_hash_is_rejected() {
        let Some(a_json) = genesis_a_json() else { return; };
        let genesis_a: GenesisConfig = serde_json::from_str(&a_json).unwrap();
        let genesis_b: GenesisConfig = serde_json::from_str(&genesis_b_json(&a_json)).unwrap();

        let local_genesis_hash   = compute_genesis_hash(&genesis_a);
        let foreign_genesis_hash = compute_genesis_hash(&genesis_b);

        // A peer from chain B: same chain_id, wrong genesis hash.
        let mut foreign_peer = PeerInfo::new(
            PeerId("12D3KooW_foreign_peer".into()),
            "/ip4/127.0.0.1/tcp/29999".into(),
        );
        foreign_peer.chain_id     = Some(genesis_a.chain_id.clone()); // same chain_id
        foreign_peer.genesis_hash = Some(foreign_genesis_hash.clone()); // WRONG hash

        // A peer from chain A: matching chain_id AND matching genesis hash.
        let mut valid_peer = PeerInfo::new(
            PeerId("12D3KooW_valid_peer".into()),
            "/ip4/127.0.0.1/tcp/29998".into(),
        );
        valid_peer.chain_id     = Some(genesis_a.chain_id.clone());
        valid_peer.genesis_hash = Some(local_genesis_hash.clone());

        let mut mgr = PeerManager::new(50);
        mgr.set_local_genesis_hash(local_genesis_hash.clone());

        // The valid peer must be accepted.
        let accepted = mgr.try_accept_peer(valid_peer);
        assert!(accepted,
            "G-02: peer with matching chain_id AND genesis hash must be accepted");

        // The foreign peer (same chain_id, wrong genesis hash) must be rejected.
        let rejected = mgr.try_accept_peer(foreign_peer);
        assert!(!rejected,
            "G-02: peer with matching chain_id but wrong genesis hash must be rejected");

        // The foreign peer must not appear in the active peer list.
        let active = mgr.peers_on_network(&genesis_a.chain_id);
        assert!(
            active.iter().all(|p| p.peer_id.0 != "12D3KooW_foreign_peer"),
            "G-02: foreign-genesis peer must not appear in trusted peers_on_network"
        );
    }

    // ══════════════════════════════════════════════════════════════════════════
    // G-03 — cross-chain transaction replay is rejected
    // ══════════════════════════════════════════════════════════════════════════

    /// G-03: A transaction signed on chain A must not be accepted on chain B,
    /// even when both chains share chain_id and the signer's key is valid on B.
    ///
    /// The transaction signing domain must cover the genesis hash, not just
    /// the chain_id.  A TransactionDomain value encapsulates (chain_id, genesis_hash)
    /// and is used as the scope for signature pre-hashing.
    ///
    /// FAILS UNTIL:
    ///   - TransactionDomain is added to chain_forge_execution
    ///   - verify_transaction_domain() is added to chain_forge_execution
    #[test]
    fn g_03_cross_chain_tx_replay_is_rejected() {
        let Some(a_json) = genesis_a_json() else { return; };
        let genesis_a: GenesisConfig = serde_json::from_str(&a_json).unwrap();
        let genesis_b: GenesisConfig = serde_json::from_str(&genesis_b_json(&a_json)).unwrap();

        let hash_a = compute_genesis_hash(&genesis_a);
        let hash_b = compute_genesis_hash(&genesis_b);

        // The signing domain for each chain incorporates genesis_hash.
        // Chains A and B share chain_id but must produce DIFFERENT domain bytes.
        let domain_a = TransactionDomain::new(&genesis_a.chain_id, &hash_a);
        let domain_b = TransactionDomain::new(&genesis_b.chain_id, &hash_b);

        assert_ne!(
            domain_a.canonical_bytes(),
            domain_b.canonical_bytes(),
            "G-03: transaction domains for chains with same chain_id but different \
             genesis hash must produce different canonical bytes"
        );

        // Create an ML-DSA-65 keypair from a deterministic seed string.
        let scheme = MlDsaScheme;
        let kp = scheme.generate_keypair("g03-sender-h08-genesis-replay-test")
            .expect("G-03: ML-DSA generate_keypair must succeed");

        // Sign the tx body on chain A's domain (chain_id + genesis_hash_a).
        let body_json = r#"{"type":"transfer","to":"qcb1recipient","amount":1000,"denom":"uqcb"}"#;
        let prehash_a = domain_a.prehash_for_signing(body_json.as_bytes());
        let sig_a = scheme.sign(&prehash_a, &kp)
            .expect("G-03: signing must succeed");

        // Verify on chain A must succeed.
        let ok_on_a = scheme.verify(&prehash_a, &sig_a, &kp.public_key);
        assert!(ok_on_a.is_ok(),
            "G-03: signature made on chain A must verify on chain A; got {ok_on_a:?}");

        // Verify on chain B must FAIL — the domain prehash is different.
        let prehash_b = domain_b.prehash_for_signing(body_json.as_bytes());
        let err_on_b = scheme.verify(&prehash_b, &sig_a, &kp.public_key);
        assert!(err_on_b.is_err(),
            "G-03: signature made on chain A must NOT verify on chain B \
             (cross-chain replay); verify returned Ok unexpectedly");
    }

    // ══════════════════════════════════════════════════════════════════════════
    // G-04 — same chain_id, different genesis hash → peer rejected
    // ══════════════════════════════════════════════════════════════════════════

    /// G-04: A node MUST NOT accept a peer based on chain_id alone.
    /// Same chain_id + different genesis hash → connection refused.
    ///
    /// This test is distinct from G-02 to explicitly document that
    /// "matching chain_id" is necessary but NOT sufficient.
    ///
    /// FAILS UNTIL: PeerManager enforces genesis-hash check in try_accept_peer().
    #[test]
    fn g_04_same_chain_id_different_genesis_hash_is_rejected() {
        let Some(a_json) = genesis_a_json() else { return; };
        let genesis_a: GenesisConfig = serde_json::from_str(&a_json).unwrap();
        let genesis_b: GenesisConfig = serde_json::from_str(&genesis_b_json(&a_json)).unwrap();

        // Confirm the test invariant: A and B really share chain_id.
        assert_eq!(genesis_a.chain_id, genesis_b.chain_id,
            "G-04 fixture: genesis A and B must share chain_id \
             (same ID, different genesis_time)");

        let hash_a = compute_genesis_hash(&genesis_a);
        let hash_b = compute_genesis_hash(&genesis_b);
        assert_ne!(hash_a, hash_b,
            "G-04 fixture: genesis A and B must have different genesis hashes");

        let mut mgr = PeerManager::new(50);
        mgr.set_local_genesis_hash(hash_a.clone());

        // Peer with correct chain_id but chain-B genesis hash.
        let mut peer_b = PeerInfo::new(
            PeerId("12D3KooW_chain_b".into()),
            "/ip4/127.0.0.1/tcp/30001".into(),
        );
        peer_b.chain_id     = Some(genesis_a.chain_id.clone()); // same chain_id as local
        peer_b.genesis_hash = Some(hash_b);                      // WRONG genesis hash

        let accepted = mgr.try_accept_peer(peer_b);
        assert!(!accepted,
            "G-04: peer with same chain_id but different genesis hash must be rejected — \
             chain_id alone is NOT sufficient for trust");
    }

    // ══════════════════════════════════════════════════════════════════════════
    // G-05 — genesis-rejected peer cannot reconnect (deny list)
    // ══════════════════════════════════════════════════════════════════════════

    /// G-05: A peer placed on the genesis-mismatch deny list must not be
    /// accepted on subsequent reconnection attempts.
    ///
    /// FAILS UNTIL: PeerManager maintains a genesis-mismatch deny list and
    ///              exposes is_genesis_denied().
    #[test]
    fn g_05_genesis_rejected_peer_cannot_reconnect() {
        let Some(a_json) = genesis_a_json() else { return; };
        let genesis_a: GenesisConfig = serde_json::from_str(&a_json).unwrap();
        let genesis_b: GenesisConfig = serde_json::from_str(&genesis_b_json(&a_json)).unwrap();

        let hash_a = compute_genesis_hash(&genesis_a);
        let hash_b = compute_genesis_hash(&genesis_b);

        let mut mgr = PeerManager::new(50);
        mgr.set_local_genesis_hash(hash_a.clone());

        let foreign_peer_id = PeerId("12D3KooW_reconnector".into());

        // First attempt: wrong genesis hash → rejected and deny-listed.
        let mut peer_first = PeerInfo::new(
            foreign_peer_id.clone(),
            "/ip4/127.0.0.1/tcp/30002".into(),
        );
        peer_first.chain_id     = Some(genesis_a.chain_id.clone());
        peer_first.genesis_hash = Some(hash_b.clone());

        let first = mgr.try_accept_peer(peer_first);
        assert!(!first, "G-05: first connection with wrong genesis must be rejected");

        // Second attempt (simulated reconnect): same peer_id, different port.
        let mut peer_reconnect = PeerInfo::new(
            foreign_peer_id.clone(),
            "/ip4/127.0.0.1/tcp/30003".into(),
        );
        peer_reconnect.chain_id     = Some(genesis_a.chain_id.clone());
        peer_reconnect.genesis_hash = Some(hash_b.clone());

        let second = mgr.try_accept_peer(peer_reconnect);
        assert!(!second,
            "G-05: reconnection attempt from deny-listed peer must be refused \
             without re-handshaking");

        // The deny list must contain the peer.
        assert!(mgr.is_genesis_denied(&foreign_peer_id),
            "G-05: rejected peer must appear in the genesis-mismatch deny list");
    }

    // ══════════════════════════════════════════════════════════════════════════
    // G-06 — valid same-chain peer is accepted (baseline / regression guard)
    // ══════════════════════════════════════════════════════════════════════════

    /// G-06: A peer that advertises matching chain_id AND matching genesis hash
    /// must be accepted normally.  Confirms the protection does not break
    /// legitimate same-chain connections.
    ///
    /// FAILS UNTIL: PeerManager::try_accept_peer() and set_local_genesis_hash()
    ///              exist and work correctly.
    #[test]
    fn g_06_valid_same_chain_peer_is_accepted() {
        let Some(a_json) = genesis_a_json() else { return; };
        let genesis_a: GenesisConfig = serde_json::from_str(&a_json).unwrap();
        let hash_a = compute_genesis_hash(&genesis_a);

        let mut mgr = PeerManager::new(50);
        mgr.set_local_genesis_hash(hash_a.clone());

        let mut valid_peer = PeerInfo::new(
            PeerId("12D3KooW_valid".into()),
            "/ip4/127.0.0.1/tcp/30004".into(),
        );
        valid_peer.chain_id     = Some(genesis_a.chain_id.clone());
        valid_peer.genesis_hash = Some(hash_a.clone());

        let accepted = mgr.try_accept_peer(valid_peer);
        assert!(accepted,
            "G-06: peer with matching chain_id AND genesis hash must be accepted");

        let peers = mgr.peers_on_network(&genesis_a.chain_id);
        assert_eq!(peers.len(), 1,
            "G-06: accepted peer must appear in peers_on_network");
        assert_eq!(peers[0].peer_id.0, "12D3KooW_valid",
            "G-06: the accepted peer must be the valid same-chain peer");
    }

    // ══════════════════════════════════════════════════════════════════════════
    // G-07 — four-node live network: foreign-genesis node cannot join
    // ══════════════════════════════════════════════════════════════════════════

    /// G-07 — live integration test (requires compiled node binary).
    ///
    /// Steps:
    ///   1. Spawn the 4-node ML-DSA devnet (Alice/Bob/Carol/Dave) — chain A.
    ///   2. Wait for the network to reach h ≥ 3 (consensus is live).
    ///   3. Spawn a fifth node ("Eve") with chain B genesis: same chain_id,
    ///      different genesis_time → different genesis hash.
    ///   4. Eve bootstraps from Alice's P2P endpoint.
    ///   5. After 15 s verify:
    ///      a. Alice has exactly 3 peers (Bob/Carol/Dave only; Eve rejected).
    ///      b. Alice's height has not regressed (consensus was not disrupted).
    ///      c. Alice's log contains a genesis-hash-mismatch rejection entry.
    ///
    /// FAILS UNTIL: the node binary enforces genesis-hash verification on
    ///              PeerConnected and logs a rejection entry.
    #[test]
    fn g_07_foreign_genesis_node_cannot_join_live_network() {
        let bin = match node_binary() {
            Some(b) if b.exists() => b,
            _ => {
                println!(
                    "SKIP g_07: node binary not found — \
                     run `cargo build -p chain-forge-node` first"
                );
                return;
            }
        };

        let genesis_a_path = genesis_4node_mldsa_path();
        if !genesis_a_path.exists() {
            println!("SKIP g_07: genesis-4node-mldsa.json not found at {genesis_a_path:?}");
            return;
        }

        let tmp  = tempfile::tempdir().expect("tempdir");
        let keys = keys_dir();

        // Write chain B genesis (same chain_id, mutated genesis_time).
        let a_json = std::fs::read_to_string(&genesis_a_path)
            .expect("genesis A already confirmed to exist above");
        let genesis_b_path = tmp.path().join("genesis-b.json");
        std::fs::write(&genesis_b_path, genesis_b_json(&a_json)).unwrap();

        let (alice_api, alice_p2p) = (free_port(), free_port());
        let (bob_api,   bob_p2p)   = (free_port(), free_port());
        let (carol_api, carol_p2p) = (free_port(), free_port());
        let (dave_api,  dave_p2p)  = (free_port(), free_port());
        let (eve_api,   eve_p2p)   = (free_port(), free_port());

        let alice_bootstrap = format!("/ip4/127.0.0.1/tcp/{alice_p2p}");
        let alice_log = tmp.path().join("alice.log");

        println!("── G-07: spawn 4-node chain A (ML-DSA devnet) ──");
        let alice = spawn_node(
            &bin, &genesis_a_path, "qcb1alice",
            &keys.join("alice.key.json"),
            &tmp.path().join("alice"), alice_api, alice_p2p,
            None, &alice_log,
        );
        let _bob = spawn_node(
            &bin, &genesis_a_path, "qcb1bob",
            &keys.join("bob.key.json"),
            &tmp.path().join("bob"), bob_api, bob_p2p,
            Some(&alice_bootstrap), &tmp.path().join("bob.log"),
        );
        let _carol = spawn_node(
            &bin, &genesis_a_path, "qcb1carol",
            &keys.join("carol.key.json"),
            &tmp.path().join("carol"), carol_api, carol_p2p,
            Some(&alice_bootstrap), &tmp.path().join("carol.log"),
        );
        let _dave = spawn_node(
            &bin, &genesis_a_path, "qcb1dave",
            &keys.join("dave.key.json"),
            &tmp.path().join("dave"), dave_api, dave_p2p,
            Some(&alice_bootstrap), &tmp.path().join("dave.log"),
        );

        println!("── G-07 Phase 1: wait for chain A to reach h ≥ 3 ──");
        assert!(
            wait_for_height(alice_api, 3, Duration::from_secs(60)),
            "G-07: chain A must reach height 3 before Eve attempts to join"
        );
        let alice_height_before = poll_height(alice_api);

        println!("── G-07 Phase 2: spawn Eve on chain B (same chain_id, wrong genesis) ──");
        // Eve uses the same validator address and key as Alice, but starts
        // from the chain B genesis (different genesis_time → different hash).
        let _eve = spawn_node(
            &bin, &genesis_b_path, "qcb1alice",
            &keys.join("alice.key.json"),
            &tmp.path().join("eve"), eve_api, eve_p2p,
            Some(&alice_bootstrap), &tmp.path().join("eve.log"),
        );

        println!("── G-07 Phase 3: wait 15 s for Eve's connection to be processed ──");
        std::thread::sleep(Duration::from_secs(15));

        // Alice must have exactly 3 peers (Bob/Carol/Dave only).
        let alice_peers = api_get_json(alice_api, "/api/peers")
            .and_then(|j| j.as_array().map(|a| a.len()))
            .unwrap_or(0);
        assert_eq!(alice_peers, 3,
            "G-07: Alice must have exactly 3 peers (Bob/Carol/Dave). \
             Eve's connection (chain B genesis) must have been rejected. \
             Got peer count={alice_peers}");

        // Alice's height must not have regressed.
        let alice_height_after = poll_height(alice_api);
        assert!(alice_height_after >= alice_height_before,
            "G-07: Alice's consensus height must not regress after Eve's attempt; \
             before={alice_height_before} after={alice_height_after}");

        // Alice's log must contain a genesis-hash-mismatch rejection entry.
        let alice_log_content = std::fs::read_to_string(&alice_log).unwrap_or_default();
        let has_rejection_log =
            alice_log_content.contains("genesis_hash_mismatch") ||
            alice_log_content.contains("genesis hash mismatch") ||
            alice_log_content.contains("wrong genesis");
        assert!(has_rejection_log,
            "G-07: Alice's log must contain a genesis-hash-mismatch rejection entry; \
             last 20 lines: {:#?}",
            alice_log_content.lines().rev().take(20).collect::<Vec<_>>()
        );

        println!("── G-07 PASSED: foreign-genesis node rejected; chain A unaffected ──");
        drop(alice);
    }
}
