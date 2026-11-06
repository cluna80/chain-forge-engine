//! A node that starts BEFORE its bootstrap peer is listening must still connect once the peer appears (real libp2p, `real-network`).
//!
//! mDNS is off (`PeerDiscovery::Bootstrap`), so the only way these two nodes can find each other is the bootstrap dial. On the
//! code before the retry fix the dial happens once at startup, fails, and the nodes never connect.
//!
//! Run: `cargo test -p chain-forge-p2p --features real-network --test bootstrap_retry -- --nocapture`
#![cfg(feature = "real-network")]

use std::net::TcpListener;
use std::time::{Duration, Instant};

use chain_forge_p2p::real::Libp2pService;
use chain_forge_p2p::{NetworkConfig, PeerDiscovery};

fn free_port() -> u16 { TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port() }

fn config(p2p_port: u16, bootstrap: Vec<String>) -> NetworkConfig {
    NetworkConfig {
        network_id: "bootstrap-retry-test".into(), p2p_port, bootstrap_nodes: bootstrap, peer_discovery: PeerDiscovery::Bootstrap,
        max_peers: 8, max_message_bytes: 1024 * 1024, genesis_hash: Some("test-genesis".into()),
    }
}

/// One trial: start `b` (bootstrap -> a) first, wait `head_start`, then start `a`; return how long `b` took to see a peer.
async fn trial(head_start: Duration, within: Duration) -> Option<Duration> {
    let (pa, pb) = (free_port(), free_port());
    let (b, _) = Libp2pService::start(&config(pb, vec![format!("/ip4/127.0.0.1/tcp/{pa}")])).await.expect("start b");
    tokio::time::sleep(head_start).await;
    let (a, _) = Libp2pService::start(&config(pa, vec![])).await.expect("start a");
    let t0 = Instant::now();
    while t0.elapsed() < within {
        if b.peer_count() >= 1 && a.peer_count() >= 1 { return Some(t0.elapsed()); }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    None
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_node_started_before_its_bootstrap_peer_connects_when_the_peer_appears_repeatedly() {
    for i in 1..=3 {
        let took = trial(Duration::from_secs(3), Duration::from_secs(25)).await;
        println!("trial {i}: {:?}", took);
        assert!(took.is_some(), "trial {i}: the node never connected to its bootstrap peer (no redial)");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unreachable_bootstrap_address_does_not_stop_the_node_from_running() {
    let port = free_port();
    let dead = free_port(); // nothing ever listens here
    let (svc, _) = Libp2pService::start(&config(port, vec![format!("/ip4/127.0.0.1/tcp/{dead}")])).await.expect("a dead bootstrap peer must not fail startup");
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert_eq!(svc.peer_count(), 0);
}
