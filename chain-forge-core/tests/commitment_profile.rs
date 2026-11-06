//! Genesis `commitment_profile` (owner decision 2026-11-05): absent = legacy, "qattice-v2" = signing v2, anything else fails
//! closed. The genesis hash is `compute_genesis_hash` (serde form), so the field must not appear when absent.
use chain_forge_core::{compute_genesis_hash, CommitmentProfile, GenesisConfig};


pub const LEGACY_JSON: &str = r#"{
    "chain_id": "profile-test-1", "chain_name": "profile test", "engine_version": "0.1.0", "genesis_time": "2026-11-05T00:00:00Z",
    "environment": { "mode": "devnet", "faucet_enabled": true, "relaxed_limits": true },
    "native_token": { "name": "QC", "symbol": "QCB", "denom": "uqcb", "max_supply": "210000000" },
    "address_prefix": "qcb",
    "consensus": { "type": "proof-of-stake", "validator_set_size": 3, "block_time_ms": 500 },
    "execution": { "state_model": "account", "parallel_execution": false, "gas_model": "dynamic", "require_signatures": true },
    "cryptography": { "signature_scheme": "pqc-native", "pqc_algorithm": "ml-dsa", "migration_trigger": "nist-guidance", "hash_width": 256, "validator_scheme": "ml-dsa-65" },
    "network": { "network_id": "p-net", "p2p_port": 27000, "rpc_port": 27001, "bootstrap_nodes": [], "peer_discovery": "bootstrap", "max_peers": 10 },
    "limits": { "max_block_bytes": 1048576, "max_tx_bytes": 65536, "block_gas_limit": 10000000, "mempool_size": 100, "mempool_ttl_seconds": 60 },
    "modules": ["bank"], "custom_modules": [],
    "genesis_accounts": [ { "label": "u", "address": "qcb1user", "balance": "5000000", "role": "user" } ]
}"#;


/// Hash of `LEGACY_JSON` on `main` before this field existed. A change here means legacy chains stopped matching their genesis.
const PINNED_LEGACY_HASH: &str = "ed2f054969209a0bb87be60d2cf4b99de6d9f079571893a55323bd1126d69070";

fn with_profile(v: &str) -> String {
    LEGACY_JSON.replacen(r#""modules": ["bank"],"#, &format!(r#""commitment_profile": {v}, "modules": ["bank"],"#), 1)
}

fn parse(json: &str) -> Result<GenesisConfig, String> { GenesisConfig::from_json(json).map_err(|e| e.to_string()) }

#[test]
fn an_absent_field_is_legacy_and_the_genesis_hash_is_unchanged() {
    let g = parse(LEGACY_JSON).unwrap();
    assert_eq!(g.commitment_profile(), Ok(CommitmentProfile::Legacy));
    assert_eq!(compute_genesis_hash(&g), PINNED_LEGACY_HASH, "legacy genesis hashes must not move");
    assert!(!serde_json::to_string(&g).unwrap().contains("commitment_profile"), "absent field must not be serialised");
}

#[test]
fn qattice_v2_resolves_survives_a_round_trip_and_is_bound_into_the_genesis_hash() {
    let g = parse(&with_profile(r#""qattice-v2""#)).unwrap();
    assert_eq!(g.commitment_profile(), Ok(CommitmentProfile::QatticeV2));
    let back = parse(&g.to_json_pretty().unwrap()).unwrap();
    assert_eq!(back.commitment_profile(), Ok(CommitmentProfile::QatticeV2), "round trip keeps the profile");
    assert_ne!(compute_genesis_hash(&g), PINNED_LEGACY_HASH, "the profile must be part of the genesis hash");
    assert_eq!(compute_genesis_hash(&g), compute_genesis_hash(&back));
}

#[test]
fn unknown_or_malformed_values_fail_closed() {
    for v in [r#""qattice-v3""#, r#""""#, r#""Qattice-V2""#, r#"" qattice-v2""#, r#""legacy""#, r#""qattice-v2\n""#] {
        let r = parse(&with_profile(v)).map(|g| g.commitment_profile());
        assert!(matches!(r, Ok(Err(_)) | Err(_)), "{v} must be refused, got {r:?}");
    }
    for v in ["2", "true", r#"["qattice-v2"]"#, "{}"] {
        let r = parse(&with_profile(v)).map(|g| g.commitment_profile());
        assert!(matches!(r, Ok(Err(_)) | Err(_)), "{v} must be refused, got {r:?}");
    }
}

/// `"commitment_profile": null` deserialises as an absent field, which would silently mean "legacy". An explicit null on a
/// chain that meant to select v2 is a configuration mistake; refuse it.
#[test]
fn an_explicit_null_is_refused_not_treated_as_legacy() {
    let r = parse(&with_profile("null")).map(|g| g.commitment_profile());
    assert!(matches!(r, Ok(Err(_)) | Err(_)), "explicit null must not mean legacy, got {r:?}");
}

#[test]
fn qattice_v2_requires_an_ml_dsa_only_chain() {
    for (scheme, extra) in [("hybrid", ""), ("classical", "")] {
        let json = with_profile(r#""qattice-v2""#).replace(r#""signature_scheme": "pqc-native", "pqc_algorithm": "ml-dsa""#,
            &format!(r#""signature_scheme": "{scheme}", "pqc_algorithm": "ml-dsa"{extra}"#));
        assert!(json.contains(scheme));
        let r = parse(&json).map(|g| g.commitment_profile());
        assert!(matches!(r, Ok(Err(_)) | Err(_)), "qattice-v2 on a {scheme} chain must be refused, got {r:?}");
    }
}
