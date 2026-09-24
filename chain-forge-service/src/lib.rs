//! chain-forge-service library: the parts of the local service that don't
//! touch processes or sockets, kept here so they can be unit-tested.
//!
//! The central job is prepare_local_chain(): take the genesis the wizard
//! produced and make it runnable on this machine --
//!   * give every genesis account a key (the developer never types keys
//!     into a web form, and private keys never leave this machine)
//!   * derive an address for any account the developer left blank
//!   * point every validator at the others over 127.0.0.1
//!   * refuse anything the engine would refuse, before touching disk

use chain_forge_core::{Address, GenesisConfig, HashWidth};
use chain_forge_crypto::ClassicalScheme;
use serde_json::{json, Value};

/// A genesis made runnable locally, plus what's needed to launch it.
#[derive(Debug)]
pub struct PreparedChain {
    pub chain_id: String,
    /// The final genesis, with addresses, public keys and local bootstrap nodes.
    pub genesis: Value,
    /// (address, key file JSON) for every key this service generated.
    /// Contains PRIVATE keys: written to disk, never sent over HTTP.
    pub key_files: Vec<(String, Value)>,
    /// (validator address, P2P port) for each node to start.
    pub validators: Vec<(String, u16)>,
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Chain ids become directory names, so allow only a safe character set.
pub fn validate_chain_id(id: &str) -> Result<(), String> {
    let ok = !id.is_empty()
        && id.len() <= 64
        && id != "." && id != ".."
        && id.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    if ok { Ok(()) } else {
        Err(format!("chain_id \"{id}\" must be 1-64 characters of letters, digits, '-', '_' or '.'"))
    }
}

/// Make a wizard genesis runnable on this machine. `next_port` supplies a
/// free P2P port per validator. Fails, without side effects, on anything
/// the engine itself would refuse.
pub fn prepare_local_chain(
    genesis_json: &str,
    mut next_port: impl FnMut() -> u16,
) -> Result<PreparedChain, String> {
    // Engine-level validation first, on the genesis exactly as submitted.
    let cfg = GenesisConfig::from_json(genesis_json).map_err(|e| e.to_string())?;
    validate_chain_id(&cfg.chain_id)?;
    cfg.enabled_modules()?;
    if cfg.address_prefix.trim().is_empty() {
        return Err("address_prefix is required".into());
    }
    let width = cfg.hash_width().unwrap_or(HashWidth::Bits256);

    let mut genesis: Value = serde_json::from_str(genesis_json).map_err(|e| e.to_string())?;
    let accounts = genesis["genesis_accounts"].as_array_mut()
        .ok_or("genesis_accounts must be a list")?;

    let mut key_files = Vec::new();
    let mut validator_addrs = Vec::new();
    for acct in accounts.iter_mut() {
        let has_key = acct["public_key"].as_str().is_some_and(|k| !k.is_empty());
        if !has_key {
            let kp = ClassicalScheme.generate_random().map_err(|e| e.to_string())?;
            let blank = acct["address"].as_str().map_or(true, |a| a.trim().is_empty());
            if blank {
                let derived = Address::from_public_key(&kp.public_key, &cfg.address_prefix, width);
                acct["address"] = json!(derived.as_str());
            }
            acct["public_key"] = json!(hex(&kp.public_key));
            let address = acct["address"].as_str().unwrap_or_default().to_string();
            key_files.push((address.clone(), json!({
                "scheme":      "classical-ed25519",
                "address":     address,
                "public_key":  hex(&kp.public_key),
                "private_key": hex(&kp.private_key),
            })));
        }
        if acct["role"].as_str() == Some("validator") {
            validator_addrs.push(acct["address"].as_str().unwrap_or_default().to_string());
        }
    }
    if validator_addrs.is_empty() {
        return Err("at least one genesis account must have the validator role".into());
    }
    let mut seen = std::collections::HashSet::new();
    for acct in genesis["genesis_accounts"].as_array().unwrap() {
        let a = acct["address"].as_str().unwrap_or_default();
        if !seen.insert(a.to_string()) {
            return Err(format!("duplicate genesis address \"{a}\""));
        }
    }

    let validators: Vec<(String, u16)> = validator_addrs.into_iter().map(|a| (a, next_port())).collect();
    // A lone validator runs the node's single-node devnet path, which is
    // only taken when there are no bootstrap nodes. Several validators
    // find each other over localhost.
    let bootstrap: Vec<String> = if validators.len() == 1 {
        Vec::new()
    } else {
        validators.iter().map(|(_, p)| format!("/ip4/127.0.0.1/tcp/{p}")).collect()
    };
    genesis["network"]["bootstrap_nodes"] = json!(bootstrap);

    // The engine must accept the final file too, not just the input.
    GenesisConfig::from_json(&genesis.to_string())
        .map_err(|e| format!("prepared genesis rejected: {e}"))?
        .enabled_modules()?;

    Ok(PreparedChain { chain_id: cfg.chain_id, genesis, key_files, validators })
}

/// Only the wizard's own origin may call the service. A request with no
/// Origin header (curl, scripts on this machine) is allowed; a request
/// from any other website is refused, since this service writes files,
/// holds private keys, and starts processes.
pub fn origin_allowed(request_origin: Option<&str>, allowed: &str) -> bool {
    match request_origin {
        None => true,
        Some(o) => o.trim_end_matches('/') == allowed.trim_end_matches('/'),
    }
}

/// Byte offset just past the blank line ending the headers, if present.
pub fn header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

/// Value of a header (case-insensitive name) in a header block.
pub fn header_value<'a>(headers: &'a str, name: &str) -> Option<&'a str> {
    headers.lines().find_map(|line| {
        let (n, v) = line.split_once(':')?;
        n.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

/// True once the headers and the full Content-Length body have arrived.
pub fn request_complete(buf: &[u8]) -> bool {
    match header_end(buf) {
        Some(end) => {
            let headers = String::from_utf8_lossy(&buf[..end]);
            let len: usize = header_value(&headers, "content-length")
                .and_then(|v| v.parse().ok()).unwrap_or(0);
            buf.len() >= end + len
        }
        None => false,
    }
}

/// Remove ANSI colour codes so node logs read cleanly in a browser.
pub fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next();
            for c2 in chars.by_ref() {
                if c2.is_ascii_alphabetic() { break; }
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wizard_genesis(accounts: Value, modules: Value) -> String {
        json!({
            "chain_id": "mychain-1", "chain_name": "My Chain", "engine_version": "0.1.0",
            "genesis_time": "2026-09-23T00:00:00Z",
            "environment": { "mode": "devnet", "faucet_enabled": true, "relaxed_limits": true },
            "native_token": { "name": "Coin", "symbol": "CN", "denom": "ucn", "max_supply": null },
            "address_prefix": "my",
            "consensus": { "type": "proof-of-stake", "validator_set_size": 2, "block_time_ms": 1000 },
            "execution": { "state_model": "account", "parallel_execution": false, "gas_model": "dynamic" },
            "cryptography": { "signature_scheme": "classical", "pqc_algorithm": null,
                "migration_trigger": "nist-guidance", "hash_width": 256, "validator_scheme": "same-as-accounts" },
            "network": { "network_id": "mychain-net", "p2p_port": 26656, "rpc_port": 26657,
                "bootstrap_nodes": [], "peer_discovery": "both", "max_peers": 50 },
            "limits": { "max_block_bytes": 1048576, "max_tx_bytes": 65536, "block_gas_limit": 10000000,
                "mempool_size": 5000, "mempool_ttl_seconds": 300 },
            "modules": modules,
            "custom_modules": [],
            "genesis_accounts": accounts,
        }).to_string()
    }

    fn ports() -> impl FnMut() -> u16 {
        let mut p = 30000;
        move || { p += 1; p }
    }

    #[test]
    fn blank_addresses_are_derived_and_every_account_gets_a_key() {
        let g = wizard_genesis(json!([
            { "label": "V1", "address": "",         "balance": "100", "role": "validator" },
            { "label": "V2", "address": "my1named", "balance": "100", "role": "validator" },
            { "label": "T",  "address": "",         "balance": "5",   "role": "treasury" },
        ]), json!(["bank", "staking"]));
        let p = prepare_local_chain(&g, ports()).unwrap();

        let accts = p.genesis["genesis_accounts"].as_array().unwrap();
        assert!(accts[0]["address"].as_str().unwrap().starts_with("my1"));
        assert_eq!(accts[1]["address"], "my1named", "a typed address is kept");
        assert!(accts.iter().all(|a| a["public_key"].as_str().unwrap().len() == 64));
        assert_eq!(p.key_files.len(), 3);
        assert!(p.key_files.iter().all(|(_, k)| k["private_key"].as_str().unwrap().len() == 64));
    }

    #[test]
    fn validators_get_local_ports_and_find_each_other_on_localhost() {
        let g = wizard_genesis(json!([
            { "label": "V1", "address": "", "balance": "1", "role": "validator" },
            { "label": "V2", "address": "", "balance": "1", "role": "validator" },
        ]), json!(["bank"]));
        let p = prepare_local_chain(&g, ports()).unwrap();
        assert_eq!(p.validators.len(), 2);
        assert_eq!(p.genesis["network"]["bootstrap_nodes"],
            json!(["/ip4/127.0.0.1/tcp/30001", "/ip4/127.0.0.1/tcp/30002"]));
    }

    #[test]
    fn a_single_validator_chain_gets_no_bootstrap_list() {
        let g = wizard_genesis(json!([
            { "label": "V1", "address": "", "balance": "1", "role": "validator" },
            { "label": "T",  "address": "", "balance": "1", "role": "treasury" },
        ]), json!(["bank"]));
        let p = prepare_local_chain(&g, ports()).unwrap();
        assert_eq!(p.validators.len(), 1);
        assert_eq!(p.genesis["network"]["bootstrap_nodes"], json!([]));
    }

    #[test]
    fn a_supplied_public_key_is_kept_and_no_private_key_is_invented() {
        let g = wizard_genesis(json!([
            { "label": "V1", "address": "my1ext", "balance": "1", "role": "validator",
              "public_key": "ab".repeat(32) },
        ]), json!(["bank"]));
        let p = prepare_local_chain(&g, ports()).unwrap();
        assert!(p.key_files.is_empty());
        assert_eq!(p.genesis["genesis_accounts"][0]["public_key"], "ab".repeat(32));
    }

    #[test]
    fn engine_refusals_are_refused_here_first() {
        let bad_module = wizard_genesis(json!([
            { "label": "V1", "address": "", "balance": "1", "role": "validator" },
        ]), json!(["bank", "dex"]));
        assert!(prepare_local_chain(&bad_module, ports()).unwrap_err().contains("unknown module"));

        let no_validator = wizard_genesis(json!([
            { "label": "T", "address": "", "balance": "1", "role": "treasury" },
        ]), json!(["bank"]));
        assert!(prepare_local_chain(&no_validator, ports()).unwrap_err().contains("validator role"));

        let dup = wizard_genesis(json!([
            { "label": "V1", "address": "my1same", "balance": "1", "role": "validator" },
            { "label": "V2", "address": "my1same", "balance": "1", "role": "validator" },
        ]), json!(["bank"]));
        assert!(prepare_local_chain(&dup, ports()).unwrap_err().contains("duplicate"));
    }

    #[test]
    fn chain_ids_must_be_safe_directory_names() {
        assert!(validate_chain_id("qcb-testnet-1").is_ok());
        assert!(validate_chain_id("../etc").is_err());
        assert!(validate_chain_id("a/b").is_err());
        assert!(validate_chain_id("").is_err());
    }

    #[test]
    fn only_the_wizard_origin_may_call_the_service() {
        let wizard = "http://localhost:5173";
        assert!(origin_allowed(None, wizard));
        assert!(origin_allowed(Some("http://localhost:5173/"), wizard));
        assert!(!origin_allowed(Some("https://evil.example"), wizard));
    }

    #[test]
    fn request_needs_its_full_body_and_ansi_is_stripped() {
        assert!(!request_complete(b"POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nab"));
        assert!(request_complete(b"POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc"));
        assert_eq!(strip_ansi("\u{1b}[32m INFO\u{1b}[0m ok"), " INFO ok");
    }
}
