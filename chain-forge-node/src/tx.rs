/// chain-forge-tx
///
/// Developer CLI for constructing and submitting transactions to a running
/// Chain Forge node via `POST /api/tx`.
///
/// USAGE
///   chain-forge-tx [OPTIONS] <SUBCOMMAND> [SUBCOMMAND-ARGS]
///
/// GLOBAL OPTIONS
///   --node <url>        Node base URL (default: http://localhost:8080)
///   --from <address>    Sender address (required for all subcommands)
///   --key-file <path>   Path to a *.key.json signing key file (optional;
///                       required when the node has require_signatures = true)
///   --gas <n>           Gas limit override (default: 100_000)
///   --chain-id <id>     Chain ID for signing (default: qcb-testnet-1)
///   --dry-run           Print the JSON tx body without submitting
///
/// SUBCOMMANDS
///   transfer          <to> <amount> [--denom <d>]
///   burn              <amount> [--denom <d>]
///   stake             <validator> <amount>
///   qrc-purchase      <qcb-amount> [--min-out <n>]
///   qrc-spend         <resource-kind> <units> <amount>
///     resource-kind: Compute|Storage|ZkProving|Bandwidth|OracleData|AiInference
///   register-identity
///   attest            <claimant-address>
///   revoke-attestation <attested-address>
///   report-suspected-sybil <suspected-address>
///   confirm-sybil     <sybil-address>
///   reverse-sybil     <sybil-address>
///   sponsor-agent     <agent-address>          (legacy; prefer register-agent)
///   revoke-agent      <agent-address>          (legacy IdentityStore only)
///   revoke-agent-full <agent-id>               (AgentStore + IdentityStore)
///   authorize-agent   <agent-id>
///   suspend-agent     <agent-id> [--reason <string>]
///   custom            <module> <hex-payload>
///
/// EXAMPLES
///   # Transfer 50 QCB from alice to bob (unsigned, testnet)
///   chain-forge-tx --from qcb1alice transfer qcb1bob 50
///
///   # Same, signed
///   chain-forge-tx --from qcb1alice --key-file keys/qcb1alice.key.json \
///                  transfer qcb1bob 50
///
///   # Attest to bob's identity
///   chain-forge-tx --from qcb1alice --key-file keys/qcb1alice.key.json \
///                  attest qcb1bob
///
///   # Report a suspected sybil
///   chain-forge-tx --from qcb1alice report-suspected-sybil qcb1eve
///
///   # Purchase QRC credits by burning 100 QCB, accepting any rate
///   chain-forge-tx --from qcb1alice qrc-purchase 100
///
///   # Dry-run: inspect tx JSON without submitting
///   chain-forge-tx --from qcb1alice --dry-run transfer qcb1bob 100
///
/// Key file format (produced by chain-forge-keygen):
///   {
///     "address":     "qcb1alice",
///     "scheme":      "ed25519",
///     "public_key":  "<64 hex chars>",
///     "private_key": "<64 hex chars>"
///   }
///
/// Key files must NEVER be committed to the repository.

use chain_forge_crypto::{KeyPair, SchemeId};
use chain_forge_execution::{Transaction, TxBody};
use chain_forge_qrc::ResourceKind;
use serde_json::Value;
use std::path::PathBuf;

// ──────────────────────────────────────────────
// Hex helpers
// ──────────────────────────────────────────────

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err(format!("hex string has odd length ({})", s.len()));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| format!("invalid hex at position {i}: {e}"))
        })
        .collect()
}

// ──────────────────────────────────────────────
// Signing key (loaded from *.key.json)
// ──────────────────────────────────────────────

fn load_keypair(path: &PathBuf) -> Result<(String, KeyPair), String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read key file {:?}: {e}", path))?;
    let v: Value = serde_json::from_str(&text)
        .map_err(|e| format!("key file is not valid JSON: {e}"))?;

    let address = v["address"]
        .as_str()
        .ok_or("key file missing 'address' field")?
        .to_string();
    let pub_hex = v["public_key"]
        .as_str()
        .ok_or("key file missing 'public_key' field")?;
    let prv_hex = v["private_key"]
        .as_str()
        .ok_or("key file missing 'private_key' field")?;

    let kp = KeyPair {
        scheme:      SchemeId::Classical,
        public_key:  hex_decode(pub_hex).map_err(|e| format!("public_key: {e}"))?,
        private_key: hex_decode(prv_hex).map_err(|e| format!("private_key: {e}"))?,
    };
    Ok((address, kp))
}

// ──────────────────────────────────────────────
// Nonce fetch  (blocking, via curl)
// ──────────────────────────────────────────────

fn fetch_nonce(node: &str, address: &str) -> Result<u64, String> {
    let url = format!("{node}/api/accounts/{address}");
    let out = std::process::Command::new("curl")
        .args(["-sf", "--max-time", "10", &url])
        .output()
        .map_err(|e| format!("curl failed to launch: {e}"))?;

    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(format!("GET {url} failed: {err}"));
    }

    let body = String::from_utf8_lossy(&out.stdout);
    let v: Value = serde_json::from_str(&body).map_err(|e| {
        format!("node returned non-JSON for account {address}: {e}\nBody: {body}")
    })?;

    // Explorer state may nest nonce at top level or under "account"
    let nonce = v
        .get("nonce")
        .or_else(|| v.pointer("/account/nonce"))
        .and_then(|n| n.as_u64())
        .unwrap_or(0);

    Ok(nonce)
}

// ──────────────────────────────────────────────
// Transaction submission (blocking, via curl)
// ──────────────────────────────────────────────

fn submit_tx(node: &str, tx_json: &str) -> Result<String, String> {
    let out = std::process::Command::new("curl")
        .args([
            "-sf",
            "--max-time",
            "15",
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "-d",
            tx_json,
            &format!("{node}/api/tx"),
        ])
        .output()
        .map_err(|e| format!("curl failed to launch: {e}"))?;

    let body = String::from_utf8_lossy(&out.stdout).to_string();
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(format!(
            "POST {node}/api/tx failed (curl {}): {err}\nResponse: {body}",
            out.status.code().unwrap_or(-1)
        ));
    }
    Ok(body)
}

// ──────────────────────────────────────────────
// ResourceKind parsing
// ──────────────────────────────────────────────

fn parse_resource(s: &str) -> Result<ResourceKind, String> {
    match s {
        "Compute"     | "compute"      => Ok(ResourceKind::Compute),
        "Storage"     | "storage"      => Ok(ResourceKind::Storage),
        "ZkProving"   | "zk-proving"   => Ok(ResourceKind::ZkProving),
        "Bandwidth"   | "bandwidth"    => Ok(ResourceKind::Bandwidth),
        "OracleData"  | "oracle-data"  => Ok(ResourceKind::OracleData),
        "AiInference" | "ai-inference" => Ok(ResourceKind::AiInference),
        other => Err(format!(
            "unknown resource kind '{other}'. \
             Valid: Compute, Storage, ZkProving, Bandwidth, OracleData, AiInference"
        )),
    }
}

// ──────────────────────────────────────────────
// Tx ID generation (no external deps)
// ──────────────────────────────────────────────

fn new_tx_id() -> String {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("tx-{ts:x}-{:x}", std::process::id())
}

// ──────────────────────────────────────────────
// CLI structures
// ──────────────────────────────────────────────

struct GlobalArgs {
    node:     String,
    from:     String,
    key_file: Option<PathBuf>,
    gas:      u64,
    chain_id: String,
    dry_run:  bool,
}

// ──────────────────────────────────────────────
// Usage / error helpers
// ──────────────────────────────────────────────

fn die(msg: &str) -> ! {
    eprintln!("Error: {msg}");
    std::process::exit(1);
}

fn usage() -> ! {
    eprintln!(
        "chain-forge-tx — submit transactions to a Chain Forge node

USAGE
  chain-forge-tx [OPTIONS] <SUBCOMMAND> [ARGS...]

OPTIONS
  --node <url>         Node base URL        (default: http://localhost:8080)
  --from <address>     Sender address       (required)
  --key-file <path>    Signing key file     (optional)
  --gas <n>            Gas limit            (default: 100000)
  --chain-id <id>      Chain ID for signing (default: qcb-testnet-1)
  --dry-run            Print JSON tx without submitting

SUBCOMMANDS
  transfer <to> <amount> [--denom <d>]
  burn <amount> [--denom <d>]
  stake <validator> <amount>
  qrc-purchase <qcb-amount> [--min-out <n>]
  qrc-spend <resource-kind> <units> <qrc-amount>
  register-identity
  attest <claimant-address>
  revoke-attestation <attested-address>
  report-suspected-sybil <suspected-address>
  confirm-sybil <sybil-address>
  reverse-sybil <sybil-address>
  sponsor-agent <agent-address>
  revoke-agent <agent-address>
  revoke-agent-full <agent-id>
  authorize-agent <agent-id>
  suspend-agent <agent-id> [--reason <string>]
  custom <module> <hex-payload>
"
    );
    std::process::exit(1)
}

fn parse_u64(s: &str, label: &str) -> u64 {
    s.parse::<u64>().unwrap_or_else(|_| {
        die(&format!("{label} must be a non-negative integer, got '{s}'"))
    })
}

fn parse_u128(s: &str, label: &str) -> u128 {
    s.parse::<u128>().unwrap_or_else(|_| {
        die(&format!("{label} must be a non-negative integer, got '{s}'"))
    })
}

// ──────────────────────────────────────────────
// Argument parsing
// ──────────────────────────────────────────────

fn parse_args() -> (GlobalArgs, TxBody) {
    let raw: Vec<String> = std::env::args().collect();
    let mut node     = "http://localhost:8080".to_string();
    let mut from     = String::new();
    let mut key_file = None::<PathBuf>;
    let mut gas      = 100_000u64;
    let mut chain_id = "qcb-testnet-1".to_string();
    let mut dry_run  = false;

    let mut i = 1usize;

    // Consume global flags (anything before the first non-flag token)
    while i < raw.len() {
        match raw[i].as_str() {
            "--node"     => { i += 1; node     = raw.get(i).cloned().unwrap_or_default(); }
            "--from"     => { i += 1; from     = raw.get(i).cloned().unwrap_or_default(); }
            "--key-file" => { i += 1; key_file = raw.get(i).map(PathBuf::from); }
            "--gas"      => { i += 1; gas      = parse_u64(raw.get(i).map(|s| s.as_str()).unwrap_or(""), "--gas"); }
            "--chain-id" => { i += 1; chain_id = raw.get(i).cloned().unwrap_or_default(); }
            "--dry-run"  => { dry_run = true; }
            "--help" | "-h" => usage(),
            _            => break,
        }
        i += 1;
    }

    let sub = raw.get(i).map(|s| s.as_str()).unwrap_or("");
    let rest = &raw[raw.len().min(i + 1)..];

    // Helper: look up --flag value in `rest`
    let flag = |f: &str| -> Option<String> {
        rest.windows(2).find(|w| w[0] == f).map(|w| w[1].clone())
    };

    let body: TxBody = match sub {
        // ── Basic economic operations ──────────────────────────────────────
        "transfer" => {
            if rest.len() < 2 { die("transfer requires <to> <amount>"); }
            let denom = flag("--denom").unwrap_or_else(|| "uqcb".to_string());
            TxBody::Transfer {
                to:     rest[0].clone(),
                denom,
                amount: parse_u128(&rest[1], "amount"),
            }
        }
        "burn" => {
            if rest.is_empty() { die("burn requires <amount>"); }
            let denom = flag("--denom").unwrap_or_else(|| "uqcb".to_string());
            TxBody::Burn { denom, amount: parse_u128(&rest[0], "amount") }
        }
        "stake" => {
            if rest.len() < 2 { die("stake requires <validator> <amount>"); }
            TxBody::Stake {
                validator: rest[0].clone(),
                amount:    parse_u128(&rest[1], "amount"),
            }
        }

        // ── QRC operations ─────────────────────────────────────────────────
        "qrc-purchase" => {
            if rest.is_empty() { die("qrc-purchase requires <qcb-amount>"); }
            let min_out = flag("--min-out")
                .map(|s| parse_u128(&s, "--min-out"))
                .unwrap_or(0);
            TxBody::QrcPurchase {
                qcb_amount:  parse_u128(&rest[0], "qcb-amount"),
                min_qrc_out: min_out,
            }
        }
        "qrc-spend" => {
            if rest.len() < 3 { die("qrc-spend requires <resource-kind> <units> <qrc-amount>"); }
            let resource = parse_resource(&rest[0]).unwrap_or_else(|e| die(&e));
            TxBody::QrcSpend {
                resource,
                units:  parse_u128(&rest[1], "units"),
                amount: parse_u128(&rest[2], "qrc-amount"),
            }
        }

        // ── Identity operations ────────────────────────────────────────────
        "register-identity" => TxBody::RegisterIdentity,

        "attest" => {
            if rest.is_empty() { die("attest requires <claimant-address>"); }
            TxBody::Attest { claimant_id: rest[0].clone() }
        }
        "revoke-attestation" => {
            if rest.is_empty() { die("revoke-attestation requires <attested-address>"); }
            TxBody::RevokeAttestation { attested_id: rest[0].clone() }
        }
        "report-suspected-sybil" => {
            if rest.is_empty() { die("report-suspected-sybil requires <suspected-address>"); }
            TxBody::ReportSuspectedSybil { suspected_id: rest[0].clone() }
        }
        "confirm-sybil" => {
            if rest.is_empty() { die("confirm-sybil requires <sybil-address>"); }
            TxBody::ConfirmSybil { sybil_id: rest[0].clone() }
        }
        "reverse-sybil" => {
            if rest.is_empty() { die("reverse-sybil requires <sybil-address>"); }
            TxBody::ReverseSybil { sybil_id: rest[0].clone() }
        }

        // ── Agent operations (legacy Phase 0 variants) ─────────────────────
        "sponsor-agent" => {
            if rest.is_empty() { die("sponsor-agent requires <agent-address>"); }
            TxBody::SponsorAgent { agent_address: rest[0].clone() }
        }
        "revoke-agent" => {
            if rest.is_empty() { die("revoke-agent requires <agent-address>"); }
            TxBody::RevokeAgent { agent_address: rest[0].clone() }
        }

        // ── Agent lifecycle (Phase 2 variants) ────────────────────────────
        "revoke-agent-full" => {
            if rest.is_empty() { die("revoke-agent-full requires <agent-id>"); }
            TxBody::RevokeAgentFull { agent_id: rest[0].clone() }
        }
        "authorize-agent" => {
            if rest.is_empty() { die("authorize-agent requires <agent-id>"); }
            TxBody::AuthorizeAgent { agent_id: rest[0].clone() }
        }
        "suspend-agent" => {
            if rest.is_empty() { die("suspend-agent requires <agent-id>"); }
            let reason = flag("--reason").unwrap_or_else(|| "suspended via chain-forge-tx".to_string());
            TxBody::SuspendAgent { agent_id: rest[0].clone(), reason }
        }

        // ── Custom / escape hatch ─────────────────────────────────────────
        "custom" => {
            if rest.len() < 2 { die("custom requires <module> <hex-payload>"); }
            let payload = hex_decode(&rest[1]).unwrap_or_else(|e| die(&format!("payload: {e}")));
            TxBody::Custom { module: rest[0].clone(), payload }
        }

        "" | "--help" | "-h" => usage(),
        other => { eprintln!("Unknown subcommand: '{other}'"); usage() }
    };

    let g = GlobalArgs { node, from, key_file, gas, chain_id, dry_run };
    (g, body)
}

// ──────────────────────────────────────────────
// Entry point
// ──────────────────────────────────────────────

pub fn main() {
    let (g, body) = parse_args();

    if g.from.is_empty() {
        die("--from <address> is required");
    }

    // Load signing key if provided, validate that it matches --from
    let keypair: Option<KeyPair> = match &g.key_file {
        Some(p) => {
            let (addr, kp) = load_keypair(p).unwrap_or_else(|e| {
                die(&format!("key file error: {e}"))
            });
            if addr != g.from {
                die(&format!(
                    "key file address '{addr}' does not match --from '{}'",
                    g.from
                ));
            }
            Some(kp)
        }
        None => None,
    };

    // Fetch sender's current nonce (0 if node is unreachable and we're in dry-run)
    let nonce = if g.dry_run {
        fetch_nonce(&g.node, &g.from).unwrap_or(0)
    } else {
        fetch_nonce(&g.node, &g.from).unwrap_or_else(|e| {
            die(&format!(
                "cannot fetch nonce from {}: {e}\n\
                 Is the node running?  Use --dry-run to bypass this check.",
                g.node
            ))
        })
    };

    let tx_id = new_tx_id();

    let mut tx = Transaction {
        id:            tx_id.clone(),
        sender:        g.from.clone(),
        nonce,
        body,
        gas_limit:     g.gas,
        signature:     vec![],
        public_key:    vec![],
        pq_signatures: vec![],
        pq_public_key: vec![],
    };

    // Sign if a keypair was loaded
    if let Some(kp) = keypair {
        tx.sign(&kp, &g.chain_id).unwrap_or_else(|e| {
            die(&format!("signing failed: {e}"))
        });
        eprintln!("Signed with key  pk={}", hex_encode(&tx.public_key));
    }

    // Serialize
    let tx_json = serde_json::to_string_pretty(&tx).unwrap_or_else(|e| {
        die(&format!("JSON serialization failed: {e}"))
    });

    // Dry-run: just print and exit
    if g.dry_run {
        println!("{tx_json}");
        return;
    }

    // Submit
    eprintln!("Submitting {} → {} ...", tx_id, g.node);

    let resp = submit_tx(&g.node, &tx_json).unwrap_or_else(|e| {
        die(&format!("submission failed: {e}"))
    });

    // Print result
    match serde_json::from_str::<Value>(&resp) {
        Ok(v) => {
            let status = v.get("status").and_then(|s| s.as_str()).unwrap_or("?");
            if status == "queued" {
                let returned_id = v.get("tx_id").and_then(|s| s.as_str()).unwrap_or(&tx_id);
                println!("queued  tx_id={returned_id}");
            } else {
                let reason = v
                    .get("reason")
                    .and_then(|s| s.as_str())
                    .unwrap_or("(no reason)");
                eprintln!("rejected: {reason}");
                if let Ok(pretty) = serde_json::to_string_pretty(&v) {
                    eprintln!("{pretty}");
                }
                std::process::exit(1);
            }
        }
        Err(_) => {
            // Raw / non-JSON response from node
            println!("{resp}");
        }
    }
}
