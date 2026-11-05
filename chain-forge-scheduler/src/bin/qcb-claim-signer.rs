//! `qcb-claim-signer`: the signer side of the scheduler's two-step settlement flow (feature `signing-v2`).
//!
//!   qcb-claim-signer --wallet <file> --prepared <prepare-response.json> --expect-chain-id <id> [--max-amount-uqcb <n>] [--out <file>]
//!
//! This process holds the operator's key (an encrypted wallet file; the passphrase comes from `QCB_WALLET_PASSPHRASE` or stdin, never
//! from the command line). The scheduler is **untrusted** here: a compromised scheduler is exactly the threat the split exists for. So
//! the signer recomputes the signing-v2 preimage itself and signs only a `ClaimResearchReward` from its own address, for the chain it was
//! told to expect, with the fixed claim gas limit, no signature yet, and (if set) an amount under the operator's ceiling.
//!
//! Output: one JSON document `{"claim_id": ..., "signed_tx": ...}` on stdout (or `--out`). Nothing is printed on refusal.
//! Exit codes: 0 signed, 1 refused or failed, 2 usage.

use chain_forge_crypto::fips204_backend::MlDsa65Fips204 as B;
use chain_forge_crypto::SchemeId;
use chain_forge_execution::{signing_v2, Transaction, TxBody};
use chain_forge_scheduler::settlement::CLAIM_GAS_LIMIT;
use serde_json::Value;
use std::io::{BufRead, Write};

fn usage(msg: &str) -> ! {
    eprintln!("error: {msg}");
    eprintln!("usage: qcb-claim-signer --wallet <file> --prepared <file> --expect-chain-id <id> [--max-amount-uqcb <n>] [--out <file>]");
    eprintln!("The passphrase comes from QCB_WALLET_PASSPHRASE or stdin, never from the command line.");
    std::process::exit(2)
}

fn refuse(msg: &str) -> ! {
    eprintln!("refused: {msg}");
    std::process::exit(1)
}

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (mut wallet, mut prepared, mut chain, mut max_amount, mut out) = (None::<String>, None::<String>, None::<String>, None::<u64>, None::<String>);
    let mut i = 0;
    while i < args.len() {
        let flag = args[i].clone();
        let mut val = || -> String {
            i += 1;
            match args.get(i) { Some(v) => v.clone(), None => usage("a flag is missing its value") }
        };
        match flag.as_str() {
            "--passphrase" | "--password" | "-p" => usage("a passphrase is never accepted on the command line"),
            "--wallet" => wallet = Some(val()),
            "--prepared" => prepared = Some(val()),
            "--expect-chain-id" => chain = Some(val()),
            "--max-amount-uqcb" => max_amount = Some(val().parse().unwrap_or_else(|_| usage("--max-amount-uqcb needs a whole number"))),
            "--out" => out = Some(val()),
            other => usage(&format!("unknown argument {other}")),
        }
        i += 1;
    }
    let wallet = wallet.unwrap_or_else(|| usage("--wallet is required"));
    let prepared_path = prepared.unwrap_or_else(|| usage("--prepared is required"));
    let chain = chain.unwrap_or_else(|| usage("--expect-chain-id is required: the signer never signs for a guessed chain"));

    let pass = std::env::var("QCB_WALLET_PASSPHRASE").unwrap_or_else(|_| {
        eprintln!("Passphrase (read from stdin; it is not hidden):");
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line).unwrap_or_else(|e| refuse(&format!("cannot read the passphrase: {e}")));
        line.trim_end_matches(['\n', '\r']).to_string()
    });

    let raw = std::fs::read(&prepared_path).unwrap_or_else(|e| refuse(&format!("cannot read {prepared_path}: {e}")));
    if raw.len() > 1_048_576 { refuse("the prepared file is larger than 1 MiB"); }
    let doc: Value = serde_json::from_slice(&raw).unwrap_or_else(|_| refuse("the prepared file is not JSON"));

    // ---- checks that need no key ----
    let sr = &doc["signing_request"];
    if sr["profile"] != "qattice-v2" { refuse("the signing request is not for profile qattice-v2 (there is no legacy fallback)"); }
    if sr["context"] != String::from_utf8_lossy(signing_v2::TX_CONTEXT).as_ref() { refuse("the signing context is not qattice/tx/v2"); }
    if sr["chain_id"] != chain.as_str() { refuse("the signing request names a different chain than --expect-chain-id"); }
    let tx: Transaction = serde_json::from_value(doc["unsigned_tx"].clone()).unwrap_or_else(|_| refuse("unsigned_tx is not a transaction"));
    if !tx.pq_signatures.is_empty() || !tx.signature.is_empty() || !tx.public_key.is_empty() { refuse("the transaction already carries signature material"); }
    if tx.gas_limit != CLAIM_GAS_LIMIT { refuse("the gas limit is not the fixed claim gas limit"); }
    let (claim_id, amount) = match &tx.body {
        TxBody::ClaimResearchReward { claim_id, amount_uqcb, .. } => (claim_id.clone(), *amount_uqcb),
        _ => refuse("the transaction is not a ClaimResearchReward: this signer signs claims only"),
    };
    if doc["claim_id"] != claim_id.as_str() { refuse("the claim id of the request does not match the transaction body"); }
    if amount == 0 { refuse("the claim amount is zero"); }
    if let Some(max) = max_amount { if amount > max { refuse("the claim amount is above --max-amount-uqcb"); } }

    // ---- the key ----
    let (kf, kp) = chain_forge_wallet::load_wallet(&wallet, &pass).unwrap_or_else(|_| refuse("cannot load the wallet (wrong passphrase, or the file is damaged)"));
    B::validate_keypair(&kp.public_key, &kp.private_key).unwrap_or_else(|_| refuse("the wallet's key pair is not consistent"));
    if tx.sender != kf.address || sr["signer"] != kf.address.as_str() { refuse("the transaction is not from this wallet's address"); }
    if !tx.pq_public_key.is_empty() && tx.pq_public_key != kp.public_key { refuse("the transaction carries a public key that is not this wallet's"); }
    if sr["pq_public_key_hex"] != hex(&kp.public_key).as_str() { refuse("the signing request names a public key that is not this wallet's"); }

    // The signer's own preimage is the only thing it signs; the scheduler's copy must agree with it.
    let mut tx = tx;
    tx.sig_scheme = Some(SchemeId::MlDsa);
    let preimage = signing_v2::tx_preimage(&chain, &tx, &kp.public_key).unwrap_or_else(|_| refuse("cannot compute the signing preimage"));
    if sr["preimage_hex"] != hex(&preimage).as_str() { refuse("the scheduler's preimage is not the preimage of this transaction"); }

    eprintln!("signing claim {claim_id}: {amount} uqcb, chain {chain}, nonce {}", tx.nonce);
    let sig = B::sign(&kp.private_key, &preimage, signing_v2::TX_CONTEXT).unwrap_or_else(|_| refuse("signing failed"));
    tx.pq_signatures = vec![format!("mldsa65:{}", hex(&sig))];

    let result = serde_json::json!({ "claim_id": claim_id, "signed_tx": serde_json::to_value(&tx).unwrap() });
    let text = serde_json::to_string(&result).unwrap();
    match out {
        Some(path) => {
            let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(&path).unwrap_or_else(|e| refuse(&format!("cannot create {path}: {e}")));
            f.write_all(text.as_bytes()).unwrap_or_else(|e| refuse(&format!("write failed: {e}")));
        }
        None => println!("{text}"),
    }
}
