//! dis-test-helper — Dilithium3 / DIS cryptographic operations for the Agent8 I11 live test.
//!
//! The Python Agent8 harness calls this binary as a subprocess; it reads a JSON
//! command from stdin and writes a JSON result to stdout.
//!
//! ## Commands (select via `--cmd`)
//!
//!   keygen
//!     Output: {"public_key_hex": "...", "secret_key_hex": "..."}
//!
//!   sign-nonce --sk <hex> --nonce <utf8_nonce_str>
//!     Sign the enrollment nonce (UTF-8 bytes of the nonce string).
//!     Output: {"signature_hex": "..."}
//!
//!   sign-transcript --sk <hex> --transcript <hex>
//!     Sign a pre-computed canonical_request transcript.
//!     Output: {"signature_hex": "..."}
//!
//!   make-delegation --delegator-pk <hex> --delegator-sk <hex>
//!                   --delegate-pk <hex> --rp-id <str>
//!                   --resource-id <str> --action <str>
//!                   --scopes <comma-sep> --issued-at <u64> --expires-at <u64>
//!                   [--max-uses <u32>]
//!     Output: {"signature_hex": "..."}

use dis_core::delegation::{canonical_delegation_body, Delegation};
use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};
use std::env;

fn die(msg: &str) -> ! {
    eprintln!("{msg}");
    std::process::exit(1);
}

fn arg(args: &[String], flag: &str) -> String {
    let i = args.iter().position(|a| a == flag).unwrap_or_else(|| die(&format!("missing {flag}")));
    args.get(i + 1).cloned().unwrap_or_else(|| die(&format!("{flag} requires a value")))
}

fn opt_arg(args: &[String], flag: &str) -> Option<String> {
    let i = args.iter().position(|a| a == flag)?;
    args.get(i + 1).cloned()
}

fn from_hex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap_or_else(|_| die(&format!("invalid hex: {s}")))
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let cmd = args.get(1).cloned().unwrap_or_default();

    match cmd.as_str() {
        "keygen" => {
            let (pk, sk) = dilithium3::keypair();
            println!(
                r#"{{"public_key_hex":"{}","secret_key_hex":"{}"}}"#,
                hex::encode(pk.as_bytes()),
                hex::encode(sk.as_bytes()),
            );
        }

        "sign-nonce" => {
            let sk_hex = arg(&args, "--sk");
            let nonce_str = arg(&args, "--nonce");
            let sk = dilithium3::SecretKey::from_bytes(&from_hex(&sk_hex))
                .unwrap_or_else(|_| die("invalid secret key"));
            let sig = dilithium3::detached_sign(nonce_str.as_bytes(), &sk);
            println!(r#"{{"signature_hex":"{}"}}"#, hex::encode(sig.as_bytes()));
        }

        "sign-transcript" => {
            let sk_hex = arg(&args, "--sk");
            let transcript_hex = arg(&args, "--transcript");
            let sk = dilithium3::SecretKey::from_bytes(&from_hex(&sk_hex))
                .unwrap_or_else(|_| die("invalid secret key"));
            let sig = dilithium3::detached_sign(&from_hex(&transcript_hex), &sk);
            println!(r#"{{"signature_hex":"{}"}}"#, hex::encode(sig.as_bytes()));
        }

        "make-delegation" => {
            let delegator_pk = from_hex(&arg(&args, "--delegator-pk"));
            let delegator_sk_bytes = from_hex(&arg(&args, "--delegator-sk"));
            let delegate_pk = from_hex(&arg(&args, "--delegate-pk"));
            let rp_id = arg(&args, "--rp-id");
            let resource_id = arg(&args, "--resource-id");
            let action = arg(&args, "--action");
            let scopes: Vec<String> = arg(&args, "--scopes")
                .split(',').map(|s| s.trim().to_string()).collect();
            let issued_at: u64 = arg(&args, "--issued-at").parse()
                .unwrap_or_else(|_| die("--issued-at must be u64"));
            let expires_at: u64 = arg(&args, "--expires-at").parse()
                .unwrap_or_else(|_| die("--expires-at must be u64"));
            let max_uses: Option<u32> = opt_arg(&args, "--max-uses")
                .map(|s| s.parse().unwrap_or_else(|_| die("--max-uses must be u32")));

            let mut d = Delegation {
                rp_id,
                delegator_public_key: delegator_pk,
                delegate_public_key: delegate_pk,
                scopes,
                resource_id,
                action,
                issued_at,
                expires_at,
                max_uses,
                requires_human_approval: false,
                signature: vec![],
            };

            let body = canonical_delegation_body(&d)
                .unwrap_or_else(|e| die(&format!("canonical_delegation_body: {e}")));
            let sk = dilithium3::SecretKey::from_bytes(&delegator_sk_bytes)
                .unwrap_or_else(|_| die("invalid delegator secret key"));
            let sig = dilithium3::detached_sign(&body, &sk);
            d.signature = sig.as_bytes().to_vec();

            println!(r#"{{"signature_hex":"{}"}}"#, hex::encode(d.signature));
        }

        "canonical-request" => {
            // Compute canonical_request bytes from challenge JSON fields piped on stdin.
            // Input (JSON on stdin): {suite_id, rp_id, rp_origin, challenge_id (array of u8),
            //   nonce (array of u8), issued_at, expires_at, resource_id, action,
            //   scopes (array), policy_id}
            // Output: {"transcript_hex": "..."}
            use std::io::Read;
            let mut input = String::new();
            std::io::stdin().read_to_string(&mut input)
                .unwrap_or_else(|_| die("could not read stdin"));
            let v: serde_json::Value = serde_json::from_str(&input)
                .unwrap_or_else(|_| die("invalid JSON on stdin"));

            let challenge_id_arr: Vec<u8> = v["challenge_id"].as_array()
                .unwrap_or_else(|| die("challenge_id not array"))
                .iter().map(|x| x.as_u64().unwrap_or_default() as u8).collect();
            let nonce_arr: Vec<u8> = v["nonce"].as_array()
                .unwrap_or_else(|| die("nonce not array"))
                .iter().map(|x| x.as_u64().unwrap_or_default() as u8).collect();
            let challenge_id: [u8; 16] = <[u8; 16]>::try_from(challenge_id_arr.as_slice())
                .unwrap_or_else(|_| die("challenge_id must be 16 bytes"));
            let nonce: [u8; 16] = <[u8; 16]>::try_from(nonce_arr.as_slice())
                .unwrap_or_else(|_| die("nonce must be 16 bytes"));
            let scopes: Vec<String> = v["scopes"].as_array()
                .unwrap_or_else(|| die("scopes not array"))
                .iter().map(|x| x.as_str().unwrap_or_default().to_string()).collect();

            let r = dis_core::Request {
                suite_id: v["suite_id"].as_u64().unwrap_or(1) as u16,
                rp_id: v["rp_id"].as_str().unwrap_or_default().to_string(),
                rp_origin: v["rp_origin"].as_str().unwrap_or_default().to_string(),
                challenge_id,
                nonce,
                issued_at: v["issued_at"].as_u64().unwrap_or_default(),
                expires_at: v["expires_at"].as_u64().unwrap_or_default(),
                resource_id: v["resource_id"].as_str().unwrap_or_default().to_string(),
                action: v["action"].as_str().unwrap_or_default().to_string(),
                scopes,
                operation_digest: None,
                policy_id: v["policy_id"].as_str().unwrap_or_default().to_string(),
            };
            let transcript = dis_core::canonical_request(&r)
                .unwrap_or_else(|e| die(&format!("canonical_request: {e}")));
            println!(r#"{{"transcript_hex":"{}"}}"#, hex::encode(transcript));
        }

        _ => die("usage: dis-test-helper <keygen|sign-nonce|sign-transcript|make-delegation|canonical-request> [args...]"),
    }
}
