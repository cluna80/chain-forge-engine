//! The migration guide (`docs/scheduler-signing-boundary/MIGRATION.md`) is tested against the code, so an operator who follows it is not
//! misled: the example bodies must parse strictly, the error table must match the handlers, the signer flags must exist, and the claim that
//! nothing in the repository still calls the removed route is re-checked on every run. No signing feature is needed.

use chain_forge_scheduler::{PrepareRequest, SubmitRequest};
use std::path::{Path, PathBuf};

const GUIDE: &str = include_str!("../../docs/scheduler-signing-boundary/MIGRATION.md");
const API: &str = include_str!("../src/api.rs");
const SIGNER: &str = include_str!("../src/bin/qcb-claim-signer.rs");

fn first_json_after<'a>(text: &'a str, marker: &str) -> &'a str {
    let i = text.find(marker).unwrap_or_else(|| panic!("the guide no longer contains {marker:?}")) + marker.len();
    let rest = &text[i..];
    let start = rest.find('{').expect("a JSON object follows");
    let (mut depth, mut end) = (0i32, 0usize);
    for (k, c) in rest[start..].char_indices() {
        match c { '{' => depth += 1, '}' => { depth -= 1; if depth == 0 { end = start + k + 1; break; } } _ => {} }
    }
    &rest[start..end]
}

#[test]
fn the_prepare_example_in_the_guide_is_a_valid_strict_request() {
    let body = first_json_after(GUIDE, "settle/prepare -H 'content-type: application/json' -d '");
    let req: PrepareRequest = serde_json::from_str(body).unwrap_or_else(|e| panic!("the guide's prepare example is not a valid PrepareRequest ({e}): {body}"));
    assert_eq!(req.signing_profile, "qattice-v2");
    assert_eq!(req.reward_kind, "primary");
}

#[test]
fn the_submit_request_has_exactly_the_four_fields_the_guide_names() {
    for name in ["claim_id", "chain_id", "signed_tx", "node_url"] { assert!(GUIDE.contains(name), "the guide must name {name}"); }
    let ok = r#"{"claim_id":"x","chain_id":"c","signed_tx":{},"node_url":"http://127.0.0.1:1"}"#;
    serde_json::from_str::<SubmitRequest>(ok).expect("the four documented fields are accepted");
    let extra = r#"{"claim_id":"x","chain_id":"c","signed_tx":{},"node_url":"http://127.0.0.1:1","operator_secret_key_hex":"00"}"#;
    assert!(serde_json::from_str::<SubmitRequest>(extra).is_err(), "any other field is refused, as the guide says");
    assert!(!GUIDE.contains("…from signed.json…"), "the old, unrunnable placeholder must not return");
}

/// (documented status, constant in api.rs)
const STATUS: [(u16, &str); 7] = [(400, "BAD_REQUEST"), (404, "NOT_FOUND"), (409, "CONFLICT"), (410, "GONE"), (422, "UNPROCESSABLE_ENTITY"), (501, "NOT_IMPLEMENTED"), (502, "BAD_GATEWAY")];

#[test]
fn every_error_row_in_the_guide_matches_the_handler_status_and_code() {
    let table = GUIDE.split("## Error reference").nth(1).expect("error table").split("##").next().unwrap();
    let mut documented = vec![];
    for line in table.lines().filter(|l| l.starts_with("| ") && l.chars().nth(2).map_or(false, |c| c.is_ascii_digit())) {
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        let status: u16 = cells[1].parse().expect("status cell");
        let konst = STATUS.iter().find(|(s, _)| *s == status).unwrap_or_else(|| panic!("undocumented status {status}")).1;
        for code in cells[2].split(',').map(|c| c.trim().trim_matches('`')).filter(|c| !c.is_empty()) {
            let at = API.find(&format!("\"{code}\"")).unwrap_or_else(|| panic!("the guide documents `{code}` but api.rs never returns it"));
            // In `settlement_error_response` each arm is ONE line: `Error => (StatusCode::X, "code"),`. Check that exact line, so a neighbouring
            // arm's status cannot satisfy the check. Two codes are built elsewhere (the 410 and 422 bodies): for those use a byte window.
            let line_start = API[..at].rfind('\n').map_or(0, |i| i + 1);
            let line_end = API[at..].find('\n').map_or(API.len(), |i| at + i);
            let line = &API[line_start..line_end];
            if line.contains("StatusCode::") {
                assert!(line.contains(&format!("StatusCode::{konst}")), "`{code}` is documented as {status} but its arm in api.rs is: {}", line.trim());
            } else {
                // Byte window, lossily decoded: api.rs contains multibyte characters in comments, so a str slice could split one.
                let window = String::from_utf8_lossy(&API.as_bytes()[at.saturating_sub(400)..(at + 400).min(API.len())]).to_string();
                assert!(window.contains(&format!("StatusCode::{konst}")), "`{code}` is documented as {status} but api.rs does not pair it with StatusCode::{konst}");
            }
            documented.push(code.to_string());
        }
    }
    // The other direction: every code the settlement handlers can return is in the guide.
    let fnbody = API.split("fn settlement_error_response").nth(1).unwrap().split("fn invalid_request").next().unwrap();
    for code in fnbody.split("\"").skip(1).step_by(2).filter(|c| c.chars().all(|ch| ch.is_ascii_lowercase() || ch == '_') && c.contains('_')) {
        if matches!(code, "internal_error") { continue; }
        assert!(documented.iter().any(|d| d == code), "api.rs can return `{code}` but the guide's error table does not list it");
    }
    assert!(documented.len() >= 14, "the table lost rows: {documented:?}");
}

#[test]
fn the_signer_flags_and_passphrase_rules_in_the_guide_exist_in_the_signer() {
    for flag in ["--wallet", "--prepared", "--expect-chain-id", "--max-amount-uqcb"] {
        assert!(GUIDE.contains(flag) && SIGNER.contains(&format!("\"{flag}\"")), "{flag} must be documented and implemented");
    }
    assert!(GUIDE.contains("QCB_WALLET_PASSPHRASE") && SIGNER.contains("QCB_WALLET_PASSPHRASE"));
    assert!(GUIDE.contains("--passphrase") && SIGNER.contains("\"--passphrase\"") && SIGNER.contains("never accepted on the command line"));
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        let name = e.file_name().to_string_lossy().to_string();
        if p.is_dir() {
            if matches!(name.as_str(), "target" | ".git" | "node_modules" | "docs" | "results") { continue; }
            walk(&p, out);
        } else if matches!(p.extension().and_then(|x| x.to_str()), Some("rs" | "py" | "sh" | "ps1" | "js" | "ts" | "toml" | "json" | "yml" | "yaml")) {
            out.push(p);
        }
    }
}

/// The guide says nothing in the repository still calls the removed route or sends a secret key to the scheduler. Re-check it.
#[test]
fn nothing_in_the_repository_still_calls_the_removed_route_or_sends_the_old_field() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf();
    let mut files = vec![];
    walk(&root, &mut files);
    assert!(files.len() > 50, "the scan found too few files ({}); is the path right?", files.len());
    let mut hits = vec![];
    for f in files {
        // The scheduler's own source and tests legitimately name the removed route and field (they refuse them).
        if f.starts_with(root.join("chain-forge-scheduler")) { continue; }
        let Ok(text) = std::fs::read_to_string(&f) else { continue };
        if text.contains("operator_secret_key_hex") { hits.push(format!("{} (operator_secret_key_hex)", f.display())); }
        for pat in ["/settle\"", "/settle'", "/settle`", "/settle?"] { if text.contains(pat) { hits.push(format!("{} ({pat})", f.display())); } }
    }
    assert!(hits.is_empty(), "the guide's 'known dependencies' table is out of date; new references to the removed route: {hits:#?}");
}
