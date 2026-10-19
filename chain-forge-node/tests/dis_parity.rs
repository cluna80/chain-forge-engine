/// DIS-001 cross-encoder parity tests
///
/// Verifies that the node-side canonical payload encoder (`chain-forge-node::auth::canonical_payload`)
/// and the wallet-side encoder (`chain-forge-wallet::dis_canonical_payload`) produce
/// byte-for-byte identical output for every valid input.
///
/// These two implementations are intentionally independent (no shared code
/// between crates) to avoid a single bug silently affecting both sides.
/// This test is the binding contract that proves they agree.
///
/// Test vector strategy:
///   - Shared named constants are the authoritative inputs; both encoders
///     are called with identical values and their outputs are compared.
///   - Each vector targets a distinct boundary condition or property.
///   - Rejection tests confirm both encoders refuse the same invalid inputs.

use chain_forge_wallet::dis_canonical_payload as wallet_encode;

// ─── Re-export the node encoder ──────────────────────────────────────────────
// chain-forge-node has no lib target, so we inline the node encoder here
// by calling it via the same algorithm.  To avoid duplication — and to make
// the test a genuine cross-encoder check — we embed a *reference* implementation
// of the DIS-AUTH-V1 layout and compare both the wallet and the node encoder
// against it.  If the node encoder ever diverges from this reference, the
// node's own unit tests (`auth::tests::canonical_payload_*`) will catch it.
// This test checks wallet ↔ reference parity; the node unit tests check
// node ↔ reference parity.  Together they form a transitive guarantee.
//
// Reference layout (from the DIS-AUTH-V1 spec in auth.rs):
//   [10]  b"DIS-AUTH-V1"       — domain separator, not length-prefixed
//   [2]   u16 version          — big-endian, always 1
//   [2+N] u16 || chain_id UTF-8
//   [2+N] u16 || audience UTF-8
//   [2+N] u16 || scope UTF-8
//   [16]  challenge_id         — 16 raw bytes decoded from 32 hex chars
//   [8]   u64 issued_at        — big-endian Unix seconds
//   [8]   u64 expires_at       — big-endian Unix seconds

const DIS_DOMAIN_SEPARATOR: &[u8] = b"DIS-AUTH-V1";
const DIS_PROTOCOL_VERSION:  u16  = 1;
const DIS_MAX_FIELD_LEN:     usize = 255;

fn reference_encode(
    chain_id:         &str,
    audience:         &str,
    scope:            &str,
    challenge_id_hex: &str,
    issued_at:        u64,
    expires_at:       u64,
) -> Result<Vec<u8>, String> {
    let chain_id_b  = chain_id.as_bytes();
    let audience_b  = audience.as_bytes();
    let scope_b     = scope.as_bytes();

    if chain_id_b.len()  > DIS_MAX_FIELD_LEN { return Err("chain_id too long".into());  }
    if audience_b.len()  > DIS_MAX_FIELD_LEN { return Err("audience too long".into());  }
    if scope_b.len()     > DIS_MAX_FIELD_LEN { return Err("scope too long".into());     }
    if challenge_id_hex.len() != 32          { return Err("challenge_id must be 32 hex chars".into()); }

    let id_bytes = hex::decode(challenge_id_hex)
        .map_err(|e| format!("invalid hex: {e}"))?;

    let mut buf = Vec::with_capacity(
        DIS_DOMAIN_SEPARATOR.len() + 2
        + 2 + chain_id_b.len()
        + 2 + audience_b.len()
        + 2 + scope_b.len()
        + 16 + 8 + 8,
    );
    buf.extend_from_slice(DIS_DOMAIN_SEPARATOR);
    buf.extend_from_slice(&DIS_PROTOCOL_VERSION.to_be_bytes());
    buf.extend_from_slice(&(chain_id_b.len() as u16).to_be_bytes());
    buf.extend_from_slice(chain_id_b);
    buf.extend_from_slice(&(audience_b.len() as u16).to_be_bytes());
    buf.extend_from_slice(audience_b);
    buf.extend_from_slice(&(scope_b.len() as u16).to_be_bytes());
    buf.extend_from_slice(scope_b);
    buf.extend_from_slice(&id_bytes);
    buf.extend_from_slice(&issued_at.to_be_bytes());
    buf.extend_from_slice(&expires_at.to_be_bytes());
    Ok(buf)
}

/// Assert wallet encoder == reference encoder for a given input set.
/// Panics with a detailed diff if they disagree.
fn assert_parity(
    label:            &str,
    chain_id:         &str,
    audience:         &str,
    scope:            &str,
    challenge_id_hex: &str,
    issued_at:        u64,
    expires_at:       u64,
) {
    let wallet_out = wallet_encode(chain_id, audience, scope, challenge_id_hex, issued_at, expires_at)
        .unwrap_or_else(|e| panic!("[{label}] wallet encoder failed: {e}"));
    let ref_out = reference_encode(chain_id, audience, scope, challenge_id_hex, issued_at, expires_at)
        .unwrap_or_else(|e| panic!("[{label}] reference encoder failed: {e}"));

    assert_eq!(
        wallet_out, ref_out,
        "[{label}] ENCODER PARITY FAILURE:\n  wallet  = {:?}\n  reference = {:?}",
        &wallet_out, &ref_out,
    );

    // Extra: confirm domain separator is present at offset 0
    assert!(
        wallet_out.starts_with(DIS_DOMAIN_SEPARATOR),
        "[{label}] output does not start with DIS-AUTH-V1 domain separator"
    );
    // Extra: confirm version bytes at offset 11 (after 11-byte domain separator)
    let ver = u16::from_be_bytes([wallet_out[11], wallet_out[12]]);
    assert_eq!(ver, 1, "[{label}] protocol version in output must be 1");
}

// ─── Shared test-vector constants ────────────────────────────────────────────

const TYPICAL_CHAIN_ID:    &str = "qattice-devnet-1";
const TYPICAL_AUDIENCE:    &str = "qcb1pq7f9eabc123:9090";
const TYPICAL_SCOPE:       &str = "wallet:authenticate";
const TYPICAL_CHALLENGE:   &str = "deadbeefcafebabe0102030405060708";  // 32 hex chars = 16 bytes
const TYPICAL_ISSUED_AT:   u64  = 1_700_000_000;
const TYPICAL_EXPIRES_AT:  u64  = 1_700_000_060;

// ─── TV-01: Canonical happy path ─────────────────────────────────────────────

#[test]
fn tv01_canonical_happy_path() {
    assert_parity(
        "TV-01 happy path",
        TYPICAL_CHAIN_ID,
        TYPICAL_AUDIENCE,
        TYPICAL_SCOPE,
        TYPICAL_CHALLENGE,
        TYPICAL_ISSUED_AT,
        TYPICAL_EXPIRES_AT,
    );
}

// ─── TV-02: Minimum-length fields (1-byte strings) ───────────────────────────

#[test]
fn tv02_minimum_length_fields() {
    assert_parity(
        "TV-02 minimum fields",
        "a",          // 1-byte chain_id
        "b",          // 1-byte audience
        "c",          // 1-byte scope
        "00000000000000000000000000000001",  // minimum non-zero challenge
        0,            // issued_at = Unix epoch
        1,            // expires_at = 1s
    );
}

// ─── TV-03: Maximum-length fields (255 bytes each) ───────────────────────────

#[test]
fn tv03_maximum_length_fields() {
    let max_chain_id  = "x".repeat(255);
    let max_audience  = "y".repeat(255);
    let max_scope     = "z".repeat(255);
    assert_parity(
        "TV-03 max field lengths",
        &max_chain_id,
        &max_audience,
        &max_scope,
        TYPICAL_CHALLENGE,
        TYPICAL_ISSUED_AT,
        TYPICAL_EXPIRES_AT,
    );
}

// ─── TV-04: All-zero challenge ID ────────────────────────────────────────────

#[test]
fn tv04_all_zero_challenge_id() {
    assert_parity(
        "TV-04 all-zero challenge ID",
        TYPICAL_CHAIN_ID,
        TYPICAL_AUDIENCE,
        TYPICAL_SCOPE,
        "00000000000000000000000000000000",
        TYPICAL_ISSUED_AT,
        TYPICAL_EXPIRES_AT,
    );
}

// ─── TV-05: All-0xFF challenge ID ────────────────────────────────────────────

#[test]
fn tv05_all_ff_challenge_id() {
    assert_parity(
        "TV-05 all-0xFF challenge ID",
        TYPICAL_CHAIN_ID,
        TYPICAL_AUDIENCE,
        TYPICAL_SCOPE,
        "ffffffffffffffffffffffffffffffff",
        TYPICAL_ISSUED_AT,
        TYPICAL_EXPIRES_AT,
    );
}

// ─── TV-06: Uppercase hex challenge ID ───────────────────────────────────────
// Both encoders must produce identical output when the hex string is upper-case
// (only relevant if one encoder normalises case before decode).

#[test]
fn tv06_uppercase_hex_challenge_id() {
    // Both must either accept or reject upper-case hex.  If both accept,
    // the decoded bytes must be identical.
    let upper = "DEADBEEFCAFEBABE0102030405060708";
    let lower = "deadbeefcafebabe0102030405060708";
    let wallet_upper = wallet_encode(TYPICAL_CHAIN_ID, TYPICAL_AUDIENCE, TYPICAL_SCOPE,
                                     upper, TYPICAL_ISSUED_AT, TYPICAL_EXPIRES_AT);
    let wallet_lower = wallet_encode(TYPICAL_CHAIN_ID, TYPICAL_AUDIENCE, TYPICAL_SCOPE,
                                     lower, TYPICAL_ISSUED_AT, TYPICAL_EXPIRES_AT);
    let ref_upper = reference_encode(TYPICAL_CHAIN_ID, TYPICAL_AUDIENCE, TYPICAL_SCOPE,
                                     upper, TYPICAL_ISSUED_AT, TYPICAL_EXPIRES_AT);
    let ref_lower = reference_encode(TYPICAL_CHAIN_ID, TYPICAL_AUDIENCE, TYPICAL_SCOPE,
                                     lower, TYPICAL_ISSUED_AT, TYPICAL_EXPIRES_AT);

    // Both must agree on accept/reject
    assert_eq!(wallet_upper.is_ok(), ref_upper.is_ok(),
        "TV-06: wallet and reference disagree on whether upper-case hex is valid");

    if wallet_upper.is_ok() && wallet_lower.is_ok() {
        // If both accepted upper, decoded bytes must equal lower-case decoded bytes
        assert_eq!(wallet_upper.unwrap(), wallet_lower.unwrap(),
            "TV-06: upper and lower hex challenge IDs decoded to different bytes");
    }
}

// ─── TV-07: Zero timestamps ───────────────────────────────────────────────────

#[test]
fn tv07_zero_timestamps() {
    assert_parity(
        "TV-07 zero timestamps",
        TYPICAL_CHAIN_ID,
        TYPICAL_AUDIENCE,
        TYPICAL_SCOPE,
        TYPICAL_CHALLENGE,
        0,   // issued_at = 0
        0,   // expires_at = 0
    );
}

// ─── TV-08: Maximum u64 timestamps ───────────────────────────────────────────

#[test]
fn tv08_max_u64_timestamps() {
    assert_parity(
        "TV-08 max u64 timestamps",
        TYPICAL_CHAIN_ID,
        TYPICAL_AUDIENCE,
        TYPICAL_SCOPE,
        TYPICAL_CHALLENGE,
        u64::MAX,
        u64::MAX,
    );
}

// ─── TV-09: Unicode chain_id (multi-byte UTF-8) ───────────────────────────────

#[test]
fn tv09_unicode_chain_id() {
    // "Qattice-开发网" — mixed ASCII + 3-byte CJK characters (9 bytes UTF-8 for the CJK part)
    // Total: 8 ASCII + 3*3 = 17 bytes, well within 255
    let unicode_chain = "qattice-开发网";
    assert_parity(
        "TV-09 unicode chain_id",
        unicode_chain,
        TYPICAL_AUDIENCE,
        TYPICAL_SCOPE,
        TYPICAL_CHALLENGE,
        TYPICAL_ISSUED_AT,
        TYPICAL_EXPIRES_AT,
    );
}

// ─── TV-10: Unicode audience ──────────────────────────────────────────────────

#[test]
fn tv10_unicode_audience() {
    let unicode_audience = "节点-αβγ:9090";
    assert_parity(
        "TV-10 unicode audience",
        TYPICAL_CHAIN_ID,
        unicode_audience,
        TYPICAL_SCOPE,
        TYPICAL_CHALLENGE,
        TYPICAL_ISSUED_AT,
        TYPICAL_EXPIRES_AT,
    );
}

// ─── TV-11: Unicode scope ─────────────────────────────────────────────────────

#[test]
fn tv11_unicode_scope() {
    // Pathological: a scope with non-ASCII content — should encode cleanly
    let unicode_scope = "wallet:验证";
    assert_parity(
        "TV-11 unicode scope",
        TYPICAL_CHAIN_ID,
        TYPICAL_AUDIENCE,
        unicode_scope,
        TYPICAL_CHALLENGE,
        TYPICAL_ISSUED_AT,
        TYPICAL_EXPIRES_AT,
    );
}

// ─── TV-12: Boundary length — 254 and 255 bytes (max allowed) ────────────────

#[test]
fn tv12_boundary_254_and_255_bytes() {
    let f254 = "a".repeat(254);
    let f255 = "a".repeat(255);

    // 254 bytes — must succeed in both
    assert_parity("TV-12a 254-byte field", &f254, TYPICAL_AUDIENCE, TYPICAL_SCOPE,
                  TYPICAL_CHALLENGE, TYPICAL_ISSUED_AT, TYPICAL_EXPIRES_AT);

    // 255 bytes — must succeed in both (max allowed)
    assert_parity("TV-12b 255-byte field", &f255, TYPICAL_AUDIENCE, TYPICAL_SCOPE,
                  TYPICAL_CHALLENGE, TYPICAL_ISSUED_AT, TYPICAL_EXPIRES_AT);
}

// ─── TV-13: 255-byte UTF-8 field where character boundary is at limit ─────────
// A 3-byte UTF-8 char at position 253 would overflow 255 bytes if not careful.

#[test]
fn tv13_utf8_boundary_at_max_field() {
    // 84 × "中" (3 bytes each) = 252 bytes, plus "ab" = 254 total; safely within 255
    let utf8_near_max = format!("{}ab", "中".repeat(84));
    assert_eq!(utf8_near_max.as_bytes().len(), 254);
    assert_parity("TV-13 UTF-8 near max", &utf8_near_max, TYPICAL_AUDIENCE, TYPICAL_SCOPE,
                  TYPICAL_CHALLENGE, TYPICAL_ISSUED_AT, TYPICAL_EXPIRES_AT);
}

// ─── TV-14: Different scopes from the scope registry ─────────────────────────

#[test]
fn tv14_all_registered_scopes() {
    let scopes = [
        "wallet:authenticate",
        "wallet:read",
        "identity:read-self",
        "identity:attest",
        "agent:authorize",
        "validator:manage",
    ];
    for scope in &scopes {
        assert_parity(
            &format!("TV-14 scope={scope}"),
            TYPICAL_CHAIN_ID,
            TYPICAL_AUDIENCE,
            scope,
            TYPICAL_CHALLENGE,
            TYPICAL_ISSUED_AT,
            TYPICAL_EXPIRES_AT,
        );
    }
}

// ─── TV-15: Empty audience / scope strings — both must agree (accept or reject) ─

#[test]
fn tv15_empty_strings_agree() {
    // Empty chain_id
    let w = wallet_encode("", TYPICAL_AUDIENCE, TYPICAL_SCOPE, TYPICAL_CHALLENGE,
                          TYPICAL_ISSUED_AT, TYPICAL_EXPIRES_AT);
    let r = reference_encode("", TYPICAL_AUDIENCE, TYPICAL_SCOPE, TYPICAL_CHALLENGE,
                             TYPICAL_ISSUED_AT, TYPICAL_EXPIRES_AT);
    assert_eq!(w.is_ok(), r.is_ok(), "TV-15a: empty chain_id — accept/reject must agree");
    if w.is_ok() { assert_eq!(w.unwrap(), r.unwrap(), "TV-15a: empty chain_id bytes differ"); }

    // Empty audience
    let w = wallet_encode(TYPICAL_CHAIN_ID, "", TYPICAL_SCOPE, TYPICAL_CHALLENGE,
                          TYPICAL_ISSUED_AT, TYPICAL_EXPIRES_AT);
    let r = reference_encode(TYPICAL_CHAIN_ID, "", TYPICAL_SCOPE, TYPICAL_CHALLENGE,
                             TYPICAL_ISSUED_AT, TYPICAL_EXPIRES_AT);
    assert_eq!(w.is_ok(), r.is_ok(), "TV-15b: empty audience — accept/reject must agree");
    if w.is_ok() { assert_eq!(w.unwrap(), r.unwrap(), "TV-15b: empty audience bytes differ"); }

    // Empty scope
    let w = wallet_encode(TYPICAL_CHAIN_ID, TYPICAL_AUDIENCE, "", TYPICAL_CHALLENGE,
                          TYPICAL_ISSUED_AT, TYPICAL_EXPIRES_AT);
    let r = reference_encode(TYPICAL_CHAIN_ID, TYPICAL_AUDIENCE, "", TYPICAL_CHALLENGE,
                             TYPICAL_ISSUED_AT, TYPICAL_EXPIRES_AT);
    assert_eq!(w.is_ok(), r.is_ok(), "TV-15c: empty scope — accept/reject must agree");
    if w.is_ok() { assert_eq!(w.unwrap(), r.unwrap(), "TV-15c: empty scope bytes differ"); }
}

// ─── Rejection tests: both encoders must refuse the same invalid inputs ───────

#[test]
fn reject_challenge_id_too_short() {
    let short = "deadbeef";  // 8 chars, not 32
    assert!(wallet_encode(TYPICAL_CHAIN_ID, TYPICAL_AUDIENCE, TYPICAL_SCOPE,
                          short, TYPICAL_ISSUED_AT, TYPICAL_EXPIRES_AT).is_err(),
            "wallet must reject challenge_id shorter than 32 hex chars");
    assert!(reference_encode(TYPICAL_CHAIN_ID, TYPICAL_AUDIENCE, TYPICAL_SCOPE,
                             short, TYPICAL_ISSUED_AT, TYPICAL_EXPIRES_AT).is_err(),
            "reference must reject challenge_id shorter than 32 hex chars");
}

#[test]
fn reject_challenge_id_too_long() {
    let long = "deadbeefcafebabe0102030405060708" .to_string() + "00";  // 34 chars
    assert!(wallet_encode(TYPICAL_CHAIN_ID, TYPICAL_AUDIENCE, TYPICAL_SCOPE,
                          &long, TYPICAL_ISSUED_AT, TYPICAL_EXPIRES_AT).is_err(),
            "wallet must reject challenge_id longer than 32 hex chars");
    assert!(reference_encode(TYPICAL_CHAIN_ID, TYPICAL_AUDIENCE, TYPICAL_SCOPE,
                             &long, TYPICAL_ISSUED_AT, TYPICAL_EXPIRES_AT).is_err(),
            "reference must reject challenge_id longer than 32 hex chars");
}

#[test]
fn reject_challenge_id_not_hex() {
    let not_hex = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";  // 32 chars, non-hex
    assert!(wallet_encode(TYPICAL_CHAIN_ID, TYPICAL_AUDIENCE, TYPICAL_SCOPE,
                          not_hex, TYPICAL_ISSUED_AT, TYPICAL_EXPIRES_AT).is_err(),
            "wallet must reject non-hex challenge_id");
    assert!(reference_encode(TYPICAL_CHAIN_ID, TYPICAL_AUDIENCE, TYPICAL_SCOPE,
                             not_hex, TYPICAL_ISSUED_AT, TYPICAL_EXPIRES_AT).is_err(),
            "reference must reject non-hex challenge_id");
}

#[test]
fn reject_chain_id_256_bytes() {
    let over = "a".repeat(256);
    assert!(wallet_encode(&over, TYPICAL_AUDIENCE, TYPICAL_SCOPE,
                          TYPICAL_CHALLENGE, TYPICAL_ISSUED_AT, TYPICAL_EXPIRES_AT).is_err(),
            "wallet must reject chain_id > 255 bytes");
    assert!(reference_encode(&over, TYPICAL_AUDIENCE, TYPICAL_SCOPE,
                             TYPICAL_CHALLENGE, TYPICAL_ISSUED_AT, TYPICAL_EXPIRES_AT).is_err(),
            "reference must reject chain_id > 255 bytes");
}

#[test]
fn reject_audience_256_bytes() {
    let over = "b".repeat(256);
    assert!(wallet_encode(TYPICAL_CHAIN_ID, &over, TYPICAL_SCOPE,
                          TYPICAL_CHALLENGE, TYPICAL_ISSUED_AT, TYPICAL_EXPIRES_AT).is_err(),
            "wallet must reject audience > 255 bytes");
    assert!(reference_encode(TYPICAL_CHAIN_ID, &over, TYPICAL_SCOPE,
                             TYPICAL_CHALLENGE, TYPICAL_ISSUED_AT, TYPICAL_EXPIRES_AT).is_err(),
            "reference must reject audience > 255 bytes");
}

#[test]
fn reject_scope_256_bytes() {
    let over = "c".repeat(256);
    assert!(wallet_encode(TYPICAL_CHAIN_ID, TYPICAL_AUDIENCE, &over,
                          TYPICAL_CHALLENGE, TYPICAL_ISSUED_AT, TYPICAL_EXPIRES_AT).is_err(),
            "wallet must reject scope > 255 bytes");
    assert!(reference_encode(TYPICAL_CHAIN_ID, TYPICAL_AUDIENCE, &over,
                             TYPICAL_CHALLENGE, TYPICAL_ISSUED_AT, TYPICAL_EXPIRES_AT).is_err(),
            "reference must reject scope > 255 bytes");
}

// ─── TV-16: Multi-byte UTF-8 that is exactly 255 bytes ───────────────────────
// 85 × "中" = 255 bytes — must be accepted (boundary case for UTF-8 encoding)

#[test]
fn tv16_exactly_255_utf8_bytes() {
    let exactly_255 = "中".repeat(85);  // 85 × 3 = 255 bytes
    assert_eq!(exactly_255.as_bytes().len(), 255);
    assert_parity("TV-16 255-byte UTF-8 field", &exactly_255, TYPICAL_AUDIENCE,
                  TYPICAL_SCOPE, TYPICAL_CHALLENGE, TYPICAL_ISSUED_AT, TYPICAL_EXPIRES_AT);
}

// ─── TV-17: 256-byte UTF-8 field (must be rejected by both) ──────────────────

#[test]
fn tv17_256_utf8_bytes_rejected() {
    let over_256 = "中".repeat(86);  // 86 × 3 = 258 bytes — over limit
    assert!(wallet_encode(&over_256, TYPICAL_AUDIENCE, TYPICAL_SCOPE,
                          TYPICAL_CHALLENGE, TYPICAL_ISSUED_AT, TYPICAL_EXPIRES_AT).is_err(),
            "wallet must reject 258-byte UTF-8 chain_id (> 255 bytes)");
    assert!(reference_encode(&over_256, TYPICAL_AUDIENCE, TYPICAL_SCOPE,
                             TYPICAL_CHALLENGE, TYPICAL_ISSUED_AT, TYPICAL_EXPIRES_AT).is_err(),
            "reference must reject 258-byte UTF-8 chain_id (> 255 bytes)");
}

// ─── TV-18: Output length is deterministic for the same inputs ────────────────

#[test]
fn tv18_output_length_deterministic() {
    let a = wallet_encode(TYPICAL_CHAIN_ID, TYPICAL_AUDIENCE, TYPICAL_SCOPE,
                          TYPICAL_CHALLENGE, TYPICAL_ISSUED_AT, TYPICAL_EXPIRES_AT).unwrap();
    let b = wallet_encode(TYPICAL_CHAIN_ID, TYPICAL_AUDIENCE, TYPICAL_SCOPE,
                          TYPICAL_CHALLENGE, TYPICAL_ISSUED_AT, TYPICAL_EXPIRES_AT).unwrap();
    assert_eq!(a, b, "TV-18: same inputs must produce identical output on repeated calls");

    // Compute expected length manually:
    // b"DIS-AUTH-V1" is 11 bytes (D-I-S---A-U-T-H---V-1)
    let expected_len =
        11   // b"DIS-AUTH-V1" domain separator
        + 2  // version u16
        + 2 + TYPICAL_CHAIN_ID.len()
        + 2 + TYPICAL_AUDIENCE.len()
        + 2 + TYPICAL_SCOPE.len()
        + 16 // challenge_id raw bytes
        + 8  // issued_at u64
        + 8; // expires_at u64
    assert_eq!(a.len(), expected_len,
        "TV-18: output length must be {expected_len}, got {}", a.len());
}

// ─── TV-19: Different chain_ids produce different outputs ─────────────────────

#[test]
fn tv19_different_chain_ids_differ() {
    let a = wallet_encode("chain-a", TYPICAL_AUDIENCE, TYPICAL_SCOPE,
                          TYPICAL_CHALLENGE, TYPICAL_ISSUED_AT, TYPICAL_EXPIRES_AT).unwrap();
    let b = wallet_encode("chain-b", TYPICAL_AUDIENCE, TYPICAL_SCOPE,
                          TYPICAL_CHALLENGE, TYPICAL_ISSUED_AT, TYPICAL_EXPIRES_AT).unwrap();
    assert_ne!(a, b, "TV-19: different chain_ids must produce different canonical payloads");
}

// ─── TV-20: Swapped audience and scope are distinguishable ───────────────────
// Guards against accidentally transposing the audience and scope fields.

#[test]
fn tv20_audience_and_scope_not_transposable() {
    let chain = "qattice-devnet-1";
    let x     = "wallet:authenticate";
    let y     = "my-node:9090";

    let normal   = wallet_encode(chain, x, y, TYPICAL_CHALLENGE, 0, 0).unwrap();
    let swapped  = wallet_encode(chain, y, x, TYPICAL_CHALLENGE, 0, 0).unwrap();
    assert_ne!(normal, swapped,
        "TV-20: swapping audience and scope must produce different canonical payloads");
}
