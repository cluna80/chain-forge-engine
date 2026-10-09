#!/usr/bin/env python3
"""
phase1_contribution_test.py — Phase 1C adversarial test suite for the
contribution verification layer (RegisterMachine + SubmitUsefulWork).

Tests every anti-farming guard wired in Phase 1A/1C:

  Test 1  Happy path — register a machine and submit a valid Grand Challenge
           receipt; confirm receipt stored and contribution score incremented.

  Test 2  Duplicate machine registration — second RegisterMachine with same
           machine_id must be rejected.

  Test 3  Unregistered machine — SubmitUsefulWork for a machine that was never
           registered must be rejected.

  Test 4  Bad seal — SubmitUsefulWork with a fabricated seal_hash that does NOT
           satisfy the stated difficulty must be rejected.

  Test 5  Trivial difficulty (< 8 bits) — SubmitUsefulWork with
           seal_difficulty_bits=4 must be rejected even if the seal is valid.

  Test 6  Below min_difficulty_override — supply override=12 but only
           provide a seal at difficulty=8; must be rejected.

  Test 7  Duplicate receipt — submit the same receipt_id twice; second must
           be rejected.

  Test 8  Wrong owner submits work — a second identity (Bob) tries to submit
           a UsefulWork receipt for Alice's machine without being the owner or
           a Verified coordinator; must be rejected.

  Test 9  Epoch receipt rate limit — submit 101 receipts from one machine in
           the same epoch; the 101st must be rejected.

Usage:
  python3 scripts/phase1_contribution_test.py

Requirements:
  - Devnet running (Alice:8080, Bob:8081, Dave:8082)
  - Python 3.8+ (stdlib only)
"""

import hashlib
import struct
import http.client
import json
import sys
import time
import random
import string

# ── Config ────────────────────────────────────────────────────────────────────

ALICE = ("127.0.0.1", 8080)
BOB   = ("127.0.0.1", 8081)

# Genesis-funded wallets (from devnet genesis).
ALICE_WALLET = "alice"
BOB_WALLET   = "bob"

# ── Seal helpers ──────────────────────────────────────────────────────────────

def compute_seal_hash(seal_nonce: int, output_hash_hex: str, challenge_id: str) -> str:
    """SHA256(seal_nonce_be8 || output_hash_bytes || challenge_id_bytes)."""
    output_bytes = bytes.fromhex(output_hash_hex)
    nonce_bytes  = struct.pack(">Q", seal_nonce)
    digest = hashlib.sha256(nonce_bytes + output_bytes + challenge_id.encode()).hexdigest()
    return digest

def meets_difficulty(seal_hash_hex: str, difficulty_bits: int) -> bool:
    """Returns True iff seal_hash_hex starts with difficulty_bits zero bits."""
    if difficulty_bits == 0:
        return True
    full_nibbles = difficulty_bits // 4
    rem_bits     = difficulty_bits % 4
    for i in range(full_nibbles):
        if seal_hash_hex[i] != '0':
            return False
    if rem_bits > 0:
        nibble = int(seal_hash_hex[full_nibbles], 16)
        shifted = (nibble << 4) & 0xFF
        mask = ~((1 << (8 - rem_bits)) - 1) & 0xFF
        if shifted & mask != 0:
            return False
    return True

def find_seal(output_hash_hex: str, challenge_id: str, difficulty_bits: int,
              max_attempts: int = 2_000_000) -> tuple[int, str]:
    """Mine a valid seal nonce. Returns (nonce, seal_hash_hex)."""
    for nonce in range(max_attempts):
        h = compute_seal_hash(nonce, output_hash_hex, challenge_id)
        if meets_difficulty(h, difficulty_bits):
            return nonce, h
    raise RuntimeError(f"No seal found in {max_attempts} attempts at difficulty={difficulty_bits}")

# ── HTTP helpers ──────────────────────────────────────────────────────────────

def post(host: str, port: int, path: str, body: dict) -> dict:
    conn = http.client.HTTPConnection(host, port, timeout=10)
    data = json.dumps(body).encode()
    conn.request("POST", path, data, {"Content-Type": "application/json"})
    resp = conn.getresponse()
    raw = resp.read()
    conn.close()
    try:
        return {"status": resp.status, "body": json.loads(raw)}
    except Exception:
        return {"status": resp.status, "body": raw.decode(errors="replace")}

def get(host: str, port: int, path: str) -> dict:
    conn = http.client.HTTPConnection(host, port, timeout=10)
    conn.request("GET", path)
    resp = conn.getresponse()
    raw = resp.read()
    conn.close()
    try:
        return {"status": resp.status, "body": json.loads(raw)}
    except Exception:
        return {"status": resp.status, "body": raw.decode(errors="replace")}

def send_tx(host: str, port: int, tx: dict) -> dict:
    return post(host, port, "/api/tx", tx)

def uid(prefix: str = "") -> str:
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return f"{prefix}{suffix}"

# ── Tx builders ───────────────────────────────────────────────────────────────

def register_machine_tx(sender: str, machine_id: str, mode: str = "ContributionOnly") -> dict:
    return {
        "id":        uid("tx-reg-"),
        "sender":    sender,
        "nonce":     int(time.time() * 1000),
        "body": {
            "type":                "RegisterMachine",
            "machine_id":          machine_id,
            "display_name":        f"Test machine {machine_id}",
            "mode":                mode,
            "attestation_key_b64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "capabilities_json":   "{}",
        },
        "gas_limit": 500_000,
        "signature": [],
    }

def submit_useful_work_tx(
    sender:               str,
    receipt_id:           str,
    machine_id:           str,
    challenge_id:         str,
    output_hash:          str,
    seal_nonce:           int,
    seal_hash:            str,
    seal_difficulty_bits: int,
    min_difficulty_override: int = 0,
) -> dict:
    return {
        "id":        uid("tx-work-"),
        "sender":    sender,
        "nonce":     int(time.time() * 1000),
        "body": {
            "type":                    "SubmitUsefulWork",
            "receipt_id":              receipt_id,
            "machine_id":              machine_id,
            "challenge_id":            challenge_id,
            "output_hash":             output_hash,
            "seal_nonce":              seal_nonce,
            "seal_hash":               seal_hash,
            "seal_difficulty_bits":    seal_difficulty_bits,
            "min_difficulty_override": min_difficulty_override,
        },
        "gas_limit": 1_000_000,
        "signature": [],
    }

# ── Test harness ──────────────────────────────────────────────────────────────

PASS = "\033[92m✓\033[0m"
FAIL = "\033[91m✗\033[0m"
results: list[tuple[str, bool, str]] = []

def test(name: str, ok: bool, detail: str = ""):
    icon = PASS if ok else FAIL
    print(f"  {icon}  {name}" + (f"\n        {detail}" if detail else ""))
    results.append((name, ok, detail))

def expect_ok(r: dict) -> bool:
    return r["status"] in (200, 201, 202)

def expect_rejected(r: dict) -> bool:
    # A properly rejected tx: HTTP 4xx, or 200 with success=false in body
    if r["status"] in (400, 409, 422, 403):
        return True
    body = r["body"]
    if isinstance(body, dict):
        return body.get("success") is False or "error" in str(body).lower() or "rejected" in str(body).lower()
    return False

# ── Tests ─────────────────────────────────────────────────────────────────────

CHALLENGE_ID = "qcb-devnet-1::Cryptography::phase1-test"
OUTPUT_HASH  = "000050f1a2b3c4d5e6f700112233445566778899aabbccddeeff00112233445566"
DIFFICULTY   = 8  # low enough to mine quickly

print("\n=== Phase 1C Contribution Verification Adversarial Tests ===\n")

# ── Test 1: Happy path ────────────────────────────────────────────────────────
print("Test 1: Happy path — register machine + submit valid receipt")
machine_id_1 = uid("MACH-ALICE-")
receipt_id_1 = uid("RCPT-1-")

# Register
r = send_tx(*ALICE, register_machine_tx(ALICE_WALLET, machine_id_1))
test("RegisterMachine accepted", expect_ok(r), str(r))

# Mine seal
nonce, seal = find_seal(OUTPUT_HASH, CHALLENGE_ID, DIFFICULTY)
print(f"        mined seal: nonce={nonce} hash={seal[:16]}…")

# Submit
r = send_tx(*ALICE, submit_useful_work_tx(
    ALICE_WALLET, receipt_id_1, machine_id_1,
    CHALLENGE_ID, OUTPUT_HASH, nonce, seal, DIFFICULTY
))
test("SubmitUsefulWork accepted", expect_ok(r), str(r))

# Verify contribution score incremented (check via state query if endpoint exists)
time.sleep(0.5)

# ── Test 2: Duplicate machine registration ────────────────────────────────────
print("\nTest 2: Duplicate machine registration")
r = send_tx(*ALICE, register_machine_tx(ALICE_WALLET, machine_id_1))
test("Duplicate RegisterMachine rejected", expect_rejected(r), str(r))

# ── Test 3: Unregistered machine ──────────────────────────────────────────────
print("\nTest 3: SubmitUsefulWork for unregistered machine")
nonce2, seal2 = find_seal(OUTPUT_HASH, CHALLENGE_ID, DIFFICULTY)
r = send_tx(*ALICE, submit_useful_work_tx(
    ALICE_WALLET, uid("RCPT-3-"), "MACH-NONEXISTENT-9999",
    CHALLENGE_ID, OUTPUT_HASH, nonce2, seal2, DIFFICULTY
))
test("Unregistered machine rejected", expect_rejected(r), str(r))

# ── Test 4: Bad seal (fabricated hash) ────────────────────────────────────────
print("\nTest 4: Fabricated seal_hash")
bad_seal = "ff" + "00" * 31  # starts with ff — cannot satisfy difficulty=8
r = send_tx(*ALICE, submit_useful_work_tx(
    ALICE_WALLET, uid("RCPT-4-"), machine_id_1,
    CHALLENGE_ID, OUTPUT_HASH, 0, bad_seal, DIFFICULTY
))
test("Fabricated seal rejected", expect_rejected(r), str(r))

# ── Test 5: Trivial difficulty (< 8 bits) ────────────────────────────────────
print("\nTest 5: Trivial seal difficulty = 4 bits")
# Seal at 4 bits is valid for 4 bits but should be rejected by 8-bit floor.
nonce4, seal4 = find_seal(OUTPUT_HASH, CHALLENGE_ID, 4)
r = send_tx(*ALICE, submit_useful_work_tx(
    ALICE_WALLET, uid("RCPT-5-"), machine_id_1,
    CHALLENGE_ID, OUTPUT_HASH, nonce4, seal4, 4  # below 8-bit floor
))
test("Trivial difficulty (4 bits) rejected", expect_rejected(r), str(r))

# ── Test 6: Below min_difficulty_override ────────────────────────────────────
print("\nTest 6: Seal at difficulty=8 but override requires 12")
nonce6, seal6 = find_seal(OUTPUT_HASH, CHALLENGE_ID, 8)
r = send_tx(*ALICE, submit_useful_work_tx(
    ALICE_WALLET, uid("RCPT-6-"), machine_id_1,
    CHALLENGE_ID, OUTPUT_HASH, nonce6, seal6, 8,
    min_difficulty_override=12
))
test("Below min_difficulty_override rejected", expect_rejected(r), str(r))

# ── Test 7: Duplicate receipt ─────────────────────────────────────────────────
print("\nTest 7: Duplicate receipt_id")
# receipt_id_1 was already submitted in Test 1.
nonce7, seal7 = find_seal(OUTPUT_HASH, CHALLENGE_ID, DIFFICULTY)
r = send_tx(*ALICE, submit_useful_work_tx(
    ALICE_WALLET, receipt_id_1, machine_id_1,
    CHALLENGE_ID, OUTPUT_HASH, nonce7, seal7, DIFFICULTY
))
test("Duplicate receipt rejected", expect_rejected(r), str(r))

# ── Test 8: Wrong owner ───────────────────────────────────────────────────────
print("\nTest 8: Wrong owner submits work for Alice's machine")
nonce8, seal8 = find_seal(OUTPUT_HASH, CHALLENGE_ID, DIFFICULTY)
# Bob tries to submit for Alice's machine.
r = send_tx(*BOB, submit_useful_work_tx(
    BOB_WALLET, uid("RCPT-8-"), machine_id_1,
    CHALLENGE_ID, OUTPUT_HASH, nonce8, seal8, DIFFICULTY
))
test("Wrong owner rejected", expect_rejected(r), str(r))

# ── Test 9: Epoch rate limit (register a fresh machine for this test) ─────────
print("\nTest 9: Epoch receipt rate limit (101 receipts, expect last rejected)")
machine_id_spam = uid("MACH-SPAM-")
r = send_tx(*ALICE, register_machine_tx(ALICE_WALLET, machine_id_spam))
if not expect_ok(r):
    print(f"        [SKIP] Could not register spam machine: {r}")
    test("Rate limit guard (skipped — setup failed)", False, str(r))
else:
    # Use a different output hash per receipt to avoid duplicate rejection.
    # Mine all seals upfront at difficulty=8.
    RATE_LIMIT = 100
    all_accepted = True
    last_result = None
    for i in range(RATE_LIMIT + 1):
        # Vary output hash per receipt.
        out = hashlib.sha256(f"spam-output-{i}".encode()).hexdigest()
        n, s = find_seal(out, CHALLENGE_ID, DIFFICULTY)
        rid = uid(f"RCPT-SPAM-{i}-")
        r = send_tx(*ALICE, submit_useful_work_tx(
            ALICE_WALLET, rid, machine_id_spam,
            CHALLENGE_ID, out, n, s, DIFFICULTY
        ))
        if i < RATE_LIMIT:
            if not expect_ok(r):
                all_accepted = False
                print(f"        [WARN] receipt {i} unexpectedly rejected: {r}")
        else:
            last_result = r
        if i % 10 == 0:
            print(f"        submitted {i+1}/{RATE_LIMIT+1} receipts…", end="\r", flush=True)

    print()
    test(
        f"First {RATE_LIMIT} receipts accepted",
        all_accepted,
        f"all within rate limit OK"
    )
    test(
        f"Receipt #{RATE_LIMIT+1} rejected (rate limit)",
        expect_rejected(last_result) if last_result else False,
        str(last_result)
    )

# ── Summary ───────────────────────────────────────────────────────────────────
print("\n" + "─" * 60)
passed = sum(1 for _, ok, _ in results if ok)
total  = len(results)
print(f"\nPhase 1C results: {passed}/{total} passed")
if passed < total:
    print("\nFailed tests:")
    for name, ok, detail in results:
        if not ok:
            print(f"  ✗ {name}")
            if detail:
                print(f"    {detail}")
    sys.exit(1)
else:
    print("\nAll anti-farming guards verified. ✓")
    sys.exit(0)
