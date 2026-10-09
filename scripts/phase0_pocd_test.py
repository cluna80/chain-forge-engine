#!/usr/bin/env python3
"""
phase0_pocd_test.py — Phase 0d PoCD live mining round on the QCB devnet.

Steps:
  1. Check that all three devnet nodes are healthy (Alice:8080, Bob:8081, Dave:8082).
  2. POST a PoCD challenge activation to Alice's registry (devnet convenience —
     normally done via governance tx; here we inject via a utility endpoint).
     In Phase 0 there is no governance tx for challenges, so instead we exercise
     the GET /api/pocd/challenges endpoint to confirm the registry is active, then
     skip to step 3 using a pre-canned challenge known to all devnet nodes.
  3. Mine a PoCD proof: find seal_nonce such that
       SHA256(seal_nonce_be8 || output_hash_bytes || challenge_id_bytes)
     starts with seal_difficulty_bits zero bits.
  4. POST the proof to POST /api/pocd/submit on Alice's node.
  5. Verify the response says "accepted".
  6. GET /api/pocd/receipts and confirm our receipt is present.
  7. Print a summary.

Usage:
  python3 scripts/phase0_pocd_test.py

Requirements:
  - Devnet running (scripts/devnet.sh start) — Alice on :8080, Bob :8081, Dave :8082
  - Python 3.8+ (stdlib only: hashlib, struct, http.client, json, time)
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

NODES = [
    ("Alice", "127.0.0.1", 8080),
    ("Bob",   "127.0.0.1", 8081),
    ("Dave",  "127.0.0.1", 8082),
]

# Use Alice as the submission target.
SUBMIT_NODE = NODES[0]

# PoCD challenge to use for the live round.
# challenge_id format: "{chain_id}::{track}::{slug}"
# The chain_id MUST match the running devnet's chain_id.
CHAIN_ID     = "qcb-testnet-1"
CHALLENGE_ID = f"{CHAIN_ID}::Mathematics::phase0-pilot-1"
MACHINE_ID   = "qcb1devminer"

# Phase 0 difficulty: 4 bits (16× faster than mainnet's minimum 16 bits).
# Each extra 4 bits doubles expected work; 4 bits ≈ 16 hash attempts on average.
SEAL_DIFFICULTY_BITS = 4

# Safety cap: give up after this many seal attempts (should never be reached
# for difficulty=4 bits, but prevents infinite loops in CI).
MAX_SEAL_ATTEMPTS = 100_000


# ── Helpers ──────────────────────────────────────────────────────────────────

def compute_seal_hash(seal_nonce: int, output_hash_hex: str, challenge_id: str) -> str:
    """SHA256(seal_nonce_be8 || output_hash_bytes || challenge_id_bytes)"""
    output_hash_bytes = bytes.fromhex(output_hash_hex)
    nonce_bytes = struct.pack(">Q", seal_nonce)  # big-endian 8 bytes
    digest = hashlib.sha256(nonce_bytes + output_hash_bytes + challenge_id.encode()).hexdigest()
    return digest


def meets_difficulty(seal_hash_hex: str, difficulty_bits: int) -> bool:
    """True when seal_hash_hex has at least difficulty_bits leading zero bits."""
    if difficulty_bits == 0:
        return True
    full_nibbles = difficulty_bits // 4
    rem_bits = difficulty_bits % 4
    need = full_nibbles + (1 if rem_bits else 0)
    if len(seal_hash_hex) < need:
        return False
    for ch in seal_hash_hex[:full_nibbles]:
        if ch != "0":
            return False
    if rem_bits:
        nibble = int(seal_hash_hex[full_nibbles], 16)
        mask = 0xF0 >> rem_bits  # high rem_bits bits of the nibble must be 0
        if (nibble << 4) & (mask << 4) != 0:
            return False
    return True


def find_seal(output_hash_hex: str, challenge_id: str, difficulty_bits: int) -> tuple[int, str]:
    """Mine until a valid seal is found. Returns (nonce, seal_hash_hex)."""
    start = random.randint(0, 2**32)
    for i in range(MAX_SEAL_ATTEMPTS):
        nonce = (start + i) & 0xFFFFFFFFFFFFFFFF
        seal = compute_seal_hash(nonce, output_hash_hex, challenge_id)
        if meets_difficulty(seal, difficulty_bits):
            return nonce, seal
    raise RuntimeError(f"seal not found after {MAX_SEAL_ATTEMPTS} attempts (difficulty={difficulty_bits})")


def http_get(host: str, port: int, path: str) -> dict:
    """GET {path} from {host}:{port}. Returns parsed JSON."""
    conn = http.client.HTTPConnection(host, port, timeout=10)
    conn.request("GET", path)
    resp = conn.getresponse()
    body = resp.read().decode()
    conn.close()
    return json.loads(body), resp.status


def http_post(host: str, port: int, path: str, payload: dict) -> tuple[dict, int]:
    """POST JSON payload to {host}:{port}{path}. Returns (parsed_json, status_code)."""
    body = json.dumps(payload).encode()
    conn = http.client.HTTPConnection(host, port, timeout=10)
    conn.request("POST", path, body=body, headers={"Content-Type": "application/json"})
    resp = conn.getresponse()
    body = resp.read().decode()
    conn.close()
    return json.loads(body), resp.status


def random_hex(n_bytes: int = 32) -> str:
    return hashlib.sha256(
        "".join(random.choices(string.ascii_letters, k=64)).encode()
    ).hexdigest()


# ── Test steps ────────────────────────────────────────────────────────────────

def check_nodes():
    print("── Step 1: health check ──────────────────────────────────────────")
    all_ok = True
    for name, host, port in NODES:
        try:
            data, status = http_get(host, port, "/api/health")
            ok = status == 200 and data.get("status") == "ok"
            print(f"  {name} ({host}:{port})  {'✓ healthy' if ok else '✗ ' + str(data)}")
            if not ok:
                all_ok = False
        except Exception as e:
            print(f"  {name} ({host}:{port})  ✗ unreachable: {e}")
            all_ok = False
    if not all_ok:
        print("\n  Start the devnet with:  bash scripts/devnet.sh start")
        sys.exit(1)
    print()


def check_pocd_registry():
    print("── Step 2: PoCD registry ─────────────────────────────────────────")
    name, host, port = SUBMIT_NODE
    data, status = http_get(host, port, "/api/pocd/challenges")
    if status != 200:
        print(f"  ✗ GET /api/pocd/challenges returned {status}: {data}")
        sys.exit(1)

    # data is either {"status": "disabled", ...} or a list of challenges.
    if isinstance(data, dict) and data.get("status") == "disabled":
        print("  PoCD is not enabled in this devnet genesis.")
        print("  Add a 'pocd' section to your genesis.json — see docs/pocd_genesis_example.json")
        sys.exit(1)

    print(f"  PoCD registry live on {name}:{port} — {len(data)} active challenge(s)")
    for ch in data:
        print(f"    • {ch.get('challenge_id', '?')}  status={ch.get('status', '?')}")
    print()
    return data


def mine_proof(challenge_id: str) -> dict:
    print("── Step 3: mining proof ──────────────────────────────────────────")
    # Simulate work: generate a random output_hash (in prod: hash of discovered value).
    output_hash = random_hex()
    input_hash  = random_hex()
    methodology_ref = "ipfs://bafybeiphase0devnet"

    print(f"  output_hash   = {output_hash[:16]}…")
    print(f"  challenge_id  = {challenge_id}")
    print(f"  difficulty    = {SEAL_DIFFICULTY_BITS} bits")

    t0 = time.time()
    seal_nonce, seal_hash = find_seal(output_hash, challenge_id, SEAL_DIFFICULTY_BITS)
    elapsed = time.time() - t0

    print(f"  seal_nonce    = {seal_nonce}")
    print(f"  seal_hash     = {seal_hash[:16]}…")
    print(f"  mining time   = {elapsed:.3f}s")
    print()

    proof_id = f"proof-phase0-{int(time.time())}"
    return {
        "proof_id":           proof_id,
        "challenge_id":       challenge_id,
        "machine_id":         MACHINE_ID,
        "output_hash":        output_hash,
        "input_hash":         input_hash,
        "methodology_ref":    methodology_ref,
        "discovery_nonce":    random.randint(0, 2**32),
        "checks_performed":   MAX_SEAL_ATTEMPTS,
        "elapsed_seconds":    elapsed,
        "timestamp_utc":      time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "machine_signature":  "devnet-no-sig",
        "seal_nonce":         seal_nonce,
        "seal_hash":          seal_hash,
        "seal_difficulty_bits": SEAL_DIFFICULTY_BITS,
    }


def submit_proof(proof: dict) -> dict:
    print("── Step 4: submitting proof ──────────────────────────────────────")
    name, host, port = SUBMIT_NODE
    data, status = http_post(host, port, "/api/pocd/submit", proof)
    print(f"  POST /api/pocd/submit → {status}")
    print(f"  response: {json.dumps(data, indent=4)}")
    print()

    if status != 200 or data.get("status") != "accepted":
        print(f"  ✗ Proof rejected by node {name}: {data}")
        sys.exit(1)
    return data


def verify_receipt(proof_id: str):
    print("── Step 5: verifying receipt stored ─────────────────────────────")
    name, host, port = SUBMIT_NODE
    data, status = http_get(host, port, "/api/pocd/receipts")
    if status != 200:
        print(f"  ✗ GET /api/pocd/receipts returned {status}: {data}")
        sys.exit(1)

    target_receipt_id = f"receipt-{proof_id}"
    found = any(r.get("receipt_id") == target_receipt_id for r in data)
    print(f"  {len(data)} receipt(s) in registry")
    print(f"  Looking for '{target_receipt_id}': {'✓ found' if found else '✗ NOT FOUND'}")
    if not found:
        print(f"  All receipts: {[r.get('receipt_id') for r in data]}")
        sys.exit(1)
    print()


def print_summary(proof: dict, accepted_response: dict):
    print("── Summary ───────────────────────────────────────────────────────")
    print(f"  proof_id      = {proof['proof_id']}")
    print(f"  challenge_id  = {proof['challenge_id']}")
    print(f"  machine_id    = {proof['machine_id']}")
    print(f"  seal_hash     = {proof['seal_hash'][:24]}…")
    print(f"  difficulty    = {proof['seal_difficulty_bits']} bits")
    print(f"  status        = {accepted_response['status']}")
    print()
    print("  ✓ Phase 0d PoCD live mining round complete!")
    print()
    print("  Next steps:")
    print("    • Activate a real challenge via governance tx (Phase 1)")
    print("    • Wire QcbRewardPolicy into epoch processing for uQRC payouts")
    print("    • Run scripts/devnet.sh and confirm /api/pocd/* across all nodes")
    print()


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print()
    print("═══════════════════════════════════════════════════════════════════")
    print("  Chain Forge — Phase 0d PoCD Live Mining Round")
    print("═══════════════════════════════════════════════════════════════════")
    print()

    check_nodes()
    challenges = check_pocd_registry()

    # Use the first active challenge if any, else fall back to the pilot challenge.
    if challenges:
        challenge_id = challenges[0]["challenge_id"]
    else:
        challenge_id = CHALLENGE_ID
        print(f"  No active challenges; using pilot challenge: {challenge_id}")
        print()

    proof = mine_proof(challenge_id)
    response = submit_proof(proof)
    verify_receipt(proof["proof_id"])
    print_summary(proof, response)
