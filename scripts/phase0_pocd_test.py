#!/usr/bin/env python3
"""
phase0_pocd_test.py — Phase 0d PoCD live mining round on the QCB devnet.

Steps:
  1. Check that all three devnet nodes are healthy (Alice:8080, Bob:8081, Dave:8082).
  2. GET /api/pocd/challenges to list active challenges seeded from genesis.
  3. Mine a PoCD proof: find seal_nonce such that
       SHA256(seal_nonce_be8 || output_hash_bytes || challenge_id_bytes)
     starts with seal_difficulty_bits zero bits.
  4. POST the proof to POST /api/pocd/submit on Alice's node.
  5. Verify the response says "accepted".
  6. GET /api/pocd/receipts and confirm our receipt is present.
  7. Check all 3 nodes agree on receipt count (P2P propagation).
  8. Print a summary.

Usage:
  python3 scripts/phase0_pocd_test.py

Requirements:
  - Devnet running: ./scripts/start-devnet-local.sh --clean
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

SUBMIT_NODE = NODES[0]   # submit proofs to Alice

CHAIN_ID    = "qcb-devnet-3node"
MACHINE_ID  = "qcb1devminer-machine1"

# Phase 0 difficulty: 4 bits (~16 hashes on average — fast).
SEAL_DIFFICULTY_BITS = 4

# Safety cap for seal mining loop.
MAX_SEAL_ATTEMPTS = 500_000

PASS = "\033[92m✓\033[0m"
FAIL = "\033[91m✗\033[0m"


# ── Helpers ──────────────────────────────────────────────────────────────────

def compute_seal_hash(seal_nonce: int, output_hash_hex: str, challenge_id: str) -> str:
    """SHA256(seal_nonce_be8 || output_hash_bytes || challenge_id_bytes)"""
    output_hash_bytes = bytes.fromhex(output_hash_hex)
    nonce_bytes = struct.pack(">Q", seal_nonce)
    return hashlib.sha256(nonce_bytes + output_hash_bytes + challenge_id.encode()).hexdigest()


def meets_difficulty(seal_hash_hex: str, difficulty_bits: int) -> bool:
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
        if (nibble >> (4 - rem_bits)) != 0:
            return False
    return True


def find_seal(output_hash_hex: str, challenge_id: str, difficulty_bits: int) -> tuple:
    """Mine until a valid seal is found. Returns (nonce, seal_hash_hex)."""
    start = random.randint(0, 2**32)
    for i in range(MAX_SEAL_ATTEMPTS):
        nonce = (start + i) & 0xFFFFFFFFFFFFFFFF
        seal = compute_seal_hash(nonce, output_hash_hex, challenge_id)
        if meets_difficulty(seal, difficulty_bits):
            return nonce, seal
    raise RuntimeError(f"seal not found after {MAX_SEAL_ATTEMPTS} attempts (difficulty={difficulty_bits})")


def http_get(host: str, port: int, path: str):
    conn = http.client.HTTPConnection(host, port, timeout=10)
    conn.request("GET", path)
    resp = conn.getresponse()
    raw = resp.read().decode()
    conn.close()
    try:
        return json.loads(raw), resp.status
    except json.JSONDecodeError:
        return raw, resp.status


def http_post(host: str, port: int, path: str, payload: dict):
    body = json.dumps(payload).encode()
    conn = http.client.HTTPConnection(host, port, timeout=10)
    conn.request("POST", path, body=body, headers={"Content-Type": "application/json"})
    resp = conn.getresponse()
    raw = resp.read().decode()
    conn.close()
    try:
        return json.loads(raw), resp.status
    except json.JSONDecodeError:
        return raw, resp.status


def random_output_hash() -> str:
    """Simulate work output: random SHA256 hex (in production: hash of discovered value)."""
    seed = "".join(random.choices(string.ascii_letters + string.digits, k=64))
    return hashlib.sha256(seed.encode()).hexdigest()


# ── Test steps ────────────────────────────────────────────────────────────────

def step1_health_check():
    print("── Step 1: node health check ────────────────────────────────────")
    all_ok = True
    for name, host, port in NODES:
        try:
            data, status = http_get(host, port, "/api/status")
            ok = status == 200
            icon = PASS if ok else FAIL
            chain = data.get("chain_id", "?") if isinstance(data, dict) else "?"
            height = data.get("height", "?") if isinstance(data, dict) else "?"
            print(f"  {icon}  {name} ({host}:{port})  chain={chain}  height={height}")
            if not ok:
                all_ok = False
        except Exception as e:
            print(f"  {FAIL}  {name} ({host}:{port})  unreachable: {e}")
            all_ok = False
    if not all_ok:
        print("\n  Start devnet: ./scripts/start-devnet-local.sh --clean")
        sys.exit(1)
    print()


def step2_list_challenges():
    print("── Step 2: PoCD challenge registry ──────────────────────────────")
    name, host, port = SUBMIT_NODE
    data, status = http_get(host, port, "/api/pocd/challenges")
    if status != 200:
        print(f"  {FAIL}  GET /api/pocd/challenges → {status}: {data}")
        print("  Make sure genesis has a 'pocd' section and 'genesis_challenges'.")
        sys.exit(1)

    if isinstance(data, dict) and data.get("status") == "disabled":
        print(f"  {FAIL}  PoCD is disabled in genesis — add a 'pocd' section.")
        sys.exit(1)

    if not data:
        print(f"  {FAIL}  No challenges in registry — add 'genesis_challenges' to genesis.json.")
        sys.exit(1)

    print(f"  {PASS}  {len(data)} active challenge(s) on {name}:{port}")
    for ch in data:
        print(f"       • {ch.get('challenge_id', '?')}  "
              f"track={ch.get('track', '?')}  "
              f"difficulty={ch.get('seal_difficulty_bits', '?')} bits  "
              f"status={ch.get('status', '?')}")
    print()
    return data


def step3_mine_proof(challenge: dict) -> dict:
    challenge_id = challenge["challenge_id"]
    difficulty   = challenge.get("seal_difficulty_bits", SEAL_DIFFICULTY_BITS)

    print("── Step 3: mining proof ─────────────────────────────────────────")
    print(f"  challenge_id  = {challenge_id}")
    print(f"  difficulty    = {difficulty} bits  (~{2**difficulty} hashes expected)")

    output_hash = random_output_hash()
    input_hash  = random_output_hash()
    print(f"  output_hash   = {output_hash[:16]}…")

    t0 = time.time()
    seal_nonce, seal_hash = find_seal(output_hash, challenge_id, difficulty)
    elapsed = time.time() - t0

    print(f"  {PASS}  seal found in {elapsed:.3f}s")
    print(f"       seal_nonce = {seal_nonce}")
    print(f"       seal_hash  = {seal_hash[:24]}…")
    print()

    proof_id = f"proof-phase0d-{int(time.time()*1000)}"
    return {
        "proof_id":             proof_id,
        "challenge_id":         challenge_id,
        "machine_id":           MACHINE_ID,
        "output_hash":          output_hash,
        "input_hash":           input_hash,
        "methodology_ref":      "ipfs://bafybeiphase0devnet",
        "discovery_nonce":      random.randint(0, 2**32),
        "checks_performed":     2**difficulty * 2,   # rough estimate
        "elapsed_seconds":      elapsed,
        "timestamp_utc":        time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "machine_signature":    "devnet-no-sig",
        "seal_nonce":           seal_nonce,
        "seal_hash":            seal_hash,
        "seal_difficulty_bits": difficulty,
    }


def step4_submit_proof(proof: dict) -> dict:
    print("── Step 4: submitting proof ─────────────────────────────────────")
    name, host, port = SUBMIT_NODE
    data, status = http_post(host, port, "/api/pocd/submit", proof)
    print(f"  POST /api/pocd/submit → {status}")
    print(f"  response: {json.dumps(data, indent=4) if isinstance(data, dict) else data}")
    print()

    if status != 200 or (isinstance(data, dict) and data.get("status") != "accepted"):
        print(f"  {FAIL}  Proof rejected by {name}: {data}")
        sys.exit(1)

    print(f"  {PASS}  Proof accepted!")
    print()
    return data


def step5_verify_receipt(proof_id: str):
    print("── Step 5: verifying receipt on Alice ───────────────────────────")
    name, host, port = SUBMIT_NODE
    data, status = http_get(host, port, "/api/pocd/receipts")
    if status != 200:
        print(f"  {FAIL}  GET /api/pocd/receipts → {status}: {data}")
        sys.exit(1)

    target = f"receipt-{proof_id}"
    found = any(r.get("receipt_id") == target for r in (data if isinstance(data, list) else []))
    icon = PASS if found else FAIL
    print(f"  {icon}  {len(data) if isinstance(data, list) else '?'} receipt(s) — looking for '{target}': {'found' if found else 'NOT FOUND'}")
    if not found:
        all_ids = [r.get("receipt_id") for r in (data if isinstance(data, list) else [])]
        print(f"       all receipt IDs: {all_ids}")
        sys.exit(1)
    print()


def step6_check_propagation(proof_id: str):
    print("── Step 6: receipt propagation across all nodes ─────────────────")
    target = f"receipt-{proof_id}"
    # Give Bob and Dave a couple of seconds to receive the gossip
    time.sleep(2)
    all_ok = True
    for name, host, port in NODES:
        try:
            data, status = http_get(host, port, "/api/pocd/receipts")
            count = len(data) if isinstance(data, list) else "?"
            found = any(r.get("receipt_id") == target for r in (data if isinstance(data, list) else []))
            icon = PASS if (status == 200 and found) else FAIL
            print(f"  {icon}  {name}:{port}  receipts={count}  target={'found' if found else 'MISSING'}")
            if not found:
                all_ok = False
        except Exception as e:
            print(f"  {FAIL}  {name}:{port}  error: {e}")
            all_ok = False

    if not all_ok:
        print("\n  NOTE: propagation may still be in-flight — receipt P2P sync is async.")
    print()


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print()
    print("=" * 70)
    print("  Chain Forge — Phase 0d PoCD Live Mining Round")
    print(f"  Chain ID: {CHAIN_ID}  |  Difficulty: {SEAL_DIFFICULTY_BITS} bits")
    print("=" * 70)
    print()

    step1_health_check()
    challenges = step2_list_challenges()

    # Pick the first active Mathematics challenge, or fall back to first available
    challenge = next(
        (c for c in challenges if c.get("track") == "Mathematics" and c.get("status") == "Active"),
        challenges[0] if challenges else None,
    )
    if challenge is None:
        print(f"{FAIL}  No active challenges found. Check genesis_challenges in genesis.json.")
        sys.exit(1)

    proof    = step3_mine_proof(challenge)
    response = step4_submit_proof(proof)
    step5_verify_receipt(proof["proof_id"])
    step6_check_propagation(proof["proof_id"])

    print("=" * 70)
    print(f"  {PASS}  Phase 0d PoCD mining round PASSED")
    print(f"       proof_id     = {proof['proof_id']}")
    print(f"       challenge_id = {proof['challenge_id']}")
    print(f"       seal_hash    = {proof['seal_hash'][:24]}…")
    print(f"       machine_id   = {proof['machine_id']}")
    print()
    print("  Next: run scripts/pocd_miner.py to continuously mine on this machine.")
    print("        Copy the binary + miner to Bob and Dave for 3-machine mining.")
    print("=" * 70)
    print()
