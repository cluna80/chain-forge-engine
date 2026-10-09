#!/usr/bin/env python3
"""
phase0_negative_release_test.py — N3/N4/N5 adversarial tests for ReleaseQrcForJob.

Each test verifies that ReleaseQrcForJob rejects the transaction when:

  N5 — escrow_id does not exist (never locked).
  N3 — sender is not the coordinator who called LockQrcForJob.
  N4 — release amount exceeds the escrow balance.

A happy-path round (lock then release with correct credentials) runs first so
the tests have a known-good baseline to contrast against.

Usage:
  python3 scripts/phase0_negative_release_test.py

Requirements:
  - Devnet running (scripts/devnet.sh start) — Alice on :8080, Bob :8081, Dave :8082
  - Python 3.8+ (stdlib only)
"""

import http.client
import json
import sys
import time
import random
import string

# ── Config ────────────────────────────────────────────────────────────────────

ALICE = ("127.0.0.1", 8080)

# Three devnet identities.  Only COORDINATOR actually signed the lock tx.
COORDINATOR = "qcb1alice"
PROVIDER    = "qcb1bob"
ATTACKER    = "qcb1carol"   # an account that never locked the escrow

LOCK_AMOUNT    = 1_000          # uQRC locked into escrow
RELEASE_AMOUNT = 500            # valid release (≤ LOCK_AMOUNT)
OVER_AMOUNT    = LOCK_AMOUNT + 1  # N4: exceeds escrow balance


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def http_get(host: str, port: int, path: str):
    conn = http.client.HTTPConnection(host, port, timeout=10)
    conn.request("GET", path)
    resp = conn.getresponse()
    body = resp.read().decode()
    conn.close()
    return json.loads(body), resp.status


def http_post(host: str, port: int, path: str, payload: dict):
    body = json.dumps(payload).encode()
    conn = http.client.HTTPConnection(host, port, timeout=10)
    conn.request("POST", path, body=body, headers={"Content-Type": "application/json"})
    resp = conn.getresponse()
    body = resp.read().decode()
    conn.close()
    return json.loads(body), resp.status


def rand_id(prefix: str = "") -> str:
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return f"{prefix}{suffix}"


# ── Transaction builders ──────────────────────────────────────────────────────

def make_lock_tx(sender: str, job_id: str, escrow_id: str, amount: int) -> dict:
    return {
        "id":          rand_id("tx-lock-"),
        "sender":      sender,
        "nonce":       random.randint(1, 2**32),
        "gas_limit":   10_000,
        "payload": {
            "type":       "LockQrcForJob",
            "job_id":     job_id,
            "escrow_id":  escrow_id,
            "amount":     amount,
            "currency":   "uqrc",
        },
    }


def make_release_tx(sender: str, job_id: str, escrow_id: str,
                    provider: str, amount: int) -> dict:
    return {
        "id":         rand_id("tx-rel-"),
        "sender":     sender,
        "nonce":      random.randint(1, 2**32),
        "gas_limit":  10_000,
        "payload": {
            "type":       "ReleaseQrcForJob",
            "job_id":     job_id,
            "escrow_id":  escrow_id,
            "provider":   provider,
            "amount":     amount,
            "currency":   "uqrc",
        },
    }


def submit(tx: dict, label: str = "") -> tuple[dict, int]:
    host, port = ALICE
    data, status = http_post(host, port, "/api/tx", tx)
    tag = f" [{label}]" if label else ""
    print(f"  POST /api/tx{tag} → HTTP {status}")
    return data, status


# ── Health check ─────────────────────────────────────────────────────────────

def check_node():
    host, port = ALICE
    data, status = http_get(host, port, "/api/health")
    ok = status == 200 and data.get("status") == "ok"
    if not ok:
        print(f"  ✗ Alice not healthy: {data}")
        print("  Start the devnet:  bash scripts/devnet.sh start")
        sys.exit(1)
    print(f"  ✓ Alice ({host}:{port}) healthy")


# ── Test cases ────────────────────────────────────────────────────────────────

def run_happy_path():
    """
    Lock → Release with the correct coordinator.  Must succeed so we know the
    endpoint works before the adversarial tests hammer it.
    """
    print("\n── Happy path: lock + release ───────────────────────────────────")
    job_id    = rand_id("job-happy-")
    escrow_id = rand_id("esc-happy-")

    # Lock
    lock_tx = make_lock_tx(COORDINATOR, job_id, escrow_id, LOCK_AMOUNT)
    data, _ = submit(lock_tx, "LockQrcForJob")
    if data.get("status") != "ok":
        print(f"  ✗ Lock failed (expected ok): {data}")
        sys.exit(1)
    print("  ✓ Lock accepted")

    # Release
    rel_tx = make_release_tx(COORDINATOR, job_id, escrow_id,
                              PROVIDER, RELEASE_AMOUNT)
    data, _ = submit(rel_tx, "ReleaseQrcForJob")
    if data.get("status") != "ok":
        print(f"  ✗ Release failed (expected ok): {data}")
        sys.exit(1)
    print("  ✓ Release accepted")
    return escrow_id   # caller can reuse to verify balance for N4


def run_n5_nonexistent_escrow():
    """
    N5: ReleaseQrcForJob with an escrow_id that was never locked.
    Expected: rejected (status != "ok").
    """
    print("\n── N5: release on non-existent escrow ───────────────────────────")
    ghost_escrow = rand_id("esc-ghost-")
    rel_tx = make_release_tx(COORDINATOR, rand_id("job-"), ghost_escrow,
                              PROVIDER, RELEASE_AMOUNT)
    data, _ = submit(rel_tx, "ReleaseQrcForJob N5")
    if data.get("status") == "ok":
        print(f"  ✗ FAIL — should have been rejected but was accepted: {data}")
        return False
    print(f"  ✓ Correctly rejected — reason: {data.get('message', data)}")
    return True


def run_n3_wrong_sender():
    """
    N3: An attacker (not the coordinator) tries to release a legitimately
    locked escrow.
    Expected: rejected.
    """
    print("\n── N3: wrong sender attempts release ────────────────────────────")
    job_id    = rand_id("job-n3-")
    escrow_id = rand_id("esc-n3-")

    # Lock as COORDINATOR
    lock_tx = make_lock_tx(COORDINATOR, job_id, escrow_id, LOCK_AMOUNT)
    data, _ = submit(lock_tx, "LockQrcForJob")
    if data.get("status") != "ok":
        print(f"  ✗ Lock setup failed: {data}")
        return False
    print("  ✓ Lock setup OK")

    # Attempt release as ATTACKER
    rel_tx = make_release_tx(ATTACKER, job_id, escrow_id,
                              PROVIDER, RELEASE_AMOUNT)
    data, _ = submit(rel_tx, "ReleaseQrcForJob N3")
    if data.get("status") == "ok":
        print(f"  ✗ FAIL — attacker release should have been rejected: {data}")
        return False
    print(f"  ✓ Correctly rejected — reason: {data.get('message', data)}")
    return True


def run_n4_over_amount():
    """
    N4: Coordinator tries to release more than the escrow holds.
    Expected: rejected.
    """
    print("\n── N4: release amount exceeds escrow balance ─────────────────────")
    job_id    = rand_id("job-n4-")
    escrow_id = rand_id("esc-n4-")

    # Lock LOCK_AMOUNT
    lock_tx = make_lock_tx(COORDINATOR, job_id, escrow_id, LOCK_AMOUNT)
    data, _ = submit(lock_tx, "LockQrcForJob")
    if data.get("status") != "ok":
        print(f"  ✗ Lock setup failed: {data}")
        return False
    print(f"  ✓ Lock setup OK ({LOCK_AMOUNT} uqrc)")

    # Attempt to release OVER_AMOUNT (> LOCK_AMOUNT)
    rel_tx = make_release_tx(COORDINATOR, job_id, escrow_id,
                              PROVIDER, OVER_AMOUNT)
    data, _ = submit(rel_tx, "ReleaseQrcForJob N4")
    if data.get("status") == "ok":
        print(f"  ✗ FAIL — over-amount release should have been rejected: {data}")
        return False
    print(f"  ✓ Correctly rejected — reason: {data.get('message', data)}")
    return True


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print()
    print("═══════════════════════════════════════════════════════════════════")
    print("  Chain Forge — Phase 0 Negative Release Tests (N3 / N4 / N5)")
    print("═══════════════════════════════════════════════════════════════════")

    print("\n── Step 0: health check ─────────────────────────────────────────")
    check_node()

    run_happy_path()

    results = {
        "N5 (non-existent escrow)":    run_n5_nonexistent_escrow(),
        "N3 (wrong sender)":           run_n3_wrong_sender(),
        "N4 (over-amount release)":    run_n4_over_amount(),
    }

    print()
    print("── Summary ───────────────────────────────────────────────────────")
    all_pass = True
    for label, passed in results.items():
        mark = "✓" if passed else "✗ FAIL"
        print(f"  {mark}  {label}")
        if not passed:
            all_pass = False

    print()
    if all_pass:
        print("  ✓ All negative-path tests passed — N3/N4/N5 guards are enforced.")
    else:
        print("  ✗ One or more tests failed — review the ReleaseQrcForJob handler.")
        sys.exit(1)
    print()
