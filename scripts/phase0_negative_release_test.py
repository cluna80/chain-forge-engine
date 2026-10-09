#!/usr/bin/env python3
"""
phase0_negative_release_test.py — N3/N4/N5 adversarial tests for ReleaseQrcForJob.

Setup (shared):
  1. Alice buys QRC              (QrcPurchase)
  2. Alice registers an agent    (RegisterAgent)
  3. Alice authorises the agent  (AuthorizeAgent)
  4. Alice deposits to treasury  (DepositToTreasury)

Each test verifies that ReleaseQrcForJob rejects when:
  N5 — escrow_id does not exist (never locked).
  N3 — sender is not the coordinator who called LockQrcForJob.
  N4 — release amount exceeds the escrow balance.

A happy-path round (lock → release with correct credentials) runs after
setup so we have a known-good baseline.

Usage:
  python3 scripts/phase0_negative_release_test.py

Requirements:
  - Devnet running — Alice on :8080
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

COORDINATOR = "qcb1alice"   # signed the lock tx
PROVIDER    = "qcb1bob"
ATTACKER    = "qcb1carol"   # never locked the escrow

LOCK_AMOUNT    = 500_000       # uQRC locked into escrow
RELEASE_AMOUNT = 250_000       # valid release (≤ LOCK_AMOUNT)
OVER_AMOUNT    = LOCK_AMOUNT + 1  # N4: exceeds escrow balance

TREASURY_DEPOSIT  = 5_000_000
PER_JOB_LIMIT     = 1_000_000
QRC_PURCHASE      = 10_000_000   # QCB units to swap for uQRC

COMMIT_TIMEOUT  = 30.0
COMMIT_POLL     = 0.5

_nonce_counter = random.randint(1000, 9999)
_run_id = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))


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


def nonce() -> int:
    global _nonce_counter
    n = _nonce_counter
    _nonce_counter += 1
    return n


def rand_id(prefix: str = "") -> str:
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return f"{prefix}{suffix}"


# ── Block polling ─────────────────────────────────────────────────────────────

def find_tx_in_blocks(host: str, port: int, tx_id: str) -> bool:
    try:
        data, _ = http_get(host, port, "/api/blocks")
        if not isinstance(data, list):
            return False
        for blk in data:
            for tid in blk.get("tx_ids", []):
                if tid == tx_id:
                    return True
            for tx in blk.get("transactions", []):
                tid = tx if isinstance(tx, str) else tx.get("id", "")
                if tid == tx_id:
                    return True
        return False
    except Exception:
        return False


def wait_for_commit(tx_id: str, label: str = "") -> bool:
    host, port = ALICE
    deadline = time.monotonic() + COMMIT_TIMEOUT
    while time.monotonic() < deadline:
        if find_tx_in_blocks(host, port, tx_id):
            return True
        time.sleep(COMMIT_POLL)
    print(f"  ✗ Timeout waiting for commit: {label or tx_id}")
    return False


# ── Transaction builders ──────────────────────────────────────────────────────

def tx(body: dict, sender: str = COORDINATOR, tx_id: str = "") -> dict:
    return {
        "id":          tx_id or rand_id("tx-"),
        "sender":      sender,
        "nonce":       nonce(),
        "gas_limit":   300_000,
        "signature":   [],
        "public_key":  [],
        "body":        body,
    }


def submit(payload: dict, label: str = "") -> tuple[dict, int]:
    host, port = ALICE
    data, status = http_post(host, port, "/api/tx", payload)
    tag = f" [{label}]" if label else ""
    print(f"  POST /api/tx{tag} → HTTP {status}  {data.get('status','?')}")
    return data, status


def submit_and_wait(payload: dict, label: str) -> bool:
    data, status = submit(payload, label)
    if status != 200 or data.get("status") != "ok":
        print(f"  ✗ Rejected: {data.get('message', data)}")
        return False
    return wait_for_commit(payload["id"], label)


# ── Setup ─────────────────────────────────────────────────────────────────────

def setup() -> str:
    """
    Buy QRC, register+authorise an agent, deposit to treasury.
    Returns the agent_id used.
    """
    print("\n── Setup ────────────────────────────────────────────────────────")
    agent_id = f"agent-n345-{_run_id}"

    ok = submit_and_wait(tx(
        {"QrcPurchase": {"qcb_amount": QRC_PURCHASE, "min_qrc_out": 0}},
        sender=COORDINATOR,
        tx_id=f"n345-{_run_id}-purchase",
    ), "QrcPurchase")
    if not ok:
        print("  ✗ QrcPurchase failed"); sys.exit(1)
    print("  ✓ QrcPurchase committed")

    ok = submit_and_wait(tx(
        {"RegisterAgent": {
            "agent_id":        agent_id,
            "agent_address":   COORDINATOR,
            "capabilities":    ["BuyCompute"],
            "spending_limits": {
                "epoch_limit_uqrc":    10_000_000,
                "lifetime_limit_uqrc": 100_000_000,
                "max_balance_uqrc":    50_000_000,
                "per_job_limit_uqrc":  0,
            },
            "description":     f"N345 test agent {_run_id}",
            "parent_agent_id": None,
        }},
        tx_id=f"n345-{_run_id}-register",
    ), "RegisterAgent")
    if not ok:
        print("  ✗ RegisterAgent failed"); sys.exit(1)
    print("  ✓ RegisterAgent committed")

    ok = submit_and_wait(tx(
        {"AuthorizeAgent": {"agent_id": agent_id}},
        tx_id=f"n345-{_run_id}-authorize",
    ), "AuthorizeAgent")
    if not ok:
        print("  ✗ AuthorizeAgent failed"); sys.exit(1)
    print("  ✓ AuthorizeAgent committed")

    ok = submit_and_wait(tx(
        {"DepositToTreasury": {
            "agent_id":           agent_id,
            "amount":             TREASURY_DEPOSIT,
            "per_job_limit_uqrc": PER_JOB_LIMIT,
        }},
        tx_id=f"n345-{_run_id}-deposit",
    ), "DepositToTreasury")
    if not ok:
        print("  ✗ DepositToTreasury failed"); sys.exit(1)
    print(f"  ✓ Treasury funded ({TREASURY_DEPOSIT} uQRC, per_job_limit={PER_JOB_LIMIT})")

    return agent_id


# ── Test cases ────────────────────────────────────────────────────────────────

def run_happy_path(agent_id: str) -> bool:
    print("\n── Happy path: lock + release ───────────────────────────────────")
    job_id    = rand_id("job-happy-")
    escrow_id = rand_id("esc-happy-")

    lock = tx({"LockQrcForJob": {
        "escrow_id":    escrow_id,
        "job_id":       job_id,
        "agent_wallet": COORDINATOR,
        "amount":       LOCK_AMOUNT,
    }}, tx_id=rand_id("tx-lock-happy-"))
    if not submit_and_wait(lock, "LockQrcForJob"):
        print("  ✗ Lock failed"); return False
    print("  ✓ Lock committed")

    rel = tx({"ReleaseQrcForJob": {
        "escrow_id":       escrow_id,
        "job_id":          job_id,
        "machine_id":      PROVIDER,
        "provider_wallet": PROVIDER,
        "amount":          RELEASE_AMOUNT,
        "receipt_hash":    "devnet-no-receipt",
    }}, tx_id=rand_id("tx-rel-happy-"))
    if not submit_and_wait(rel, "ReleaseQrcForJob"):
        print("  ✗ Release failed"); return False
    print("  ✓ Release committed")
    return True


def run_n5_nonexistent_escrow() -> bool:
    print("\n── N5: release on non-existent escrow ───────────────────────────")
    ghost = rand_id("esc-ghost-")
    rel = tx({"ReleaseQrcForJob": {
        "escrow_id":       ghost,
        "job_id":          rand_id("job-"),
        "machine_id":      PROVIDER,
        "provider_wallet": PROVIDER,
        "amount":          RELEASE_AMOUNT,
        "receipt_hash":    "devnet-no-receipt",
    }}, tx_id=rand_id("tx-n5-"))
    data, status = submit(rel, "ReleaseQrcForJob N5")
    if data.get("status") == "ok":
        # accepted at mempool — wait and check tx result
        wait_for_commit(rel["id"])
        host, port = ALICE
        result, _ = http_get(host, port, f"/api/tx/{rel['id']}")
        if result.get("success") is True:
            print(f"  ✗ FAIL — should have been rejected: {result}")
            return False
        print(f"  ✓ Correctly rejected at execution — {result.get('error','')[:80]}")
        return True
    print(f"  ✓ Correctly rejected at mempool — {data.get('message','')[:80]}")
    return True


def run_n3_wrong_sender(agent_id: str) -> bool:
    print("\n── N3: wrong sender attempts release ────────────────────────────")
    job_id    = rand_id("job-n3-")
    escrow_id = rand_id("esc-n3-")

    lock = tx({"LockQrcForJob": {
        "escrow_id":    escrow_id,
        "job_id":       job_id,
        "agent_wallet": COORDINATOR,
        "amount":       LOCK_AMOUNT,
    }}, tx_id=rand_id("tx-lock-n3-"))
    if not submit_and_wait(lock, "LockQrcForJob"):
        print("  ✗ Lock setup failed"); return False
    print("  ✓ Lock setup committed")

    # Attacker tries to release
    rel = tx({"ReleaseQrcForJob": {
        "escrow_id":       escrow_id,
        "job_id":          job_id,
        "machine_id":      PROVIDER,
        "provider_wallet": PROVIDER,
        "amount":          RELEASE_AMOUNT,
        "receipt_hash":    "devnet-no-receipt",
    }}, sender=ATTACKER, tx_id=rand_id("tx-n3-"))
    data, status = submit(rel, "ReleaseQrcForJob N3")
    if data.get("status") == "ok":
        wait_for_commit(rel["id"])
        host, port = ALICE
        result, _ = http_get(host, port, f"/api/tx/{rel['id']}")
        if result.get("success") is True:
            print(f"  ✗ FAIL — attacker release accepted: {result}")
            return False
        print(f"  ✓ Correctly rejected at execution — {result.get('error','')[:80]}")
        return True
    print(f"  ✓ Correctly rejected at mempool — {data.get('message','')[:80]}")
    return True


def run_n4_over_amount(agent_id: str) -> bool:
    print("\n── N4: release amount exceeds escrow balance ─────────────────────")
    job_id    = rand_id("job-n4-")
    escrow_id = rand_id("esc-n4-")

    lock = tx({"LockQrcForJob": {
        "escrow_id":    escrow_id,
        "job_id":       job_id,
        "agent_wallet": COORDINATOR,
        "amount":       LOCK_AMOUNT,
    }}, tx_id=rand_id("tx-lock-n4-"))
    if not submit_and_wait(lock, "LockQrcForJob"):
        print("  ✗ Lock setup failed"); return False
    print(f"  ✓ Lock setup committed ({LOCK_AMOUNT} uQRC)")

    rel = tx({"ReleaseQrcForJob": {
        "escrow_id":       escrow_id,
        "job_id":          job_id,
        "machine_id":      PROVIDER,
        "provider_wallet": PROVIDER,
        "amount":          OVER_AMOUNT,
        "receipt_hash":    "devnet-no-receipt",
    }}, tx_id=rand_id("tx-n4-"))
    data, status = submit(rel, "ReleaseQrcForJob N4")
    if data.get("status") == "ok":
        wait_for_commit(rel["id"])
        host, port = ALICE
        result, _ = http_get(host, port, f"/api/tx/{rel['id']}")
        if result.get("success") is True:
            print(f"  ✗ FAIL — over-amount release accepted: {result}")
            return False
        print(f"  ✓ Correctly rejected at execution — {result.get('error','')[:80]}")
        return True
    print(f"  ✓ Correctly rejected at mempool — {data.get('message','')[:80]}")
    return True


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print()
    print("═══════════════════════════════════════════════════════════════════")
    print("  Chain Forge — Phase 0 Negative Release Tests (N3 / N4 / N5)")
    print("═══════════════════════════════════════════════════════════════════")

    print("\n── Step 0: health check ─────────────────────────────────────────")
    host, port = ALICE
    data, status = http_get(host, port, "/api/health")
    if status != 200 or data.get("status") != "ok":
        print(f"  ✗ Alice not healthy: {data}")
        print("  Start the devnet first.")
        sys.exit(1)
    print(f"  ✓ Alice ({host}:{port}) healthy")

    agent_id = setup()

    happy = run_happy_path(agent_id)

    results = {
        "Happy path (lock + release)":   happy,
        "N5 (non-existent escrow)":      run_n5_nonexistent_escrow(),
        "N3 (wrong sender)":             run_n3_wrong_sender(agent_id),
        "N4 (over-amount release)":      run_n4_over_amount(agent_id),
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
        print("  ✓ All tests passed — N3/N4/N5 guards are enforced.")
    else:
        print("  ✗ One or more tests failed.")
        sys.exit(1)
    print()
