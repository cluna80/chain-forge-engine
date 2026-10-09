#!/usr/bin/env python3
"""
phase0_negative_refund_test.py — N6/N7/N8/N9 adversarial tests for RefundQrcForJob.

Mirrors phase0_negative_release_test.py but targets the Refund path.

Setup (shared):
  1. Alice buys QRC              (QrcPurchase)
  2. Alice registers an agent    (RegisterAgent)
  3. Alice authorises the agent  (AuthorizeAgent)
  4. Alice deposits to treasury  (DepositToTreasury)

Each test verifies that RefundQrcForJob rejects when:
  N6 — escrow_id does not exist (never locked).
  N7 — sender is not the coordinator who called LockQrcForJob.
  N8 — refund amount exceeds the escrow balance.
  N9 — escrow was already released (ReleaseQrcForJob accepted, then
       RefundQrcForJob submitted for the same escrow — balance is 0,
       and no double-payment must occur).

A happy-path round (lock → refund with correct credentials) runs after
setup so we have a known-good baseline.

Usage:
  python3 scripts/phase0_negative_refund_test.py

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

LOCK_AMOUNT   = 500_000         # uQRC locked into escrow
REFUND_AMOUNT = 500_000         # valid refund (must equal lock for full refund)
OVER_AMOUNT   = LOCK_AMOUNT + 1 # N8: exceeds escrow balance

TREASURY_DEPOSIT = 5_000_000
PER_JOB_LIMIT    = 1_000_000
QRC_PURCHASE     = 10_000_000   # QCB units to swap for uQRC

COMMIT_TIMEOUT = 30.0
COMMIT_POLL    = 0.5

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


def find_tx_by_status(host: str, port: int, tx_id: str) -> bool:
    try:
        data, status = http_get(host, port, f"/api/tx/{tx_id}")
        if status != 200:
            return False
        return data.get("id") == tx_id or "success" in data or "error" in data
    except Exception:
        return False


def wait_for_commit(tx_id: str, label: str = "") -> bool:
    host, port = ALICE
    deadline = time.monotonic() + COMMIT_TIMEOUT
    last_blocks_sample = None
    while time.monotonic() < deadline:
        if find_tx_in_blocks(host, port, tx_id):
            return True
        if find_tx_by_status(host, port, tx_id):
            return True
        try:
            sample, _ = http_get(host, port, "/api/blocks")
            last_blocks_sample = sample
        except Exception:
            pass
        time.sleep(COMMIT_POLL)
    print(f"  ✗ Timeout waiting for commit: {label or tx_id}")
    if last_blocks_sample is not None:
        n = len(last_blocks_sample) if isinstance(last_blocks_sample, list) else "?"
        print(f"    /api/blocks returned {n} blocks")
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
    accepted = status == 200 and data.get("status") in ("ok", "queued")
    if not accepted:
        print(f"  ✗ Rejected: {data.get('message', data)}")
        return False
    return wait_for_commit(payload["id"], label)


def check_tx_failed_at_execution(tx_id: str) -> tuple[bool, str]:
    """Returns (was_rejected_by_execution, error_message)."""
    host, port = ALICE
    try:
        result, _ = http_get(host, port, f"/api/tx/{tx_id}")
        if result.get("success") is True:
            return False, ""
        err = result.get("error") or result.get("message") or str(result)
        return True, str(err)[:120]
    except Exception as e:
        return False, str(e)


def lock_escrow(agent_id: str, label: str) -> tuple[str, str]:
    """Lock LOCK_AMOUNT in a fresh escrow. Returns (job_id, escrow_id)."""
    job_id    = rand_id(f"job-{label}-")
    escrow_id = rand_id(f"esc-{label}-")
    lock = tx({"LockQrcForJob": {
        "escrow_id":    escrow_id,
        "job_id":       job_id,
        "agent_wallet": COORDINATOR,
        "amount":       LOCK_AMOUNT,
    }}, tx_id=rand_id(f"tx-lock-{label}-"))
    if not submit_and_wait(lock, f"LockQrcForJob [{label}]"):
        print(f"  ✗ Lock setup failed for {label}"); sys.exit(1)
    print(f"  ✓ Lock committed ({LOCK_AMOUNT} uQRC, escrow={escrow_id})")
    return job_id, escrow_id


# ── Setup ─────────────────────────────────────────────────────────────────────

def setup() -> str:
    print("\n── Setup ────────────────────────────────────────────────────────")
    agent_id = f"agent-n6789-{_run_id}"

    ok = submit_and_wait(tx(
        {"QrcPurchase": {"qcb_amount": QRC_PURCHASE, "min_qrc_out": 0}},
        sender=COORDINATOR,
        tx_id=f"n6789-{_run_id}-purchase",
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
                "epoch_limit_uqrc":    50_000_000,
                "lifetime_limit_uqrc": 500_000_000,
                "max_balance_uqrc":    200_000_000,
                "per_job_limit_uqrc":  0,
            },
            "description":     f"N6789 test agent {_run_id}",
            "parent_agent_id": None,
        }},
        tx_id=f"n6789-{_run_id}-register",
    ), "RegisterAgent")
    if not ok:
        print("  ✗ RegisterAgent failed"); sys.exit(1)
    print("  ✓ RegisterAgent committed")

    ok = submit_and_wait(tx(
        {"AuthorizeAgent": {"agent_id": agent_id}},
        tx_id=f"n6789-{_run_id}-authorize",
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
        tx_id=f"n6789-{_run_id}-deposit",
    ), "DepositToTreasury")
    if not ok:
        print("  ✗ DepositToTreasury failed"); sys.exit(1)
    print(f"  ✓ Treasury funded ({TREASURY_DEPOSIT} uQRC, per_job_limit={PER_JOB_LIMIT})")

    return agent_id


# ── Test cases ────────────────────────────────────────────────────────────────

def run_happy_path(agent_id: str) -> bool:
    """Happy path: lock → refund (full amount). Treasury must be restored."""
    print("\n── Happy path: lock + refund ─────────────────────────────────────")
    job_id, escrow_id = lock_escrow(agent_id, "happy")

    ref = tx({"RefundQrcForJob": {
        "escrow_id":    escrow_id,
        "job_id":       job_id,
        "agent_wallet": COORDINATOR,
        "amount":       REFUND_AMOUNT,
        "reason":       "Timeout",
    }}, tx_id=rand_id("tx-ref-happy-"))
    if not submit_and_wait(ref, "RefundQrcForJob"):
        print("  ✗ Refund failed"); return False
    print("  ✓ Refund committed")
    return True


def run_n6_nonexistent_escrow() -> bool:
    """N6: Refund on an escrow_id that was never locked."""
    print("\n── N6: refund on non-existent escrow ────────────────────────────")
    ghost = rand_id("esc-ghost-")
    ref = tx({"RefundQrcForJob": {
        "escrow_id":    ghost,
        "job_id":       rand_id("job-"),
        "agent_wallet": COORDINATOR,
        "amount":       REFUND_AMOUNT,
        "reason":       "Timeout",
    }}, tx_id=rand_id("tx-n6-"))
    data, status = submit(ref, "RefundQrcForJob N6")
    if data.get("status") in ("ok", "queued"):
        wait_for_commit(ref["id"])
        rejected, err = check_tx_failed_at_execution(ref["id"])
        if not rejected:
            print(f"  ✗ FAIL — ghost escrow refund was accepted")
            return False
        print(f"  ✓ Correctly rejected at execution — {err}")
        return True
    print(f"  ✓ Correctly rejected at mempool — {data.get('message','')[:80]}")
    return True


def run_n7_wrong_sender(agent_id: str) -> bool:
    """N7: Attacker tries to refund an escrow they did not lock."""
    print("\n── N7: wrong sender attempts refund ─────────────────────────────")
    job_id, escrow_id = lock_escrow(agent_id, "n7")

    # Attacker submits the refund
    ref = tx({"RefundQrcForJob": {
        "escrow_id":    escrow_id,
        "job_id":       job_id,
        "agent_wallet": ATTACKER,
        "amount":       REFUND_AMOUNT,
        "reason":       "Timeout",
    }}, sender=ATTACKER, tx_id=rand_id("tx-n7-"))
    data, status = submit(ref, "RefundQrcForJob N7")
    if data.get("status") in ("ok", "queued"):
        wait_for_commit(ref["id"])
        rejected, err = check_tx_failed_at_execution(ref["id"])
        if not rejected:
            print(f"  ✗ FAIL — attacker refund accepted")
            return False
        print(f"  ✓ Correctly rejected at execution — {err}")
        return True
    print(f"  ✓ Correctly rejected at mempool — {data.get('message','')[:80]}")
    return True


def run_n8_over_amount(agent_id: str) -> bool:
    """N8: Refund amount exceeds escrow balance."""
    print("\n── N8: refund amount exceeds escrow balance ─────────────────────")
    job_id, escrow_id = lock_escrow(agent_id, "n8")

    ref = tx({"RefundQrcForJob": {
        "escrow_id":    escrow_id,
        "job_id":       job_id,
        "agent_wallet": COORDINATOR,
        "amount":       OVER_AMOUNT,   # LOCK_AMOUNT + 1
        "reason":       "Timeout",
    }}, tx_id=rand_id("tx-n8-"))
    data, status = submit(ref, "RefundQrcForJob N8")
    if data.get("status") in ("ok", "queued"):
        wait_for_commit(ref["id"])
        rejected, err = check_tx_failed_at_execution(ref["id"])
        if not rejected:
            print(f"  ✗ FAIL — over-amount refund accepted")
            return False
        print(f"  ✓ Correctly rejected at execution — {err}")
        return True
    print(f"  ✓ Correctly rejected at mempool — {data.get('message','')[:80]}")
    return True


def run_n9_release_then_refund(agent_id: str) -> bool:
    """
    N9 (Cross-operation conflict): ReleaseQrcForJob accepted first,
    then RefundQrcForJob on the same escrow — escrow balance is 0 so
    the refund must be rejected.  This prevents double settlement.
    """
    print("\n── N9: release then refund same escrow (double-settlement guard) ─")
    job_id, escrow_id = lock_escrow(agent_id, "n9")

    # Step 1: release (should succeed)
    rel = tx({"ReleaseQrcForJob": {
        "escrow_id":       escrow_id,
        "job_id":          job_id,
        "machine_id":      PROVIDER,
        "provider_wallet": PROVIDER,
        "amount":          LOCK_AMOUNT,
        "receipt_hash":    "devnet-no-receipt",
    }}, tx_id=rand_id("tx-n9-rel-"))
    if not submit_and_wait(rel, "ReleaseQrcForJob [n9 setup]"):
        print("  ✗ Release failed — cannot run N9"); return False
    print("  ✓ Release committed (escrow balance is now 0)")

    # Step 2: refund the same escrow — must be rejected (balance = 0)
    ref = tx({"RefundQrcForJob": {
        "escrow_id":    escrow_id,
        "job_id":       job_id,
        "agent_wallet": COORDINATOR,
        "amount":       LOCK_AMOUNT,
        "reason":       "Timeout",
    }}, tx_id=rand_id("tx-n9-ref-"))
    data, status = submit(ref, "RefundQrcForJob N9")
    if data.get("status") in ("ok", "queued"):
        wait_for_commit(ref["id"])
        rejected, err = check_tx_failed_at_execution(ref["id"])
        if not rejected:
            print(f"  ✗ FAIL — double-settlement allowed: refund accepted after release")
            return False
        print(f"  ✓ Correctly rejected at execution — {err}")
        return True
    print(f"  ✓ Correctly rejected at mempool — {data.get('message','')[:80]}")
    return True


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print()
    print("═══════════════════════════════════════════════════════════════════")
    print("  Chain Forge — Phase 0 Negative Refund Tests (N6 / N7 / N8 / N9)")
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
        "Happy path (lock + refund)":               happy,
        "N6 (non-existent escrow refund)":          run_n6_nonexistent_escrow(),
        "N7 (wrong sender refund)":                 run_n7_wrong_sender(agent_id),
        "N8 (over-amount refund)":                  run_n8_over_amount(agent_id),
        "N9 (release then refund — double settle)": run_n9_release_then_refund(agent_id),
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
        print("  ✓ All tests passed — N6/N7/N8/N9 guards are enforced.")
    else:
        print("  ✗ One or more tests failed.")
        sys.exit(1)
