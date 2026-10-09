#!/usr/bin/env python3
"""
phase0_settlement_test.py — Phase 0c Settlement Happy-Path Test

Proves ReleaseQrcForJob and RefundQrcForJob work end-to-end across the devnet:

  Setup (shared for both paths):
    1. Alice buys QRC              (QrcPurchase)
    2. Alice registers an agent   (RegisterAgent)
    3. Alice authorises the agent  (AuthorizeAgent)
    4. Alice deposits to treasury  (DepositToTreasury, per-job cap = 1 M uQRC)

  Release path:
    5. Alice locks escrow for a job (LockQrcForJob  → escrow:release-{run})
    6. Assert: treasury debited, escrow funded, provider wallet zero
    7. Alice releases the escrow   (ReleaseQrcForJob → credits provider wallet)
    8. Assert: escrow zeroed, provider credited
    9. Repeat the release          (idempotent — balances must not change)

  Refund path (new lock on same treasury, different escrow_id):
   10. Alice locks another escrow  (LockQrcForJob  → escrow:refund-{run})
   11. Assert: treasury re-debited, refund escrow funded
   12. Alice refunds the escrow    (RefundQrcForJob → restores treasury)
   13. Assert: escrow zeroed, treasury restored
   14. Repeat the refund           (idempotent — balances must not change)

Devnet topology (as of Phase 0 genesis):
  Machine 1  →  Alice  localhost:8080
             →  Bob    localhost:8081
             →  Dave   localhost:8082
  Machine 2  →  Carol  192.168.137.3:8080

Usage:
    python3 scripts/phase0_settlement_test.py [--machine2 IP] [--skip-carol]

Options:
    --machine2   Machine 2 IP address (default: 192.168.137.3)
    --skip-carol Skip Carol reachability check (for single-machine runs)
"""

import argparse
import json
import sys
import time
import uuid
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

# ── Devnet topology ────────────────────────────────────────────────────────

MACHINE1_HOST = "127.0.0.1"
MACHINE2_HOST_DEFAULT = "192.168.137.3"

NODES_MACHINE1 = [
    ("Alice", MACHINE1_HOST, 8080),
    ("Bob",   MACHINE1_HOST, 8081),
    ("Dave",  MACHINE1_HOST, 8082),
]

# ── Test parameters ────────────────────────────────────────────────────────

ALICE_ADDRESS = "qcb1alice"

_run_id        = uuid.uuid4().hex[:8]
AGENT_ID       = f"settle-{_run_id}"
AGENT_ADDRESS  = f"agent-settle-{_run_id}"

# Treasury / escrow amounts  (uQRC)
QCB_TO_BURN      = 10_000_000
MIN_QRC_OUT      = 0
TREASURY_DEPOSIT = 5_000_000   # deposited once; both locks draw from it
PER_JOB_LIMIT    = 1_000_000
ESCROW_AMOUNT    =   800_000   # < per-job limit

# Unique IDs for the two lock legs
JOB_ID_RELEASE    = f"job-release-{_run_id}"
ESCROW_ID_RELEASE = f"release-{_run_id}"
JOB_ID_REFUND     = f"job-refund-{_run_id}"
ESCROW_ID_REFUND  = f"refund-{_run_id}"

# Provider wallet credited by ReleaseQrcForJob
PROVIDER_WALLET = "qcb1carol"

# Timing
SUBMIT_TIMEOUT_SECS  = 8
STATUS_TIMEOUT_SECS  = 5
PROPAGATION_WAIT_S   = 10
COMMIT_POLL_INTERVAL = 0.5
COMMIT_TIMEOUT_S     = 30

# ── Colour helpers ─────────────────────────────────────────────────────────

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"


def ok(msg: str)   -> str: return f"{GREEN}✓  {RESET}{msg}"
def fail(msg: str) -> str: return f"{RED}✗  {RESET}{msg}"
def warn(msg: str) -> str: return f"{YELLOW}⚠  {RESET}{msg}"
def info(msg: str) -> str: return f"{CYAN}→  {RESET}{msg}"
def hdr(msg: str)  -> str: return f"\n{BOLD}{msg}{RESET}"


def now() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S UTC")


# ── HTTP helpers ───────────────────────────────────────────────────────────

def get_json(host: str, port: int, path: str,
             timeout: int = STATUS_TIMEOUT_SECS) -> Optional[dict | list]:
    url = f"http://{host}:{port}{path}"
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        raise RuntimeError(f"HTTP {e.code} from {url}: {body}")
    except Exception as e:
        raise RuntimeError(f"GET {url} failed: {e}")


def post_json(host: str, port: int, path: str, payload: dict,
              timeout: int = SUBMIT_TIMEOUT_SECS) -> dict:
    url  = f"http://{host}:{port}{path}"
    data = json.dumps(payload).encode()
    req  = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        raise RuntimeError(f"HTTP {e.code} from {url}: {body}")
    except Exception as e:
        raise RuntimeError(f"POST {url} failed: {e}")


def node_ok(host: str, port: int) -> bool:
    try:
        get_json(host, port, "/api/status", timeout=3)
        return True
    except Exception:
        return False


# ── Nonce helpers ──────────────────────────────────────────────────────────

def get_live_nonce(host: str, port: int, address: str) -> int:
    try:
        data = get_json(host, port, f"/api/accounts/{address}")
        if isinstance(data, dict):
            return int(data.get("nonce", 0))
        return 0
    except Exception:
        return 0


_nonce_counter: int = 0


def fetch_and_set_nonce(host: str, port: int, address: str) -> int:
    global _nonce_counter
    _nonce_counter = get_live_nonce(host, port, address)
    return _nonce_counter


def _nonce() -> int:
    global _nonce_counter
    n = _nonce_counter
    _nonce_counter += 1
    return n


# ── Transaction builders ───────────────────────────────────────────────────

def tx_qrc_purchase(sender: str, qcb_amount: int, min_qrc_out: int) -> dict:
    return {
        "id":         f"settle-{_run_id}-purchase",
        "sender":     sender,
        "nonce":      _nonce(),
        "body":       {"QrcPurchase": {"qcb_amount": qcb_amount, "min_qrc_out": min_qrc_out}},
        "gas_limit":  200_000,
        "signature":  [],
        "public_key": [],
    }


def tx_register_agent(sender: str, agent_id: str, agent_address: str) -> dict:
    return {
        "id":         f"settle-{_run_id}-register",
        "sender":     sender,
        "nonce":      _nonce(),
        "body": {
            "RegisterAgent": {
                "agent_id":        agent_id,
                "agent_address":   agent_address,
                "capabilities":    ["BuyCompute"],
                "spending_limits": {
                    "epoch_limit_uqrc":    10_000_000,
                    "lifetime_limit_uqrc": 100_000_000,
                    "max_balance_uqrc":    50_000_000,
                    "per_job_limit_uqrc":  0,
                },
                "description":     f"Phase 0c settlement test agent ({_run_id})",
                "parent_agent_id": None,
            }
        },
        "gas_limit":  300_000,
        "signature":  [],
        "public_key": [],
    }


def tx_authorize_agent(sender: str, agent_id: str) -> dict:
    return {
        "id":         f"settle-{_run_id}-authorize",
        "sender":     sender,
        "nonce":      _nonce(),
        "body":       {"AuthorizeAgent": {"agent_id": agent_id}},
        "gas_limit":  150_000,
        "signature":  [],
        "public_key": [],
    }


def tx_deposit_to_treasury(sponsor: str, agent_id: str,
                            amount: int, per_job_limit: int) -> dict:
    return {
        "id":         f"settle-{_run_id}-deposit",
        "sender":     sponsor,
        "nonce":      _nonce(),
        "body": {
            "DepositToTreasury": {
                "agent_id":           agent_id,
                "amount":             amount,
                "per_job_limit_uqrc": per_job_limit,
            }
        },
        "gas_limit":  200_000,
        "signature":  [],
        "public_key": [],
    }


def tx_lock_qrc_for_job(sender: str, label: str,
                         escrow_id: str, job_id: str,
                         agent_wallet: str, amount: int) -> dict:
    return {
        "id":         f"settle-{_run_id}-{label}",
        "sender":     sender,
        "nonce":      _nonce(),
        "body": {
            "LockQrcForJob": {
                "escrow_id":    escrow_id,
                "job_id":       job_id,
                "agent_wallet": agent_wallet,
                "amount":       amount,
            }
        },
        "gas_limit":  200_000,
        "signature":  [],
        "public_key": [],
    }


def tx_release_qrc_for_job(sender: str, label: str,
                            escrow_id: str, job_id: str,
                            machine_id: str, provider_wallet: str,
                            amount: int, receipt_hash: str) -> dict:
    return {
        "id":         f"settle-{_run_id}-{label}",
        "sender":     sender,
        "nonce":      _nonce(),
        "body": {
            "ReleaseQrcForJob": {
                "escrow_id":       escrow_id,
                "job_id":          job_id,
                "machine_id":      machine_id,
                "provider_wallet": provider_wallet,
                "amount":          amount,
                "receipt_hash":    receipt_hash,
            }
        },
        "gas_limit":  200_000,
        "signature":  [],
        "public_key": [],
    }


def tx_refund_qrc_for_job(sender: str, label: str,
                           escrow_id: str, job_id: str,
                           agent_wallet: str, amount: int,
                           reason: str) -> dict:
    return {
        "id":         f"settle-{_run_id}-{label}",
        "sender":     sender,
        "nonce":      _nonce(),
        "body": {
            "RefundQrcForJob": {
                "escrow_id":    escrow_id,
                "job_id":       job_id,
                "agent_wallet": agent_wallet,
                "amount":       amount,
                "reason":       reason,
            }
        },
        "gas_limit":  200_000,
        "signature":  [],
        "public_key": [],
    }


# ── Balance helpers ─────────────────────────────────────────────────────────

def get_account_balance(host: str, port: int,
                         address: str, denom: str = "uqrc") -> Optional[int]:
    try:
        data = get_json(host, port, f"/api/accounts/{address}")
        if not isinstance(data, dict):
            return None
        balances = data.get("balances", {})
        if isinstance(balances, dict):
            return balances.get(denom, 0)
        return data.get(denom, 0)
    except Exception:
        return None


# ── Block / commit helpers ─────────────────────────────────────────────────

def find_tx_in_blocks(host: str, port: int, tx_id: str) -> bool:
    try:
        blocks = get_json(host, port, "/api/blocks")
        if not isinstance(blocks, list):
            return False
        for blk in blocks:
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


def get_tx_result(host: str, port: int, tx_id: str) -> Optional[dict]:
    try:
        data = get_json(host, port, f"/api/tx/{tx_id}")
        if isinstance(data, dict):
            return data
        return None
    except Exception:
        return None


def wait_for_commit(host: str, port: int, tx_id: str,
                    timeout: float = COMMIT_TIMEOUT_S,
                    poll: float = COMMIT_POLL_INTERVAL) -> tuple[bool, Optional[dict]]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if find_tx_in_blocks(host, port, tx_id):
            result = get_tx_result(host, port, tx_id)
            return True, result
        time.sleep(poll)
    return False, None


# ── Step helpers ───────────────────────────────────────────────────────────

def step_submit(label: str, host: str, port: int, tx: dict) -> tuple[bool, str]:
    print(f"  {info(label)} → Alice [{host}:{port}]", flush=True)
    try:
        resp   = post_json(host, port, "/api/tx", tx)
        status = resp.get("status", "unknown")
        tx_id  = resp.get("tx_id", tx.get("id", "?"))
        if status in ("queued", "ok", "accepted"):
            print(f"    {ok(f'queued  tx_id={tx_id}')}", flush=True)
            return True, status
        else:
            msg = resp.get("message", str(resp))
            print(f"    {fail(f'rejected  status={status}  msg={msg}')}", flush=True)
            return False, msg
    except Exception as e:
        print(f"    {fail(str(e))}", flush=True)
        return False, str(e)


def step_submit_and_wait(label: str, host: str, port: int,
                          tx: dict) -> tuple[bool, bool]:
    queued, _ = step_submit(label, host, port, tx)
    if not queued:
        return False, False

    tx_id = tx["id"]
    print(f"    {CYAN}waiting for commit …{RESET}", end="\r", flush=True)
    found, result = wait_for_commit(host, port, tx_id)

    if not found:
        print(f"    {fail(f'timed out after {COMMIT_TIMEOUT_S}s — tx not in any block')}", flush=True)
        return True, False

    if result is None:
        print(f"    {ok('committed')}", flush=True)
        return True, True

    success = result.get("success", True)
    if success:
        events = result.get("events", [])
        print(f"    {ok('committed  executed=ok')}  {CYAN}{events}{RESET}", flush=True)
        return True, True
    else:
        error = result.get("error") or result.get("message") or str(result)
        print(f"    {fail(f'committed but execution FAILED: {error}')}", flush=True)
        return True, False


# ── Balance assertion helper ────────────────────────────────────────────────

def assert_balances(nodes: list[tuple[str, str, int]],
                    expected: dict[str, int]) -> bool:
    """
    Assert that each account in `expected` has the given uqrc balance on
    every reachable node.  Returns True if all assertions pass.

    expected keys are bare account addresses; values are expected uqrc balances.
    """
    all_pass = True
    for name, host, port in nodes:
        bal_str = {acc: get_account_balance(host, port, acc) for acc in expected}
        row = {acc: (bal if bal is not None else "N/A") for acc, bal in bal_str.items()}
        match = all(
            bal_str[acc] == v
            for acc, v in expected.items()
            if bal_str[acc] is not None
        )
        tag  = "PASS" if match else "FAIL"
        col  = GREEN if match else RED
        print(f"{col}{tag}{RESET} {name}: balances {row}")
        if not match:
            all_pass = False
    return all_pass


# ── Main test ──────────────────────────────────────────────────────────────

def run(nodes: list[tuple[str, str, int]]) -> int:
    alice_name, alice_host, alice_port = nodes[0]

    treasury_key = f"treasury:{AGENT_ID}"
    escrow_rel   = f"escrow:{ESCROW_ID_RELEASE}"
    escrow_ref   = f"escrow:{ESCROW_ID_REFUND}"

    print(hdr("═══ Phase 0c Settlement Happy-Path Test ═══"))
    print(f"  Run ID:            {_run_id}")
    print(f"  Agent ID:          {AGENT_ID}")
    print(f"  Escrow (release):  {ESCROW_ID_RELEASE}")
    print(f"  Escrow (refund):   {ESCROW_ID_REFUND}")
    print(f"  Provider wallet:   {PROVIDER_WALLET}")
    print(f"  Treasury deposit:  {TREASURY_DEPOSIT:,} uQRC  (per-job cap: {PER_JOB_LIMIT:,})")
    print(f"  Escrow amount:     {ESCROW_AMOUNT:,} uQRC")
    print(f"  Nodes:             {', '.join(n for n,_,_ in nodes)}")

    # ─── Node reachability ───────────────────────────────────────────────────
    print(hdr("Step 0 — Node reachability"))
    for name, host, port in nodes:
        alive = node_ok(host, port)
        sym   = ok(f"{name} [{host}:{port}] online") if alive \
                else warn(f"{name} [{host}:{port}] OFFLINE")
        print(f"  {sym}")

    # ─── Fetch Alice's nonce ─────────────────────────────────────────────────
    live_nonce = fetch_and_set_nonce(alice_host, alice_port, ALICE_ADDRESS)
    print(hdr(f"Step 0b — Alice nonce = {live_nonce}"))

    # ─── Build all transactions up-front (nonces must be contiguous) ─────────
    tx_purchase  = tx_qrc_purchase(ALICE_ADDRESS, QCB_TO_BURN, MIN_QRC_OUT)
    tx_register  = tx_register_agent(ALICE_ADDRESS, AGENT_ID, AGENT_ADDRESS)
    tx_authorize = tx_authorize_agent(ALICE_ADDRESS, AGENT_ID)
    tx_deposit   = tx_deposit_to_treasury(
                     ALICE_ADDRESS, AGENT_ID, TREASURY_DEPOSIT, PER_JOB_LIMIT)
    tx_lock_rel  = tx_lock_qrc_for_job(
                     ALICE_ADDRESS, "lock-release",
                     ESCROW_ID_RELEASE, JOB_ID_RELEASE,
                     AGENT_ID, ESCROW_AMOUNT)
    tx_release   = tx_release_qrc_for_job(
                     ALICE_ADDRESS, "release",
                     ESCROW_ID_RELEASE, JOB_ID_RELEASE,
                     "machine-1", PROVIDER_WALLET, ESCROW_AMOUNT,
                     "sha256:0000000000000000000000000000000000000000000000000000000000000000")
    tx_rep_rel   = tx_release_qrc_for_job(
                     ALICE_ADDRESS, "repeat-release",
                     ESCROW_ID_RELEASE, JOB_ID_RELEASE,
                     "machine-1", PROVIDER_WALLET, ESCROW_AMOUNT,
                     "sha256:0000000000000000000000000000000000000000000000000000000000000000")
    # NOTE: tx_lock_ref, tx_refund, tx_rep_ref are built lazily after the
    # repeat-release step, because repeat-release may or may not consume a
    # nonce slot on-chain (it commits but fails execution — the chain still
    # increments the nonce).  We re-fetch the live nonce at that point so
    # the refund leg always uses the correct next nonce.

    overall_pass = True

    # ─── Setup: purchase → register → authorize → deposit ───────────────────
    print(hdr("Setup — purchase → register → authorize → deposit"))
    for label, tx in [
        ("purchase",  tx_purchase),
        ("register",  tx_register),
        ("authorize", tx_authorize),
        ("deposit",   tx_deposit),
    ]:
        q, e = step_submit_and_wait(label, alice_host, alice_port, tx)
        if not (q and e):
            print(f"\n  {fail(f'{label} failed — aborting')}")
            return 1

    # ─── Release path: lock → assert → release → assert → repeat-release ────
    print(hdr("Release path — lock-release"))
    q, e = step_submit_and_wait("lock-release", alice_host, alice_port, tx_lock_rel)
    if not (q and e):
        print(f"\n  {fail('lock-release failed — aborting release path')}")
        return 1

    print(f"\n  Checking balances after lock-release …")
    time.sleep(PROPAGATION_WAIT_S)
    after_lock_rel = {
        treasury_key: TREASURY_DEPOSIT - ESCROW_AMOUNT,   # 4_200_000
        escrow_rel:   ESCROW_AMOUNT,                       # 800_000
        PROVIDER_WALLET: 0,
    }
    if not assert_balances(nodes, after_lock_rel):
        overall_pass = False

    print(hdr("Release path — release"))
    q, e = step_submit_and_wait("release", alice_host, alice_port, tx_release)
    if not (q and e):
        print(f"\n  {fail('release failed — aborting release path')}")
        overall_pass = False
    else:
        print(f"\n  Checking balances after release …")
        time.sleep(PROPAGATION_WAIT_S)
        after_release = {
            treasury_key: TREASURY_DEPOSIT - ESCROW_AMOUNT,  # unchanged
            escrow_rel:   0,
            PROVIDER_WALLET: ESCROW_AMOUNT,                   # 800_000
        }
        if not assert_balances(nodes, after_release):
            overall_pass = False

        print(hdr("Release path — repeat-release (idempotent)"))
        q2, e2 = step_submit_and_wait("repeat-release", alice_host, alice_port, tx_rep_rel)
        # repeat-release is expected to be a no-op; the tx may commit-ok or
        # be rejected by the guard — either way balances must not change.
        time.sleep(PROPAGATION_WAIT_S)
        print(f"\n  Checking balances after repeat-release …")
        if not assert_balances(nodes, after_release):
            overall_pass = False

    # ─── Refund path: lock → assert → refund → assert → repeat-refund ───────
    # Re-fetch the live nonce now that the release path is fully settled.
    # repeat-release commits on-chain but fails execution; the chain does NOT
    # increment the sender nonce for a tx rejected at the execution layer, but
    # to be safe we always re-fetch here so the refund leg uses the exact next
    # expected nonce regardless of chain behaviour.
    fetch_and_set_nonce(alice_host, alice_port, ALICE_ADDRESS)
    tx_lock_ref = tx_lock_qrc_for_job(
                    ALICE_ADDRESS, "lock-refund",
                    ESCROW_ID_REFUND, JOB_ID_REFUND,
                    AGENT_ID, ESCROW_AMOUNT)
    tx_refund   = tx_refund_qrc_for_job(
                    ALICE_ADDRESS, "refund",
                    ESCROW_ID_REFUND, JOB_ID_REFUND,
                    AGENT_ADDRESS, ESCROW_AMOUNT,
                    "Timeout")
    tx_rep_ref  = tx_refund_qrc_for_job(
                    ALICE_ADDRESS, "repeat-refund",
                    ESCROW_ID_REFUND, JOB_ID_REFUND,
                    AGENT_ADDRESS, ESCROW_AMOUNT,
                    "Timeout")

    print(hdr("Refund path — lock-refund"))
    q, e = step_submit_and_wait("lock-refund", alice_host, alice_port, tx_lock_ref)
    if not (q and e):
        print(f"\n  {fail('lock-refund failed — aborting refund path')}")
        overall_pass = False
    else:
        print(f"\n  Checking balances after lock-refund …")
        time.sleep(PROPAGATION_WAIT_S)
        # treasury was at (TREASURY_DEPOSIT - ESCROW_AMOUNT) after release lock;
        # a second lock debits another ESCROW_AMOUNT from what remains.
        after_lock_ref = {
            treasury_key: TREASURY_DEPOSIT - 2 * ESCROW_AMOUNT,  # 3_400_000
            escrow_ref:   ESCROW_AMOUNT,                          # 800_000
            PROVIDER_WALLET: ESCROW_AMOUNT,                       # unchanged 800_000
        }
        if not assert_balances(nodes, after_lock_ref):
            overall_pass = False

        print(hdr("Refund path — refund"))
        q, e = step_submit_and_wait("refund", alice_host, alice_port, tx_refund)
        if not (q and e):
            print(f"\n  {fail('refund failed')}")
            overall_pass = False
        else:
            print(f"\n  Checking balances after refund …")
            time.sleep(PROPAGATION_WAIT_S)
            after_refund = {
                treasury_key: TREASURY_DEPOSIT - ESCROW_AMOUNT,  # restored to 4_200_000
                escrow_ref:   0,
                PROVIDER_WALLET: ESCROW_AMOUNT,                  # unchanged 800_000
            }
            if not assert_balances(nodes, after_refund):
                overall_pass = False

            print(hdr("Refund path — repeat-refund (idempotent)"))
            q2, e2 = step_submit_and_wait("repeat-refund", alice_host, alice_port, tx_rep_ref)
            time.sleep(PROPAGATION_WAIT_S)
            print(f"\n  Checking balances after repeat-refund …")
            if not assert_balances(nodes, after_refund):
                overall_pass = False

    # ─── Summary ─────────────────────────────────────────────────────────────
    tx_count  = 10   # purchase, register, authorize, deposit, lock×2, release, repeat-release, refund, repeat-refund
    node_count = len(nodes)
    if overall_pass:
        print(f"\n{GREEN}{BOLD}OVERALL PASS: {tx_count} transactions checked on {node_count} nodes{RESET}")
        return 0
    else:
        print(f"\n{RED}{BOLD}OVERALL FAIL: see FAIL lines above{RESET}")
        return 1


# ── Entry point ────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Phase 0c settlement happy-path test")
    parser.add_argument("--machine2",   default=MACHINE2_HOST_DEFAULT,
                        metavar="IP",   help="Machine 2 IP address")
    parser.add_argument("--skip-carol", action="store_true",
                        help="Skip Carol (run with Machine 1 nodes only)")
    args = parser.parse_args()

    nodes = list(NODES_MACHINE1)
    if not args.skip_carol:
        nodes.append(("Carol", args.machine2, 8080))

    sys.exit(run(nodes))


if __name__ == "__main__":
    main()
