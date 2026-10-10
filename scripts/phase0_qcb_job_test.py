#!/usr/bin/env python3
"""
phase0_qcb_job_test.py — QCB-Native Job Lifecycle End-to-End Test (Change Set B)

Proves the complete QCB single-token job execution loop on the devnet.
No QrcPurchase step — Alice funds the agent treasury directly from her
genesis uqcb balance.

Flow:
  1.  Alice registers Carol's machine
  2.  Alice registers + authorises an agent
  3.  Alice deposits uqcb directly to the agent treasury (DepositToTreasury)
  4.  Alice locks uqcb in escrow for the job (LockQrcForJob)
  5.  Agent submits CreateJob         → Created
  6.  Carol (Alice) submits AcceptJob → Running
  7.  Carol computes output_hash, submits CompleteJob → Completed
  8.  Agent self-verifies (VerifyJob)                 → Settled
  9.  Assert Carol's provider wallet received uqcb (settled + residual per UED-001)
  10. Assert all three devnet nodes agree on final job state

UED-001 note: VerifyJob routes any escrow residual to the provider in Phase 1.
  ESCROW_AMOUNT = 1_000_000 uqcb
  PAYMENT_AMOUNT = 900_000 uqcb   (what VerifyJob declares as the settled amount)
  Provider receives: 900_000 + 100_000 residual = 1_000_000 total

Devnet topology:
  Alice  localhost:8080   (primary submit node)
  Bob    localhost:8081
  Dave   localhost:8082

Usage:
    python3 scripts/phase0_qcb_job_test.py [--node HOST:PORT] [--verbose]
"""

import argparse
import hashlib
import json
import sys
import time
import uuid
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Optional

# ── Topology ───────────────────────────────────────────────────────────────

PRIMARY_HOST = "127.0.0.1"
PRIMARY_PORT = 8080

ALL_NODES = [
    ("Alice", "127.0.0.1", 8080),
    ("Bob",   "127.0.0.1", 8081),
    ("Dave",  "127.0.0.1", 8082),
]

# ── Test parameters ────────────────────────────────────────────────────────

ALICE = "qcb1alice"   # owns everything in Phase 0

_run_id = uuid.uuid4().hex[:8]

MACHINE_ID    = f"carol-machine-qcb-{_run_id}"
AGENT_ID      = f"agent-qcb-{_run_id}"
AGENT_ADDRESS = f"agent-qcb-addr-{_run_id}"
JOB_ID        = f"job-qcb-{_run_id}"
ESCROW_ID     = f"esc-qcb-{_run_id}"
RECEIPT_ID    = f"rcpt-qcb-{_run_id}"

# All amounts in uqcb — no QrcPurchase, no uqrc involved.
TREASURY_DEPOSIT  = 5_000_000    # uqcb deposited directly to agent treasury
PER_JOB_LIMIT     = 2_000_000    # per-job spending cap (uqcb)
ESCROW_AMOUNT     = 1_000_000    # uqcb locked in escrow
PAYMENT_AMOUNT    = 900_000      # declared settled amount in VerifyJob

# UED-001: residual = ESCROW_AMOUNT - PAYMENT_AMOUNT flows to provider.
RESIDUAL_AMOUNT   = ESCROW_AMOUNT - PAYMENT_AMOUNT          # 100_000
EXPECTED_PROVIDER_TOTAL = PAYMENT_AMOUNT + RESIDUAL_AMOUNT  # 1_000_000

PROVIDER_WALLET   = f"wallet:{MACHINE_ID}"

WORKLOAD_PAYLOAD  = f"phase0-qcb-job-payload-{_run_id}"

# ── Colour helpers ─────────────────────────────────────────────────────────

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

def ok(msg):   return f"{GREEN}✓  {RESET}{msg}"
def fail(msg): return f"{RED}✗  {RESET}{msg}"
def warn(msg): return f"{YELLOW}⚠  {RESET}{msg}"
def info(msg): return f"{CYAN}→  {RESET}{msg}"
def hdr(msg):  return f"\n{BOLD}{msg}{RESET}"

# ── Exit tracking ──────────────────────────────────────────────────────────

_failures = 0

def check(label: str, cond: bool, detail: str = "") -> bool:
    global _failures
    if cond:
        print(ok(f"{label}"))
        if detail:
            print(f"   {CYAN}{detail}{RESET}")
    else:
        _failures += 1
        print(fail(f"{label}"))
        if detail:
            print(f"   {RED}{detail}{RESET}")
    return cond

# ── HTTP helpers ───────────────────────────────────────────────────────────

VERBOSE = False

def get_json(host: str, port: int, path: str, timeout: int = 5):
    url = f"http://{host}:{port}{path}"
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        if VERBOSE:
            print(warn(f"HTTP {e.code} from {url}: {body}"))
        return None
    except Exception as e:
        if VERBOSE:
            print(warn(f"GET {url} failed: {e}"))
        return None


def post_json(host: str, port: int, path: str, payload: dict, timeout: int = 8):
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
        raise RuntimeError(f"HTTP {e.code}: {body}")
    except Exception as e:
        raise RuntimeError(str(e))

# ── Nonce management ───────────────────────────────────────────────────────

_nonce_counter = 0

def fetch_nonce(host: str, port: int, address: str) -> int:
    global _nonce_counter
    data = get_json(host, port, f"/api/accounts/{address}")
    if isinstance(data, dict):
        _nonce_counter = int(data.get("nonce", 0))
    else:
        _nonce_counter = 0
    return _nonce_counter

def _nonce() -> int:
    global _nonce_counter
    n = _nonce_counter
    _nonce_counter += 1
    return n

# ── Transaction builders ───────────────────────────────────────────────────

def _tx(sender: str, body: dict, gas: int = 300_000) -> dict:
    return {
        "id":         f"tx-{uuid.uuid4().hex[:12]}",
        "sender":     sender,
        "nonce":      _nonce(),
        "body":       body,
        "gas_limit":  gas,
        "signature":  [],
        "public_key": [],
    }


def tx_register_machine(sender: str, machine_id: str) -> dict:
    return _tx(sender, {
        "RegisterMachine": {
            "machine_id":          machine_id,
            "display_name":        f"Carol QCB Machine [{machine_id}]",
            "mode":                "ContributionOnly",
            "attestation_key_b64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "capabilities_json":   '{"workloads":["hash","sim"]}',
        }
    }, 400_000)


def tx_register_agent(sender: str, agent_id: str, agent_address: str) -> dict:
    return _tx(sender, {
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
            "description":     f"QCB-native job test agent ({_run_id})",
            "parent_agent_id": None,
        }
    }, 300_000)


def tx_authorize_agent(sender: str, agent_id: str) -> dict:
    return _tx(sender, {"AuthorizeAgent": {"agent_id": agent_id}}, 150_000)


def tx_deposit_treasury(sender: str, agent_id: str,
                        amount: int, per_job_limit: int) -> dict:
    """Fund the agent treasury directly in uqcb — no QrcPurchase required."""
    return _tx(sender, {
        "DepositToTreasury": {
            "agent_id":           agent_id,
            "amount":             amount,
            "per_job_limit_uqrc": per_job_limit,
        }
    }, 200_000)


def tx_lock_qrc(sender: str, escrow_id: str, job_id: str,
                agent_wallet: str, amount: int) -> dict:
    """Lock uqcb in escrow for a job (handler now uses uqcb after Change Set A)."""
    return _tx(sender, {
        "LockQrcForJob": {
            "escrow_id":    escrow_id,
            "job_id":       job_id,
            "agent_wallet": agent_wallet,
            "amount":       amount,
        }
    }, 250_000)


def tx_create_job(sender: str, job_id: str, escrow_id: str,
                  machine_id: str, payload: str) -> dict:
    return _tx(sender, {
        "CreateJob": {
            "job_id":            job_id,
            "escrow_id":         escrow_id,
            "machine_id":        machine_id,
            "description":       f"QCB-native hash workload job {job_id}",
            "workload_type":     "hash",
            "workload_payload":  payload,
            "timeout_seconds":   300,
        }
    }, 350_000)


def tx_accept_job(sender: str, job_id: str, machine_id: str) -> dict:
    return _tx(sender, {
        "AcceptJob": {
            "job_id":     job_id,
            "machine_id": machine_id,
        }
    }, 200_000)


def tx_complete_job(sender: str, job_id: str, machine_id: str,
                    output_hash: str, receipt_id: str) -> dict:
    stats = json.dumps({
        "executor":        "carol-qcb-sim",
        "elapsed_seconds": 0.001,
        "phase":           0,
        "denom":           "uqcb",
    })
    return _tx(sender, {
        "CompleteJob": {
            "job_id":               job_id,
            "machine_id":           machine_id,
            "output_hash":          output_hash,
            "receipt_id":           receipt_id,
            "execution_stats_json": stats,
        }
    }, 250_000)


def tx_verify_job(sender: str, job_id: str, escrow_id: str,
                  expected_output_hash: str, provider_wallet: str,
                  amount: int, receipt_hash: str) -> dict:
    return _tx(sender, {
        "VerifyJob": {
            "job_id":               job_id,
            "escrow_id":            escrow_id,
            "expected_output_hash": expected_output_hash,
            "provider_wallet":      provider_wallet,
            "amount":               amount,
            "receipt_hash":         receipt_hash,
        }
    }, 400_000)

# ── Submit helpers ─────────────────────────────────────────────────────────

def submit_and_wait(label: str, host: str, port: int, tx: dict,
                    expect_ok: bool = True) -> bool:
    if VERBOSE:
        print(info(f"  submitting {label}  tx={tx['id']}  nonce={tx['nonce']}"))
    try:
        resp = post_json(host, port, "/api/tx", tx)
    except RuntimeError as e:
        check(label, not expect_ok, f"submission error: {e}")
        fetch_nonce(host, port, tx["sender"])
        return not expect_ok

    if VERBOSE:
        print(f"  → {resp}")

    status = resp.get("status", "")
    if status not in ("ok", "queued"):
        check(label, not expect_ok, f"submit rejected: {resp.get('error', resp)}")
        fetch_nonce(host, port, tx["sender"])
        return not expect_ok

    committed = _wait_committed(host, port, tx["id"])
    if not committed:
        fetch_nonce(host, port, tx["sender"])
    return check(
        label,
        committed == expect_ok,
        f"tx={tx['id']} committed={committed} expected={expect_ok}",
    )


def _wait_committed(host: str, port: int, tx_id: str,
                    timeout_s: int = 30, interval: float = 0.4) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        data = get_json(host, port, f"/api/tx/{tx_id}")
        if isinstance(data, dict) and "success" in data:
            if data.get("success"):
                return True
            err = data.get("error") or "(no error detail)"
            print(warn(f"  tx {tx_id} failed on-chain: {err}"))
            return False
        time.sleep(interval)
    print(warn(f"  tx {tx_id} timed out after {timeout_s}s"))
    return False


def get_job(host: str, port: int, job_id: str) -> Optional[dict]:
    data = get_json(host, port, f"/api/jobs/{job_id}")
    if isinstance(data, dict) and data.get("job_id"):
        return data
    return None


def get_balance(host: str, port: int, address: str, denom: str) -> int:
    data = get_json(host, port, f"/api/accounts/{address}")
    if isinstance(data, dict):
        return int(data.get("balances", {}).get(denom, 0))
    return 0

# ── Test suite ─────────────────────────────────────────────────────────────

def run_test(host: str, port: int) -> None:
    H, P = host, port
    print(hdr(f"QCB-Native Job Lifecycle Test  [{H}:{P}]  run={_run_id}"))
    print(info(f"Denom: uqcb (no QrcPurchase step)"))
    print(info(f"Escrow: {ESCROW_AMOUNT:,} uqcb  |  Payment: {PAYMENT_AMOUNT:,}  |  "
               f"Residual→provider: {RESIDUAL_AMOUNT:,}  (UED-001)"))

    # Sync nonce from chain
    fetch_nonce(H, P, ALICE)
    print(info(f"Alice on-chain nonce: {_nonce_counter}"))

    # Check Alice's starting uqcb balance
    alice_qcb_start = get_balance(H, P, ALICE, "uqcb")
    check("Alice has genesis uqcb", alice_qcb_start > 0,
          f"Alice uqcb={alice_qcb_start:,}")

    # ── 1. Register Carol's machine ────────────────────────────────────────
    print(hdr("1. Register Carol's machine"))
    submit_and_wait("RegisterMachine accepted",
                    H, P, tx_register_machine(ALICE, MACHINE_ID))
    acct = get_json(H, P, f"/api/accounts/machine:{MACHINE_ID}")
    check("machine account created", isinstance(acct, dict),
          f"machine:{MACHINE_ID}")

    # ── 2. Register + authorise agent ─────────────────────────────────────
    print(hdr("2. Register + authorise agent"))
    submit_and_wait("RegisterAgent accepted",
                    H, P, tx_register_agent(ALICE, AGENT_ID, AGENT_ADDRESS))
    submit_and_wait("AuthorizeAgent accepted",
                    H, P, tx_authorize_agent(ALICE, AGENT_ID))

    # ── 3. Fund agent treasury directly in uqcb ───────────────────────────
    print(hdr("3. Deposit uqcb to agent treasury  [no QrcPurchase]"))
    alice_before_deposit = get_balance(H, P, ALICE, "uqcb")
    submit_and_wait("DepositToTreasury accepted",
                    H, P, tx_deposit_treasury(ALICE, AGENT_ID,
                                               TREASURY_DEPOSIT, PER_JOB_LIMIT))

    # Verify treasury holds uqcb
    treasury_acct = get_json(H, P, f"/api/accounts/treasury:{AGENT_ID}")
    treasury_qcb = int((treasury_acct or {}).get("balances", {}).get("uqcb", 0))
    check("treasury funded in uqcb",
          treasury_qcb >= TREASURY_DEPOSIT,
          f"treasury:{AGENT_ID}  uqcb={treasury_qcb:,}  expected≥{TREASURY_DEPOSIT:,}")

    alice_after_deposit = get_balance(H, P, ALICE, "uqcb")
    check("Alice uqcb debited by deposit",
          alice_after_deposit <= alice_before_deposit - TREASURY_DEPOSIT,
          f"before={alice_before_deposit:,}  after={alice_after_deposit:,}  "
          f"deposit={TREASURY_DEPOSIT:,}")

    # ── 4. Lock uqcb in escrow ────────────────────────────────────────────
    print(hdr("4. Lock uqcb in escrow (LockQrcForJob)"))
    submit_and_wait("LockQrcForJob accepted",
                    H, P, tx_lock_qrc(ALICE, ESCROW_ID, JOB_ID,
                                       AGENT_ID, ESCROW_AMOUNT))

    escrow_acct = get_json(H, P, f"/api/accounts/escrow:{ESCROW_ID}")
    locked_qcb  = int((escrow_acct or {}).get("balances", {}).get("locked_uqcb", 0))
    escrow_qcb  = int((escrow_acct or {}).get("balances", {}).get("uqcb",        0))
    check("escrow locked_uqcb correct",
          locked_qcb == ESCROW_AMOUNT,
          f"locked_uqcb={locked_qcb:,}  expected={ESCROW_AMOUNT:,}")
    check("escrow uqcb balance correct",
          escrow_qcb == ESCROW_AMOUNT,
          f"uqcb={escrow_qcb:,}  expected={ESCROW_AMOUNT:,}")

    # No uqrc should appear anywhere in this flow
    check("escrow has no legacy uqrc",
          int((escrow_acct or {}).get("balances", {}).get("uqrc", 0)) == 0,
          "uqrc=0 (single-token invariant)")

    # ── 5. CreateJob ──────────────────────────────────────────────────────
    print(hdr("5. CreateJob"))
    submit_and_wait("CreateJob accepted",
                    H, P, tx_create_job(ALICE, JOB_ID, ESCROW_ID,
                                         MACHINE_ID, WORKLOAD_PAYLOAD))
    job = get_job(H, P, JOB_ID)
    check("job state = Created",
          job is not None and job.get("state") == "Created",
          f"state={job.get('state') if job else 'NOT FOUND'}")

    # ── 6. AcceptJob ──────────────────────────────────────────────────────
    print(hdr("6. AcceptJob (Carol accepts)"))
    submit_and_wait("AcceptJob accepted",
                    H, P, tx_accept_job(ALICE, JOB_ID, MACHINE_ID))
    job = get_job(H, P, JOB_ID)
    check("job state = Running",
          job is not None and job.get("state") == "Running",
          f"state={job.get('state') if job else 'NOT FOUND'}")

    # ── 7. Execute workload ───────────────────────────────────────────────
    print(hdr("7. Execute workload (compute output_hash)"))
    output_hash = hashlib.sha256(WORKLOAD_PAYLOAD.encode()).hexdigest()
    print(info(f"  output_hash = {output_hash[:16]}…"))

    # ── 8. CompleteJob ────────────────────────────────────────────────────
    print(hdr("8. CompleteJob (Carol submits result)"))
    submit_and_wait("CompleteJob accepted",
                    H, P, tx_complete_job(ALICE, JOB_ID, MACHINE_ID,
                                           output_hash, RECEIPT_ID))
    job = get_job(H, P, JOB_ID)
    check("job state = Completed",
          job is not None and job.get("state") == "Completed",
          f"state={job.get('state') if job else 'NOT FOUND'}")
    stored_hash = job.get("output_hash", "") if job else ""
    check("output_hash stored correctly",
          stored_hash == output_hash,
          f"stored={stored_hash[:16]}…  expected={output_hash[:16]}…")

    # ── 9. VerifyJob (Phase 0 self-verify) ───────────────────────────────
    print(hdr("9. VerifyJob (agent self-verifies)"))
    receipt_hash = hashlib.sha256(RECEIPT_ID.encode()).hexdigest()
    wallet_before = get_balance(H, P, PROVIDER_WALLET, "uqcb")

    submit_and_wait("VerifyJob accepted",
                    H, P, tx_verify_job(
                        ALICE, JOB_ID, ESCROW_ID,
                        output_hash, PROVIDER_WALLET,
                        PAYMENT_AMOUNT, receipt_hash,
                    ))

    job = get_job(H, P, JOB_ID)
    check("job state = Settled",
          job is not None and job.get("state") == "Settled",
          f"state={job.get('state') if job else 'NOT FOUND'}")

    # ── 10. Economic conservation checks ─────────────────────────────────
    print(hdr("10. Economic conservation — uqcb single-token invariants"))
    time.sleep(1)  # let state propagate

    wallet_after = get_balance(H, P, PROVIDER_WALLET, "uqcb")
    gained = wallet_after - wallet_before

    check("provider wallet credited in uqcb",
          wallet_after >= wallet_before + PAYMENT_AMOUNT,
          f"wallet={PROVIDER_WALLET}  before={wallet_before:,}  after={wallet_after:,}")

    check(f"provider received settled + residual = {EXPECTED_PROVIDER_TOTAL:,} uqcb  (UED-001)",
          gained == EXPECTED_PROVIDER_TOTAL,
          f"gained={gained:,}  expected={EXPECTED_PROVIDER_TOTAL:,}  "
          f"(settled={PAYMENT_AMOUNT:,} + residual={RESIDUAL_AMOUNT:,})")

    # Escrow should be drained
    escrow_final = get_json(H, P, f"/api/accounts/escrow:{ESCROW_ID}")
    escrow_qcb_final = int((escrow_final or {}).get("balances", {}).get("uqcb", 0))
    check("escrow fully drained after settlement",
          escrow_qcb_final == 0,
          f"escrow uqcb={escrow_qcb_final:,}  expected=0")

    # Treasury should be reduced by escrow amount
    treasury_final = get_json(H, P, f"/api/accounts/treasury:{AGENT_ID}")
    treasury_qcb_final = int((treasury_final or {}).get("balances", {}).get("uqcb", 0))
    expected_treasury = TREASURY_DEPOSIT - ESCROW_AMOUNT
    check("treasury reduced by escrow amount",
          treasury_qcb_final == expected_treasury,
          f"treasury uqcb={treasury_qcb_final:,}  "
          f"expected={expected_treasury:,}  (deposit={TREASURY_DEPOSIT:,} - escrow={ESCROW_AMOUNT:,})")

    # No uqrc should have appeared anywhere
    provider_uqrc = get_balance(H, P, PROVIDER_WALLET, "uqrc")
    check("provider wallet has no legacy uqrc",
          provider_uqrc == 0,
          f"uqrc={provider_uqrc}  (single-token invariant)")

    # ── 11. Cross-node state consistency ─────────────────────────────────
    print(hdr("11. Cross-node propagation — all 3 nodes agree"))
    time.sleep(3)  # allow gossip to settle
    for (name, nh, np) in ALL_NODES:
        j     = get_job(nh, np, JOB_ID)
        state = j.get("state") if j else "NOT FOUND"
        check(f"{name} job state = Settled",
              state == "Settled",
              f"{nh}:{np}/api/jobs/{JOB_ID}  state={state}")

        bal = get_balance(nh, np, PROVIDER_WALLET, "uqcb")
        check(f"{name} sees provider uqcb = {EXPECTED_PROVIDER_TOTAL:,}",
              bal == EXPECTED_PROVIDER_TOTAL,
              f"{nh}:{np}/api/accounts/{PROVIDER_WALLET}  uqcb={bal:,}")


# ── Entry point ────────────────────────────────────────────────────────────

def main():
    global VERBOSE
    parser = argparse.ArgumentParser(
        description="QCB-Native Job Lifecycle End-to-End Test (Change Set B)"
    )
    parser.add_argument("--node", default=f"{PRIMARY_HOST}:{PRIMARY_PORT}",
                        help="Primary node HOST:PORT (default 127.0.0.1:8080)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Print individual HTTP calls and responses")
    args = parser.parse_args()
    VERBOSE = args.verbose

    parts = args.node.rsplit(":", 1)
    host  = parts[0] if len(parts) == 2 else PRIMARY_HOST
    port  = int(parts[1]) if len(parts) == 2 else PRIMARY_PORT

    status = get_json(host, port, "/api/status", timeout=5)
    if status is None:
        print(fail(f"Cannot reach node at {host}:{port}"))
        print(warn("Start the devnet: bash scripts/start-devnet.sh"))
        sys.exit(1)
    print(ok(f"Node reachable: {host}:{port}"))

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    print(info(f"Started: {ts}  run_id={_run_id}"))

    run_test(host, port)

    print()
    print("─" * 60)
    if _failures == 0:
        print(f"{GREEN}{BOLD}ALL CHECKS PASSED{RESET}  run={_run_id}")
        sys.exit(0)
    else:
        print(f"{RED}{BOLD}{_failures} CHECK(S) FAILED{RESET}  run={_run_id}")
        sys.exit(1)


if __name__ == "__main__":
    main()
