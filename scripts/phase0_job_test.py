#!/usr/bin/env python3
"""
phase0_job_test.py — Phase 0 Resource Job Lifecycle End-to-End Test

Proves the full job execution loop works on the devnet:

  1.  Alice registers a machine (carol-machine-{run_id}) and claims ownership
  2.  Alice creates an escrow (LockQrcForJob)
  3.  Agent submits CreateJob  (Created state)
  4.  Alice (acting as Carol) submits AcceptJob   (Running)
  5.  Alice (acting as Carol) submits CompleteJob (Completed)
  6.  Agent self-verifies     (VerifyJob)          → Settled
  7.  Asserts job state == Settled on all devnet nodes
  8.  Asserts Carol's wallet received the payment

For Phase 0 the "requester" and "verifier" are both Alice.  Carol's machine is
registered on Alice's sender address so the ownership check passes — in Phase 1
Carol will run on her own node with her own keys.

Devnet topology:
  Machine 1  →  Alice localhost:8080   (primary submit node)
             →  Bob   localhost:8081
             →  Dave  localhost:8082

Usage:
    python3 scripts/phase0_job_test.py [--node HOST:PORT] [--verbose]
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

MACHINE_ID    = f"carol-machine-{_run_id}"
AGENT_ID      = f"agent-job-{_run_id}"
AGENT_ADDRESS = f"agent-addr-{_run_id}"
JOB_ID        = f"job-{_run_id}"
ESCROW_ID     = f"esc-job-{_run_id}"
RECEIPT_ID    = f"rcpt-job-{_run_id}"

# Amounts (all uQRC unless noted)
QCB_TO_BURN       = 10_000_000   # Alice burns QCB to get QRC
TREASURY_DEPOSIT  = 5_000_000    # deposited to agent treasury
PER_JOB_LIMIT     = 2_000_000
ESCROW_AMOUNT     = 1_000_000    # QRC locked for the job
PAYMENT_AMOUNT    = 900_000      # what Carol earns (escrow - 10% protocol fee placeholder)

PROVIDER_WALLET   = f"wallet:{MACHINE_ID}"  # the wallet Carol's earnings go to

WORKLOAD_PAYLOAD  = f"phase0-job-payload-{_run_id}"

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
def now():     return datetime.now(timezone.utc).strftime("%H:%M:%S UTC")

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


def tx_qrc_purchase(sender: str, qcb_amount: int) -> dict:
    return _tx(sender, {"QrcPurchase": {"qcb_amount": qcb_amount, "min_qrc_out": 0}}, 200_000)


def tx_register_machine(sender: str, machine_id: str) -> dict:
    return _tx(sender, {
        "RegisterMachine": {
            "machine_id":          machine_id,
            "display_name":        f"Carol Phase0 Machine [{machine_id}]",
            "mode":                "ResourceOnly",
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
            "description":     f"Phase 0 job test agent ({_run_id})",
            "parent_agent_id": None,
        }
    }, 300_000)


def tx_authorize_agent(sender: str, agent_id: str) -> dict:
    return _tx(sender, {"AuthorizeAgent": {"agent_id": agent_id}}, 150_000)


def tx_deposit_treasury(sender: str, agent_id: str, amount: int, per_job_limit: int) -> dict:
    return _tx(sender, {
        "DepositToTreasury": {
            "agent_id":           agent_id,
            "amount":             amount,
            "per_job_limit_uqrc": per_job_limit,
        }
    }, 200_000)


def tx_lock_qrc(sender: str, escrow_id: str, job_id: str,
                agent_wallet: str, amount: int) -> dict:
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
            "description":       f"Phase 0 hash workload job {job_id}",
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
        "executor": "carol-phase0-sim",
        "elapsed_seconds": 0.001,
        "phase": 0,
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
            "job_id":                job_id,
            "escrow_id":             escrow_id,
            "expected_output_hash":  expected_output_hash,
            "provider_wallet":       provider_wallet,
            "amount":                amount,
            "receipt_hash":          receipt_hash,
        }
    }, 400_000)

# ── Submit + poll for commit ───────────────────────────────────────────────

def submit(label: str, host: str, port: int, tx: dict,
           expect_ok: bool = True) -> dict:
    if VERBOSE:
        print(info(f"  submitting {label}  tx={tx['id']}  nonce={tx['nonce']}"))
    try:
        resp = post_json(host, port, "/api/tx", tx)
    except RuntimeError as e:
        check(label, not expect_ok, f"submission error: {e}")
        return {"status": "error", "error": str(e)}
    if VERBOSE:
        print(f"  → {resp}")
    return resp


def wait_committed(host: str, port: int, tx_id: str,
                   timeout_s: int = 30, interval: float = 0.4) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        data = get_json(host, port, f"/api/tx/{tx_id}")
        if isinstance(data, dict):
            if data.get("status") == "ok":
                return True
            if data.get("status") == "error":
                return False
        time.sleep(interval)
    return False


def submit_and_wait(label: str, host: str, port: int, tx: dict,
                    expect_ok: bool = True) -> bool:
    resp = submit(label, host, port, tx, expect_ok)
    if resp.get("status") != "ok":
        # The submission itself was rejected
        accepted = resp.get("status") == "ok"
        check(label, not expect_ok, f"submit rejected: {resp.get('error', resp)}")
        return not expect_ok

    committed = wait_committed(host, port, tx["id"])
    ok_result = check(
        label,
        committed == expect_ok,
        f"tx={tx['id']} committed={committed} expected={expect_ok}",
    )
    return ok_result


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
    print(hdr(f"Phase 0 Resource Job Test  [{H}:{P}]  run={_run_id}"))

    # Sync nonce
    fetch_nonce(H, P, ALICE)
    print(info(f"Alice nonce: {_nonce_counter}"))

    # ── 0. Buy QRC ─────────────────────────────────────────────────────────
    print(hdr("0. Buy QRC"))
    qrc_before = get_balance(H, P, ALICE, "uqrc")
    submit_and_wait("QrcPurchase accepted",
                    H, P, tx_qrc_purchase(ALICE, QCB_TO_BURN))
    qrc_after  = get_balance(H, P, ALICE, "uqrc")
    check("Alice has QRC after purchase", qrc_after > qrc_before,
          f"before={qrc_before} after={qrc_after}")

    # ── 1. Register Carol's machine ────────────────────────────────────────
    print(hdr("1. Register Carol's machine"))
    submit_and_wait("RegisterMachine accepted",
                    H, P, tx_register_machine(ALICE, MACHINE_ID))
    acct = get_json(H, P, f"/api/accounts/machine:{MACHINE_ID}")
    check("machine account created", isinstance(acct, dict),
          f"machine:{MACHINE_ID}")

    # ── 2. Register and authorise agent ───────────────────────────────────
    print(hdr("2. Register + authorise agent"))
    submit_and_wait("RegisterAgent accepted",
                    H, P, tx_register_agent(ALICE, AGENT_ID, AGENT_ADDRESS))
    submit_and_wait("AuthorizeAgent accepted",
                    H, P, tx_authorize_agent(ALICE, AGENT_ID))

    # ── 3. Fund agent treasury ─────────────────────────────────────────────
    print(hdr("3. Deposit to agent treasury"))
    submit_and_wait("DepositToTreasury accepted",
                    H, P, tx_deposit_treasury(ALICE, AGENT_ID,
                                               TREASURY_DEPOSIT, PER_JOB_LIMIT))
    treasury_acct = get_json(H, P, f"/api/accounts/treasury:{AGENT_ID}")
    check("treasury account funded",
          isinstance(treasury_acct, dict)
          and int(treasury_acct.get("balances", {}).get("uqrc", 0)) > 0,
          f"treasury:{AGENT_ID}")

    # ── 4. Lock QRC for job (create escrow) ────────────────────────────────
    print(hdr("4. Lock QRC for job"))
    submit_and_wait("LockQrcForJob accepted",
                    H, P, tx_lock_qrc(ALICE, ESCROW_ID, JOB_ID,
                                       AGENT_ID, ESCROW_AMOUNT))
    escrow_acct = get_json(H, P, f"/api/accounts/escrow:{ESCROW_ID}")
    locked = int((escrow_acct or {}).get("balances", {}).get("locked_uqrc", 0))
    check("escrow locked", locked == ESCROW_AMOUNT,
          f"locked={locked} expected={ESCROW_AMOUNT}")

    # ── 5. CreateJob ───────────────────────────────────────────────────────
    print(hdr("5. CreateJob"))
    submit_and_wait("CreateJob accepted",
                    H, P, tx_create_job(ALICE, JOB_ID, ESCROW_ID,
                                         MACHINE_ID, WORKLOAD_PAYLOAD))
    job = get_job(H, P, JOB_ID)
    check("job state = Created",
          job is not None and job.get("state") == "Created",
          f"state={job.get('state') if job else 'NOT FOUND'}")

    # ── 6. AcceptJob ───────────────────────────────────────────────────────
    print(hdr("6. AcceptJob (Carol accepts)"))
    submit_and_wait("AcceptJob accepted",
                    H, P, tx_accept_job(ALICE, JOB_ID, MACHINE_ID))
    job = get_job(H, P, JOB_ID)
    check("job state = Running",
          job is not None and job.get("state") == "Running",
          f"state={job.get('state') if job else 'NOT FOUND'}")

    # ── 7. Execute workload (compute output_hash) ──────────────────────────
    print(hdr("7. Execute workload"))
    output_hash = hashlib.sha256(WORKLOAD_PAYLOAD.encode()).hexdigest()
    print(info(f"  output_hash = {output_hash[:16]}…"))

    # ── 8. CompleteJob ─────────────────────────────────────────────────────
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
          f"stored={stored_hash[:16]}… expected={output_hash[:16]}…")

    # ── 9. VerifyJob (self-verify, Phase 0) ────────────────────────────────
    print(hdr("9. VerifyJob (agent self-verifies)"))
    # receipt_hash is the hash of the receipt_id for this test
    receipt_hash = hashlib.sha256(RECEIPT_ID.encode()).hexdigest()
    wallet_before = get_balance(H, P, PROVIDER_WALLET, "uqrc")
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

    # ── 10. Check payment received ─────────────────────────────────────────
    print(hdr("10. Verify Carol's wallet received payment"))
    time.sleep(1)  # let state propagate
    wallet_after = get_balance(H, P, PROVIDER_WALLET, "uqrc")
    check("provider wallet credited",
          wallet_after >= wallet_before + PAYMENT_AMOUNT,
          f"wallet={PROVIDER_WALLET}  before={wallet_before}  after={wallet_after}  payment={PAYMENT_AMOUNT}")

    # ── 11. Cross-node propagation check ───────────────────────────────────
    print(hdr("11. Cross-node state consistency"))
    time.sleep(3)  # wait for gossip
    for (name, nh, np) in ALL_NODES:
        j = get_job(nh, np, JOB_ID)
        state = j.get("state") if j else "NOT FOUND"
        check(f"{name} job state = Settled", state == "Settled",
              f"{nh}:{np}/api/jobs/{JOB_ID}  state={state}")


def main():
    global VERBOSE
    parser = argparse.ArgumentParser(description="Phase 0 Resource Job End-to-End Test")
    parser.add_argument("--node", default=f"{PRIMARY_HOST}:{PRIMARY_PORT}",
                        help="Primary node HOST:PORT (default 127.0.0.1:8080)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Print individual HTTP calls")
    args = parser.parse_args()

    VERBOSE = args.verbose

    parts = args.node.rsplit(":", 1)
    host  = parts[0] if len(parts) == 2 else PRIMARY_HOST
    port  = int(parts[1]) if len(parts) == 2 else PRIMARY_PORT

    # Quick reachability check
    status = get_json(host, port, "/api/status", timeout=5)
    if status is None:
        print(fail(f"Cannot reach node at {host}:{port}"))
        print(warn("Start the devnet first: bash scripts/start-devnet.sh"))
        sys.exit(1)
    print(ok(f"Node reachable: {host}:{port}"))

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
