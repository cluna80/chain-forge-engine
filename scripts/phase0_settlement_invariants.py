#!/usr/bin/env python3
"""
phase0_settlement_invariants.py — QCB Economic Integrity & Settlement Security Suite

Verifies that the resource-job settlement layer is financially consistent and
resistant to replay/double-settlement attacks.  Designed to be reusable across
any Chain Forge blockchain that implements the QRC resource-job module.

Settlement Invariants tested
─────────────────────────────
  SI-001  QRC conservation      No unexplained creation or disappearance of QRC
  SI-002  Restart persistence   Settled job and balances survive a node restart
  SI-003  Duplicate settlement  Second settlement attempt cannot release additional funds
  SI-004  Cross-node agreement  All nodes agree on balances and job state at the same height
  SI-005  Protocol fee acctg.   Residual escrow (fee placeholder) is explicitly accounted for

Prerequisites
─────────────
  • Three-node devnet must already be running (Alice :8080, Bob :8081, Dave :8082).
  • The script will run a *complete* resource-job lifecycle internally (same tx
    sequence as phase0_job_test.py) so it has a freshly-settled job to inspect.
  • For SI-002 the script restarts Alice's node.  It needs the path to the
    chain-forge-node binary and Alice's log/data directories.  Pass these via
    --node-bin, --alice-data, --alice-log, or set the environment variables
    CFE_NODE_BIN, CFE_ALICE_DATA, CFE_ALICE_LOG.

Usage
─────
    python scripts/phase0_settlement_invariants.py [options]

    --node        HOST:PORT   Primary node (default 127.0.0.1:8080)
    --node-bin    PATH        chain-forge-node binary
    --alice-data  PATH        Alice's data directory (for restart)
    --alice-log   PATH        Alice's log file (for restart)
    --genesis     PATH        Genesis JSON (for restart)
    --skip-restart            Skip SI-002 (useful in CI without process control)
    --verbose                 Print individual HTTP calls

Architecture note — QCB-ECON-001 (future milestone)
─────────────────────────────────────────────────────
  Settlement currently distributes:
    900,000 uQRC → resource provider wallet
    100,000 uQRC → remains in escrow (protocol fee placeholder, not yet routed)

  Until QCB-ECON-001 (Deterministic Protocol Fee Routing) is implemented,
  SI-005 asserts the residual is accounted for but does NOT assert it reaches
  a treasury.  Once fee routing lands, update EXPECTED_FEE_DESTINATION below
  and remove the skip condition in _si005.
"""

import argparse
import hashlib
import json
import os
import platform
import signal
import subprocess
import sys
import time
import uuid
import urllib.request
import urllib.error
from typing import Optional, Tuple

# ── Topology ──────────────────────────────────────────────────────────────────

PRIMARY_HOST = "127.0.0.1"
PRIMARY_PORT = 8080

ALL_NODES: list[Tuple[str, str, int]] = [
    ("Alice", "127.0.0.1", 8080),
    ("Bob",   "127.0.0.1", 8081),
    ("Dave",  "127.0.0.1", 8082),
]

# ── Amounts ───────────────────────────────────────────────────────────────────

ALICE            = "qcb1alice"
QCB_TO_BURN      = 10_000_000
TREASURY_DEPOSIT = 5_000_000
PER_JOB_LIMIT    = 2_000_000
ESCROW_AMOUNT    = 1_000_000   # total locked
PAYMENT_AMOUNT   = 900_000     # provider receives
FEE_RESIDUAL     = ESCROW_AMOUNT - PAYMENT_AMOUNT   # 100,000 — currently stranded

# Future: set this to e.g. "treasury:protocol" once QCB-ECON-001 is implemented.
EXPECTED_FEE_DESTINATION: Optional[str] = None   # None = not yet routed

# ── Colour helpers ────────────────────────────────────────────────────────────

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

# ── Result tracking ───────────────────────────────────────────────────────────

_failures = 0

def check(label: str, cond: bool, detail: str = "") -> bool:
    global _failures
    if cond:
        print(ok(label))
        if detail:
            print(f"   {CYAN}{detail}{RESET}")
    else:
        _failures += 1
        print(fail(label))
        if detail:
            print(f"   {RED}{detail}{RESET}")
    return cond


def abort(msg: str) -> None:
    """Hard-fail immediately — used when a violated invariant makes further
    testing meaningless (e.g. settlement itself failed)."""
    global _failures
    _failures += 1
    print(f"\n{RED}{BOLD}ABORT:{RESET} {RED}{msg}{RESET}")
    _print_summary()
    sys.exit(1)

# ── HTTP helpers ──────────────────────────────────────────────────────────────

VERBOSE = False


def get_json(host: str, port: int, path: str, timeout: int = 5) -> Optional[dict]:
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


def post_json(host: str, port: int, path: str, payload: dict,
              timeout: int = 8) -> dict:
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

# ── Nonce management ──────────────────────────────────────────────────────────

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

# ── Transaction builders ──────────────────────────────────────────────────────

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


def _tx_qrc_purchase(sender: str) -> dict:
    return _tx(sender, {"QrcPurchase": {"qcb_amount": QCB_TO_BURN, "min_qrc_out": 0}}, 200_000)

def _tx_register_machine(sender: str, machine_id: str) -> dict:
    return _tx(sender, {
        "RegisterMachine": {
            "machine_id":          machine_id,
            "display_name":        f"SI Machine [{machine_id}]",
            "mode":                "ContributionOnly",
            "attestation_key_b64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "capabilities_json":   '{"workloads":["hash"]}',
        }
    }, 400_000)

def _tx_register_agent(sender: str, agent_id: str, agent_address: str) -> dict:
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
            "description":     f"SI test agent",
            "parent_agent_id": None,
        }
    }, 300_000)

def _tx_authorize_agent(sender: str, agent_id: str) -> dict:
    return _tx(sender, {"AuthorizeAgent": {"agent_id": agent_id}}, 150_000)

def _tx_deposit_treasury(sender: str, agent_id: str) -> dict:
    return _tx(sender, {
        "DepositToTreasury": {
            "agent_id":           agent_id,
            "amount":             TREASURY_DEPOSIT,
            "per_job_limit_uqrc": PER_JOB_LIMIT,
        }
    }, 200_000)

def _tx_lock_qrc(sender: str, escrow_id: str, job_id: str, agent_id: str) -> dict:
    return _tx(sender, {
        "LockQrcForJob": {
            "escrow_id":    escrow_id,
            "job_id":       job_id,
            "agent_wallet": agent_id,
            "amount":       ESCROW_AMOUNT,
        }
    }, 250_000)

def _tx_create_job(sender: str, job_id: str, escrow_id: str,
                   machine_id: str, payload: str) -> dict:
    return _tx(sender, {
        "CreateJob": {
            "job_id":           job_id,
            "escrow_id":        escrow_id,
            "machine_id":       machine_id,
            "description":      f"SI invariant job {job_id}",
            "workload_type":    "hash",
            "workload_payload": payload,
            "timeout_seconds":  300,
        }
    }, 350_000)

def _tx_accept_job(sender: str, job_id: str, machine_id: str) -> dict:
    return _tx(sender, {"AcceptJob": {"job_id": job_id, "machine_id": machine_id}}, 200_000)

def _tx_complete_job(sender: str, job_id: str, machine_id: str,
                     output_hash: str, receipt_id: str) -> dict:
    stats = json.dumps({"executor": "si-sim", "elapsed_seconds": 0.001, "phase": 0})
    return _tx(sender, {
        "CompleteJob": {
            "job_id":               job_id,
            "machine_id":           machine_id,
            "output_hash":          output_hash,
            "receipt_id":           receipt_id,
            "execution_stats_json": stats,
        }
    }, 250_000)

def _tx_verify_job(sender: str, job_id: str, escrow_id: str,
                   output_hash: str, provider_wallet: str,
                   receipt_hash: str, amount: int = PAYMENT_AMOUNT) -> dict:
    return _tx(sender, {
        "VerifyJob": {
            "job_id":               job_id,
            "escrow_id":            escrow_id,
            "expected_output_hash": output_hash,
            "provider_wallet":      provider_wallet,
            "amount":               amount,
            "receipt_hash":         receipt_hash,
        }
    }, 400_000)

# ── Submit + poll ─────────────────────────────────────────────────────────────

def _submit(host: str, port: int, tx: dict, expect_ok: bool = True) -> Tuple[bool, bool]:
    """
    Submit a transaction and wait for commitment.

    Returns (submitted_ok, committed_ok).
    Re-syncs nonce from chain on any failure so subsequent txs don't cascade.
    """
    label = next(iter(tx["body"]))  # tx type name for logging
    if VERBOSE:
        print(info(f"  submitting {label}  tx={tx['id']}  nonce={tx['nonce']}"))
    try:
        resp = post_json(host, port, "/api/tx", tx)
    except RuntimeError as e:
        if VERBOSE:
            print(warn(f"  submit error: {e}"))
        fetch_nonce(host, port, tx["sender"])
        return False, False

    status = resp.get("status", "")
    if VERBOSE:
        print(f"  → {resp}")
    if status not in ("ok", "queued"):
        if VERBOSE:
            print(warn(f"  submit rejected: {resp.get('error', resp)}"))
        fetch_nonce(host, port, tx["sender"])
        return False, False

    committed = _wait_committed(host, port, tx["id"])
    if not committed:
        fetch_nonce(host, port, tx["sender"])
    return True, committed


def _wait_committed(host: str, port: int, tx_id: str,
                    timeout_s: int = 30, interval: float = 0.4) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        data = get_json(host, port, f"/api/tx/{tx_id}")
        if isinstance(data, dict) and "success" in data:
            if data.get("success"):
                return True
            err = data.get("error") or "(no error detail)"
            if VERBOSE:
                print(warn(f"  tx {tx_id} failed on-chain: {err}"))
            return False
        time.sleep(interval)
    if VERBOSE:
        print(warn(f"  tx {tx_id} timed out after {timeout_s}s"))
    return False

# ── Balance snapshot ──────────────────────────────────────────────────────────

def _bal(host: str, port: int, address: str, denom: str) -> int:
    data = get_json(host, port, f"/api/accounts/{address}")
    if isinstance(data, dict):
        return int(data.get("balances", {}).get(denom, 0))
    return 0

def _job_state(host: str, port: int, job_id: str) -> Optional[str]:
    data = get_json(host, port, f"/api/jobs/{job_id}")
    if isinstance(data, dict) and data.get("job_id"):
        return data.get("state")
    return None

def _chain_height(host: str, port: int) -> int:
    data = get_json(host, port, "/api/status")
    if isinstance(data, dict):
        return int(data.get("latest_block_height", 0))
    return 0

# ── Lifecycle: run a full job and return the settlement context ───────────────

class SettlementContext:
    def __init__(self, run_id: str, job_id: str, escrow_id: str,
                 machine_id: str, agent_id: str, provider_wallet: str,
                 output_hash: str, receipt_hash: str,
                 alice_qrc_before: int, alice_qrc_after_lock: int,
                 provider_before: int, provider_after: int,
                 escrow_before_verify: int):
        self.run_id              = run_id
        self.job_id              = job_id
        self.escrow_id           = escrow_id
        self.machine_id          = machine_id
        self.agent_id            = agent_id
        self.provider_wallet     = provider_wallet
        self.output_hash         = output_hash
        self.receipt_hash        = receipt_hash
        self.alice_qrc_before    = alice_qrc_before       # before QrcPurchase
        self.alice_qrc_after_lock = alice_qrc_after_lock  # after LockQrcForJob
        self.provider_before     = provider_before         # before VerifyJob
        self.provider_after      = provider_after          # after VerifyJob
        self.escrow_before_verify = escrow_before_verify   # locked_uqrc before VerifyJob


def _run_full_lifecycle(host: str, port: int, label: str = "") -> SettlementContext:
    """Run the complete resource-job happy path and return balance snapshots."""
    run_id         = uuid.uuid4().hex[:8]
    machine_id     = f"si-machine-{run_id}"
    agent_id       = f"si-agent-{run_id}"
    agent_address  = f"si-addr-{run_id}"
    job_id         = f"si-job-{run_id}"
    escrow_id      = f"si-esc-{run_id}"
    receipt_id     = f"si-rcpt-{run_id}"
    payload        = f"si-payload-{run_id}"
    provider_wallet = f"wallet:{machine_id}"

    tag = f"[{label}] " if label else ""

    print(info(f"  {tag}run_id={run_id}  setting up lifecycle…"))

    H, P = host, port
    fetch_nonce(H, P, ALICE)

    # Snapshot Alice's QRC before any purchase
    alice_qrc_before = _bal(H, P, ALICE, "uqrc")

    # QRC purchase
    _, ok_ = _submit(H, P, _tx_qrc_purchase(ALICE))
    if not ok_:
        abort(f"{tag}QrcPurchase failed — cannot continue lifecycle setup")

    # Machine + agent setup
    _, ok_ = _submit(H, P, _tx_register_machine(ALICE, machine_id))
    if not ok_:
        abort(f"{tag}RegisterMachine failed")
    _, ok_ = _submit(H, P, _tx_register_agent(ALICE, agent_id, agent_address))
    if not ok_:
        abort(f"{tag}RegisterAgent failed")
    _, ok_ = _submit(H, P, _tx_authorize_agent(ALICE, agent_id))
    if not ok_:
        abort(f"{tag}AuthorizeAgent failed")
    _, ok_ = _submit(H, P, _tx_deposit_treasury(ALICE, agent_id))
    if not ok_:
        abort(f"{tag}DepositToTreasury failed")

    # Lock escrow
    _, ok_ = _submit(H, P, _tx_lock_qrc(ALICE, escrow_id, job_id, agent_id))
    if not ok_:
        abort(f"{tag}LockQrcForJob failed")

    alice_qrc_after_lock = _bal(H, P, ALICE, "uqrc")

    # Job lifecycle
    _, ok_ = _submit(H, P, _tx_create_job(ALICE, job_id, escrow_id, machine_id, payload))
    if not ok_:
        abort(f"{tag}CreateJob failed")
    _, ok_ = _submit(H, P, _tx_accept_job(ALICE, job_id, machine_id))
    if not ok_:
        abort(f"{tag}AcceptJob failed")

    output_hash  = hashlib.sha256(payload.encode()).hexdigest()
    receipt_hash = hashlib.sha256(receipt_id.encode()).hexdigest()

    _, ok_ = _submit(H, P, _tx_complete_job(ALICE, job_id, machine_id, output_hash, receipt_id))
    if not ok_:
        abort(f"{tag}CompleteJob failed")

    # Snapshot escrow and provider wallet BEFORE settlement
    escrow_before_verify = _bal(H, P, f"escrow:{escrow_id}", "locked_uqrc")
    provider_before      = _bal(H, P, provider_wallet, "uqrc")

    # Settle
    _, ok_ = _submit(H, P, _tx_verify_job(ALICE, job_id, escrow_id, output_hash,
                                           provider_wallet, receipt_hash))
    if not ok_:
        abort(f"{tag}VerifyJob failed — settlement invariants cannot be tested")

    time.sleep(1)  # let state propagate
    provider_after = _bal(H, P, provider_wallet, "uqrc")

    state = _job_state(H, P, job_id)
    if state != "Settled":
        abort(f"{tag}Job did not reach Settled state (got {state!r}) — cannot test invariants")

    print(info(f"  {tag}lifecycle complete — job={job_id} state=Settled"))
    return SettlementContext(
        run_id=run_id, job_id=job_id, escrow_id=escrow_id,
        machine_id=machine_id, agent_id=agent_id,
        provider_wallet=provider_wallet,
        output_hash=output_hash, receipt_hash=receipt_hash,
        alice_qrc_before=alice_qrc_before,
        alice_qrc_after_lock=alice_qrc_after_lock,
        provider_before=provider_before,
        provider_after=provider_after,
        escrow_before_verify=escrow_before_verify,
    )

# ── SI-001: QRC Conservation ──────────────────────────────────────────────────

def si001(ctx: SettlementContext, host: str, port: int) -> None:
    """
    SI-001  QRC Conservation

    At every step, QRC must be conserved: no amount is created from nothing or
    silently destroyed.  We track the flow from Alice's wallet through escrow
    to Carol's provider wallet.

    Expected flow:
      Alice wallet   -1,000,000  (LockQrcForJob debits uqrc)
      Escrow account +1,000,000  (locked_uqrc credited)
      ── VerifyJob ──
      Escrow account -  900,000  (locked_uqrc debited)
      Provider wallet+  900,000  (uqrc credited)
      Residual (fee)  = 100,000  (remains in escrow as locked_uqrc - amount)

    Because LockQrcForJob deducts from the agent treasury (not directly from
    Alice's wallet in all implementations), we measure the escrow balance as
    the ground-truth locked amount and verify the provider delta equals PAYMENT_AMOUNT.

    Note: QrcPurchase mints new QRC against burned QCB, so Alice's total uqrc
    increases.  We treat the post-purchase state as the starting baseline for
    the escrow flow, which is already captured in alice_qrc_after_lock.
    """
    print(hdr("SI-001  QRC Conservation"))

    H, P = host, port

    # 1. Escrow was properly credited before VerifyJob
    check(
        "SI-001a  escrow held correct amount before settlement",
        ctx.escrow_before_verify == ESCROW_AMOUNT,
        f"escrow locked_uqrc={ctx.escrow_before_verify}  expected={ESCROW_AMOUNT}",
    )

    # 2. Provider received exactly PAYMENT_AMOUNT
    provider_delta = ctx.provider_after - ctx.provider_before
    check(
        "SI-001b  provider wallet delta equals payment amount",
        provider_delta == PAYMENT_AMOUNT,
        f"before={ctx.provider_before}  after={ctx.provider_after}  "
        f"delta={provider_delta}  expected={PAYMENT_AMOUNT}",
    )

    # 3. Residual (FEE_RESIDUAL) is accounted for in escrow after settlement
    #    The escrow's locked_uqrc should have been debited by PAYMENT_AMOUNT,
    #    leaving FEE_RESIDUAL.  We read the CURRENT escrow balance.
    escrow_after = _bal(H, P, f"escrow:{ctx.escrow_id}", "locked_uqrc")
    expected_residual = ESCROW_AMOUNT - PAYMENT_AMOUNT   # == FEE_RESIDUAL
    check(
        "SI-001c  escrow residual equals ESCROW_AMOUNT − PAYMENT_AMOUNT",
        escrow_after == expected_residual,
        f"escrow locked_uqrc after settlement={escrow_after}  "
        f"expected={expected_residual}  (ESCROW={ESCROW_AMOUNT} − PAYMENT={PAYMENT_AMOUNT})",
    )

    # 4. Total accounted = payment + residual == original escrow
    total_accounted = provider_delta + escrow_after
    check(
        "SI-001d  provider_delta + escrow_residual == ESCROW_AMOUNT",
        total_accounted == ESCROW_AMOUNT,
        f"{provider_delta} + {escrow_after} = {total_accounted}  expected={ESCROW_AMOUNT}",
    )

# ── SI-002: Restart Persistence ───────────────────────────────────────────────

def si002(ctx: SettlementContext, host: str, port: int,
          node_bin: Optional[str], alice_data: Optional[str],
          alice_log: Optional[str], genesis: Optional[str],
          skip: bool) -> None:
    """
    SI-002  Restart Persistence

    A Settled job and the provider's credited balance must survive a node restart.
    This guards against in-memory-only state that is lost on crash/restart.

    We restart Alice's node (leaving Bob and Dave running to maintain quorum),
    wait for it to re-join and re-sync, then re-read the job state and balances.

    The original settlement must NOT be repeated — provider balance must not
    increase a second time and the job must remain Settled.
    """
    print(hdr("SI-002  Restart Persistence"))

    if skip or not all([node_bin, alice_data, alice_log, genesis]):
        missing = []
        if not node_bin:  missing.append("--node-bin")
        if not alice_data: missing.append("--alice-data")
        if not alice_log:  missing.append("--alice-log")
        if not genesis:    missing.append("--genesis")
        reason = "explicitly skipped" if skip else f"missing: {', '.join(missing)}"
        print(warn(f"  SI-002 skipped ({reason})"))
        print(warn("  To enable: pass --node-bin, --alice-data, --alice-log, --genesis"))
        return

    H, P = host, port

    # Record provider balance before restart
    provider_before_restart = _bal(H, P, ctx.provider_wallet, "uqrc")
    height_before_restart   = _chain_height(H, P)
    print(info(f"  height before restart: {height_before_restart}"))
    print(info(f"  provider balance before restart: {provider_before_restart}"))

    # ── Kill Alice's node ──────────────────────────────────────────────────
    print(info("  killing Alice's node…"))
    if platform.system() == "Windows":
        subprocess.run(["taskkill", "/F", "/IM", "chain-forge-node.exe"],
                       capture_output=True)
    else:
        subprocess.run(["pkill", "-f", f"chain-forge-node.*{alice_data}"],
                       capture_output=True)
    time.sleep(2)

    # Confirm Alice is down (Bob/Dave still respond)
    alice_down = get_json("127.0.0.1", 8080, "/api/status", timeout=2) is None
    check("SI-002a  Alice node went offline", alice_down,
          "Alice's node did not stop — restart test may be inaccurate")

    # ── Bob + Dave should still produce blocks ─────────────────────────────
    # With only 2-of-3 validators, quorum requires all to vote (3 validators,
    # quorum=3).  This means block production will PAUSE until Alice returns.
    # That's expected — we just need Alice to come back and re-join.
    print(info("  Alice node down — restarting…"))

    # ── Restart Alice ──────────────────────────────────────────────────────
    bootstrap_peers = []
    for (name, nh, np_) in ALL_NODES:
        if nh != "127.0.0.1" or np_ != 8080:  # skip Alice herself
            bootstrap_peers.extend(["--bootstrap", f"{nh}:2665{np_ - 8080 + 6}"])

    log_file = open(alice_log, "a")
    proc = subprocess.Popen(
        [node_bin, "--genesis", genesis, "--data-dir", alice_data,
         "--api-port", "8080", "--p2p-port", "26656"] + bootstrap_peers,
        stdout=log_file, stderr=log_file,
    )
    print(info(f"  Alice restarted  PID={proc.pid}"))

    # ── Wait for Alice to re-sync and produce/commit blocks ───────────────
    deadline = time.monotonic() + 60
    alice_up = False
    while time.monotonic() < deadline:
        s = get_json("127.0.0.1", 8080, "/api/status", timeout=2)
        if s and int(s.get("latest_block_height", 0)) > height_before_restart:
            alice_up = True
            break
        time.sleep(1)
    check("SI-002b  Alice re-joined and chain advanced",
          alice_up,
          f"height_before={height_before_restart}  "
          f"current={_chain_height('127.0.0.1', 8080)}")

    if not alice_up:
        return

    time.sleep(2)  # let gossip propagate

    # ── Re-read state after restart ────────────────────────────────────────
    job_state_after = _job_state(H, P, ctx.job_id)
    check("SI-002c  job state is still Settled after restart",
          job_state_after == "Settled",
          f"job_id={ctx.job_id}  state={job_state_after!r}")

    provider_after_restart = _bal(H, P, ctx.provider_wallet, "uqrc")
    check("SI-002d  provider balance unchanged after restart",
          provider_after_restart == provider_before_restart,
          f"before_restart={provider_before_restart}  "
          f"after_restart={provider_after_restart}")

    check("SI-002e  provider balance did NOT increase on restart",
          provider_after_restart <= provider_before_restart,
          f"restart must not replay settlement payment")

# ── SI-003: Duplicate Settlement ─────────────────────────────────────────────

def si003(ctx: SettlementContext, host: str, port: int) -> None:
    """
    SI-003  Duplicate Settlement Guard

    Once a job is Settled, a second VerifyJob (or any other settlement tx)
    on the same job_id must be rejected.

    We use the correct next account nonce — so nonce rejection cannot mask a
    missing settlement guard.  The tx must fail for a substantive reason
    (job already settled / escrow already drained), not just because of a
    stale nonce.
    """
    print(hdr("SI-003  Duplicate Settlement Guard"))

    H, P = host, port

    # Re-sync nonce so the duplicate attempt uses the correct next nonce
    fetch_nonce(H, P, ALICE)
    nonce_for_replay = _nonce_counter   # will be used by _nonce()
    _ = nonce_for_replay                # just for the log

    provider_before_replay = _bal(H, P, ctx.provider_wallet, "uqrc")

    if VERBOSE:
        print(info(f"  attempting duplicate VerifyJob at nonce={nonce_for_replay}"))

    tx = _tx_verify_job(ALICE, ctx.job_id, ctx.escrow_id,
                        ctx.output_hash, ctx.provider_wallet, ctx.receipt_hash)
    submitted, committed = _submit(H, P, tx, expect_ok=False)

    # The duplicate should either be rejected at submission or fail on-chain.
    # Either outcome is a pass.  What must NOT happen is committed=True.
    check(
        "SI-003a  duplicate VerifyJob was NOT committed",
        not committed,
        f"tx={tx['id']}  committed={committed}  "
        f"(submitted={submitted} — expected rejection on-chain or at submission)",
    )

    time.sleep(1)
    provider_after_replay = _bal(H, P, ctx.provider_wallet, "uqrc")
    check(
        "SI-003b  provider balance did not increase after duplicate attempt",
        provider_after_replay == provider_before_replay,
        f"before={provider_before_replay}  after={provider_after_replay}  "
        f"delta={provider_after_replay - provider_before_replay}  expected=0",
    )

    # Job state must remain Settled (not reverted or re-opened)
    state = _job_state(H, P, ctx.job_id)
    check(
        "SI-003c  job state remains Settled after duplicate attempt",
        state == "Settled",
        f"state={state!r}",
    )

# ── SI-004: Cross-Node Consistency ───────────────────────────────────────────

def si004(ctx: SettlementContext) -> None:
    """
    SI-004  Cross-Node Consistency

    All nodes must agree on:
      • job state == Settled
      • provider wallet balance (same amount credited)
      • escrow residual balance

    We compare at whatever the current height is on each node — if a node is
    lagging it will show a lower height and potentially stale state, which is
    itself a useful signal.  Strict same-height comparison is only possible
    when the API exposes a state-root or block header; we use best-effort here
    and flag discrepancies.
    """
    print(hdr("SI-004  Cross-Node Consistency"))

    job_states:      dict[str, str]  = {}
    provider_bals:   dict[str, int]  = {}
    escrow_residuals: dict[str, int] = {}
    heights:         dict[str, int]  = {}

    time.sleep(3)  # let gossip propagate

    for (name, nh, np_) in ALL_NODES:
        state    = _job_state(nh, np_, ctx.job_id)
        pbal     = _bal(nh, np_, ctx.provider_wallet, "uqrc")
        residual = _bal(nh, np_, f"escrow:{ctx.escrow_id}", "locked_uqrc")
        height   = _chain_height(nh, np_)

        job_states[name]       = state or "NOT FOUND"
        provider_bals[name]    = pbal
        escrow_residuals[name] = residual
        heights[name]          = height

    # Report heights (informational — divergence here is a separate concern)
    heights_str = "  ".join(f"{n}=h{h}" for n, h in heights.items())
    print(info(f"  node heights: {heights_str}"))

    # All agree on job state
    states_ok = all(s == "Settled" for s in job_states.values())
    states_str = "  ".join(f"{n}={s}" for n, s in job_states.items())
    check("SI-004a  all nodes report job state = Settled",
          states_ok, f"states: {states_str}")

    # All agree on provider balance
    pbal_values = list(provider_bals.values())
    pbals_agree = all(b == pbal_values[0] for b in pbal_values)
    pbals_str   = "  ".join(f"{n}={b}" for n, b in provider_bals.items())
    check("SI-004b  all nodes agree on provider wallet balance",
          pbals_agree and pbal_values[0] >= PAYMENT_AMOUNT,
          f"balances: {pbals_str}  expected≥{PAYMENT_AMOUNT}")

    # All agree on escrow residual
    res_values  = list(escrow_residuals.values())
    res_agree   = all(r == res_values[0] for r in res_values)
    res_str     = "  ".join(f"{n}={r}" for n, r in escrow_residuals.items())
    expected_res = ESCROW_AMOUNT - PAYMENT_AMOUNT
    check("SI-004c  all nodes agree on escrow residual",
          res_agree and res_values[0] == expected_res,
          f"residuals: {res_str}  expected={expected_res}")

# ── SI-005: Protocol Fee Accounting ──────────────────────────────────────────

def si005(ctx: SettlementContext, host: str, port: int) -> None:
    """
    SI-005  Protocol Fee Accounting

    The 100,000 uQRC difference between ESCROW_AMOUNT and PAYMENT_AMOUNT is a
    protocol fee placeholder.  Until QCB-ECON-001 (Deterministic Protocol Fee
    Routing) is implemented, these funds remain in the escrow account.

    This test:
      a) Asserts ESCROW_AMOUNT == PAYMENT_AMOUNT + FEE_RESIDUAL (accounting identity)
      b) Verifies the fee residual is present somewhere on-chain (not lost)
      c) If EXPECTED_FEE_DESTINATION is set, asserts it received FEE_RESIDUAL
      d) Documents the current behavior as a known limitation

    NOTE: stranded ≠ burned.  Unless supply reduction is explicitly implemented,
    these units remain part of the total QRC supply even if currently unspendable.
    """
    print(hdr("SI-005  Protocol Fee Accounting"))

    H, P = host, port

    # a) Accounting identity
    identity_ok = (ESCROW_AMOUNT == PAYMENT_AMOUNT + FEE_RESIDUAL)
    check("SI-005a  accounting identity: ESCROW == PAYMENT + FEE_RESIDUAL",
          identity_ok,
          f"{ESCROW_AMOUNT} == {PAYMENT_AMOUNT} + {FEE_RESIDUAL}")

    # b) Residual is still present on-chain in the escrow account
    escrow_residual = _bal(H, P, f"escrow:{ctx.escrow_id}", "locked_uqrc")
    check("SI-005b  fee residual present in escrow account",
          escrow_residual == FEE_RESIDUAL,
          f"escrow:{ctx.escrow_id}  locked_uqrc={escrow_residual}  expected={FEE_RESIDUAL}")

    # c) Fee destination (only asserted once QCB-ECON-001 is implemented)
    if EXPECTED_FEE_DESTINATION is not None:
        fee_dest_bal = _bal(H, P, EXPECTED_FEE_DESTINATION, "uqrc")
        check("SI-005c  fee routed to protocol treasury",
              fee_dest_bal >= FEE_RESIDUAL,
              f"{EXPECTED_FEE_DESTINATION}  balance={fee_dest_bal}  expected≥{FEE_RESIDUAL}")
    else:
        print(warn("  SI-005c  fee routing not yet implemented (QCB-ECON-001 pending)"))
        print(warn(f"  SI-005c  {FEE_RESIDUAL} uQRC stranded in escrow:{ctx.escrow_id}"))
        print(warn("  SI-005c  Set EXPECTED_FEE_DESTINATION and implement fee routing to resolve"))

    # d) Summary line documenting current behavior
    print(info(f"  Protocol fee status: {FEE_RESIDUAL} uQRC "
               f"{'→ ' + EXPECTED_FEE_DESTINATION if EXPECTED_FEE_DESTINATION else 'stranded in escrow (QCB-ECON-001 pending)'}"))

# ── Summary ───────────────────────────────────────────────────────────────────

_run_id_global = uuid.uuid4().hex[:8]

def _print_summary() -> None:
    print()
    print("─" * 60)
    if _failures == 0:
        print(f"{GREEN}{BOLD}ALL SETTLEMENT INVARIANTS PASSED{RESET}  run={_run_id_global}")
    else:
        print(f"{RED}{BOLD}{_failures} SETTLEMENT INVARIANT(S) FAILED{RESET}  run={_run_id_global}")

# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    global VERBOSE, _run_id_global

    parser = argparse.ArgumentParser(
        description="QCB Phase 0 Settlement Invariants Test Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--node",         default=f"{PRIMARY_HOST}:{PRIMARY_PORT}",
                        help="Primary node HOST:PORT (default 127.0.0.1:8080)")
    parser.add_argument("--node-bin",     default=os.environ.get("CFE_NODE_BIN"),
                        help="Path to chain-forge-node binary (for SI-002)")
    parser.add_argument("--alice-data",   default=os.environ.get("CFE_ALICE_DATA"),
                        help="Alice's data directory (for SI-002)")
    parser.add_argument("--alice-log",    default=os.environ.get("CFE_ALICE_LOG"),
                        help="Alice's log file path (for SI-002)")
    parser.add_argument("--genesis",      default=os.environ.get("CFE_GENESIS"),
                        help="Genesis JSON path (for SI-002)")
    parser.add_argument("--skip-restart", action="store_true",
                        help="Skip SI-002 (node restart test)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Print individual HTTP calls")
    args = parser.parse_args()

    VERBOSE = args.verbose

    parts = args.node.rsplit(":", 1)
    host  = parts[0] if len(parts) == 2 else PRIMARY_HOST
    port  = int(parts[1]) if len(parts) == 2 else PRIMARY_PORT

    # Reachability check
    status = get_json(host, port, "/api/status", timeout=5)
    if status is None:
        print(fail(f"Cannot reach node at {host}:{port}"))
        print(warn("Start the devnet first: bash scripts/start-devnet-local.sh"))
        sys.exit(1)
    print(ok(f"Node reachable: {host}:{port}"))

    print(hdr(f"QCB Settlement Invariants  [{host}:{port}]  run={_run_id_global}"))
    print()
    print("Running lifecycle setup…")
    print("─" * 60)

    # ── Run the full lifecycle to get a settled job ──────────────────────────
    ctx = _run_full_lifecycle(host, port, label="setup")

    # ── SI-001 ───────────────────────────────────────────────────────────────
    si001(ctx, host, port)

    # ── SI-002 ───────────────────────────────────────────────────────────────
    si002(ctx, host, port,
          node_bin=args.node_bin,
          alice_data=args.alice_data,
          alice_log=args.alice_log,
          genesis=args.genesis,
          skip=args.skip_restart)

    # ── SI-003 ───────────────────────────────────────────────────────────────
    si003(ctx, host, port)

    # ── SI-004 ───────────────────────────────────────────────────────────────
    si004(ctx)

    # ── SI-005 ───────────────────────────────────────────────────────────────
    si005(ctx, host, port)

    # ── Final summary ─────────────────────────────────────────────────────────
    _print_summary()
    sys.exit(0 if _failures == 0 else 1)


if __name__ == "__main__":
    main()
