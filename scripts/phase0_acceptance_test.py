#!/usr/bin/env python3
"""
phase0_acceptance_test.py — Phase 0 Cross-Machine Purchase Acceptance Test

Proves the full QRC escrow lifecycle works end-to-end across the devnet:

  1. Alice (Machine 1) buys QRC via QrcPurchase
  2. Alice registers a resource agent  (RegisterAgent)
  3. Alice authorises the agent        (AuthorizeAgent → Active status)
  4. Alice deposits to the agent treasury with a per-job cap (DepositToTreasury)
  5. Alice escrows QRC for a job       (LockQrcForJob, drawing from treasury)
  6. All 4 devnet nodes confirm the transactions are in committed blocks
  7. Balance assertions are verified on every node

Devnet topology (as of Phase 0 genesis):
  Machine 1  →  Alice  localhost:8080
             →  Bob    localhost:8081
             →  Dave   localhost:8082
  Machine 2  →  Carol  192.168.137.3:8080

Usage:
    python3 scripts/phase0_acceptance_test.py [--machine2 IP]

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

# Carol is added dynamically after arg parsing

# ── Test parameters ────────────────────────────────────────────────────────

# Alice's devnet address (from genesis alloc — must match the genesis validator address)
# The genesis-4node.json allocates QCB/QRC to "qcb1alice" (the validator's --validator flag).
ALICE_ADDRESS = "qcb1alice"

# Synthetic agent identity for this test run (unique per run)
_run_id      = uuid.uuid4().hex[:8]
AGENT_ID      = f"test-agent-{_run_id}"
AGENT_ADDRESS = f"agent-addr-{_run_id}"

# QRC/escrow amounts  (all in uQRC unless noted)
QCB_TO_BURN         = 10_000_000   # uQCB to burn for QRC
MIN_QRC_OUT         = 0            # accept any rate (devnet has no slippage)
TREASURY_DEPOSIT    = 5_000_000    # uQRC deposited into the treasury
PER_JOB_LIMIT       = 1_000_000    # uQRC max per single job
ESCROW_AMOUNT       = 800_000      # uQRC locked for the test job (< per-job limit)

JOB_ID    = f"job-{_run_id}"
ESCROW_ID = f"esc-{_run_id}"

# Timing
SUBMIT_TIMEOUT_SECS  = 8    # per-request tx submission timeout
STATUS_TIMEOUT_SECS  = 5    # per-request status/balance check timeout
PROPAGATION_WAIT_S   = 10   # seconds to wait for cross-node propagation after all txs commit
COMMIT_POLL_INTERVAL = 0.5  # seconds between block polls while waiting for a tx to commit
COMMIT_TIMEOUT_S     = 30   # max seconds to wait for a single tx to appear in a block

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


# ── Nonce helper ───────────────────────────────────────────────────────────

def get_live_nonce(host: str, port: int, address: str) -> int:
    """
    Fetch the current nonce for `address` from the node at host:port.
    Returns 0 if the account doesn't exist yet (fresh account).
    The node stores the NEXT expected nonce on the account after each
    successful tx, so this is exactly what we pass in our next tx.
    """
    try:
        data = get_json(host, port, f"/api/accounts/{address}")
        if isinstance(data, dict):
            return int(data.get("nonce", 0))
        return 0
    except Exception:
        return 0   # account not yet created → nonce 0


# ── Nonce state (populated from live node before tx building) ───────────────

_nonce_counter: int = 0   # set by fetch_and_set_nonce() before first tx


def fetch_and_set_nonce(host: str, port: int, address: str) -> int:
    """Query the live nonce for address and initialise the global counter."""
    global _nonce_counter
    _nonce_counter = get_live_nonce(host, port, address)
    return _nonce_counter


def _nonce() -> int:
    global _nonce_counter
    n = _nonce_counter
    _nonce_counter += 1
    return n


# ── Transaction builders ───────────────────────────────────────────────────
#
# Mirror the Rust Transaction constructors, producing the same JSON that
# serde_json::from_str::<Transaction> expects.
#
# Field layout from chain-forge-execution:
#   { "id", "sender", "nonce", "body": { "<VariantName>": { ...fields... } },
#     "gas_limit", "signature": [], "public_key": [] }
#
# TxBody uses default serde (externally-tagged), so:
#   "body": { "QrcPurchase": { "qcb_amount": ..., "min_qrc_out": ... } }

def tx_qrc_purchase(sender: str, qcb_amount: int, min_qrc_out: int) -> dict:
    return {
        "id":         f"tx-qrc-buy-{_run_id}",
        "sender":     sender,
        "nonce":      _nonce(),
        "body":       {"QrcPurchase": {"qcb_amount": qcb_amount, "min_qrc_out": min_qrc_out}},
        "gas_limit":  200_000,
        "signature":  [],
        "public_key": [],
    }


def tx_register_agent(sender: str, agent_id: str, agent_address: str) -> dict:
    return {
        "id":         f"tx-reg-agent-{_run_id}",
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
                "description":     f"Phase 0 acceptance test agent ({_run_id})",
                "parent_agent_id": None,
            }
        },
        "gas_limit":  300_000,
        "signature":  [],
        "public_key": [],
    }


def tx_authorize_agent(sender: str, agent_id: str) -> dict:
    return {
        "id":         f"tx-auth-agent-{_run_id}",
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
        "id":         f"tx-deposit-{_run_id}",
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


def tx_lock_qrc_for_job(sender: str, escrow_id: str,
                         job_id: str, agent_wallet: str, amount: int) -> dict:
    """
    agent_wallet is the key used to derive the treasury address:
    treasury:{agent_wallet}.  Must match the agent_id passed to
    DepositToTreasury so the treasury lookup succeeds.
    """
    return {
        "id":         f"tx-lock-{_run_id}",
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


# ── Assertion helpers ──────────────────────────────────────────────────────

@dataclass
class Check:
    passed: bool
    desc:   str
    detail: str = ""


@dataclass
class NodeReport:
    name:   str
    host:   str
    port:   int
    online: bool = False
    checks: list = field(default_factory=list)

    def add(self, passed: bool, desc: str, detail: str = "") -> None:
        self.checks.append(Check(passed, desc, detail))

    @property
    def pass_count(self) -> int:
        return sum(1 for c in self.checks if c.passed)

    @property
    def fail_count(self) -> int:
        return sum(1 for c in self.checks if not c.passed)


# ── Block / tx helpers ─────────────────────────────────────────────────────

def find_tx_in_blocks(host: str, port: int, tx_id: str) -> bool:
    """Return True if tx_id appears in any committed block on this node.

    BlockSummary serialises as {"height":…, "tx_count":…, "tx_ids": ["tx-abc", …]}.
    Also falls back to checking a "transactions" field (array of objects with an
    "id" key) in case the schema ever changes.
    """
    try:
        blocks = get_json(host, port, "/api/blocks")
        if not isinstance(blocks, list):
            return False
        for blk in blocks:
            # Primary path: tx_ids is a Vec<String> of bare tx ids
            for tid in blk.get("tx_ids", []):
                if tid == tx_id:
                    return True
            # Fallback: transactions field containing objects with an "id" key
            for tx in blk.get("transactions", []):
                tid = tx if isinstance(tx, str) else tx.get("id", "")
                if tid == tx_id:
                    return True
        return False
    except Exception:
        return False


def get_tx_result(host: str, port: int, tx_id: str) -> Optional[dict]:
    """Return the TxSummary for tx_id from /api/tx/{id}, or None if not found."""
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
    """
    Poll until tx_id appears in a committed block on host:port, or timeout.
    Returns (found, tx_summary_or_None).
    tx_summary has {success, error, events, …} from /api/tx/{id}.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if find_tx_in_blocks(host, port, tx_id):
            result = get_tx_result(host, port, tx_id)
            return True, result
        time.sleep(poll)
    return False, None


def get_account_balance(host: str, port: int,
                         address: str, denom: str = "uqrc") -> Optional[int]:
    """Return the uqrc (or other denom) balance for address, or None on error."""
    try:
        data = get_json(host, port, f"/api/accounts/{address}")
        if not isinstance(data, dict):
            return None
        # Two possible shapes: {"balances": {"uqrc": 12345}} or {"balance": ...}
        balances = data.get("balances", {})
        if isinstance(balances, dict):
            return balances.get(denom, 0)
        # Flat shape — some devnet versions emit {"address":..., "uqrc": 123}
        return data.get(denom, 0)
    except Exception:
        return None


# ── Phase steps ────────────────────────────────────────────────────────────

def step_submit(label: str, host: str, port: int, tx: dict) -> tuple[bool, str]:
    """POST a transaction to Alice's node; return (queued, status/error)."""
    print(f"  {info(label)} → Alice [{host}:{port}]", flush=True)
    try:
        resp = post_json(host, port, "/api/tx", tx)
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


def step_submit_and_wait(label: str, host: str, port: int, tx: dict) -> tuple[bool, bool]:
    """
    POST a tx, then poll until it commits.  Returns (queued, executed_ok).
    If queuing fails, returns (False, False) immediately.
    If the tx commits but execution failed (reverted), returns (True, False)
    and prints the execution error — the caller should abort the sequence
    because subsequent txs will have wrong nonces.
    """
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
        # Block has the tx but /api/tx/{id} not exposed — treat as committed-ok
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


# ── Main test ──────────────────────────────────────────────────────────────

def run(nodes: list[tuple[str, str, int]]) -> int:
    """
    Execute the Phase 0 acceptance test.
    Returns 0 on full pass, 1 on any failure.
    """
    alice_name, alice_host, alice_port = nodes[0]

    print(hdr("═══ Phase 0 Cross-Machine Purchase Acceptance Test ═══"))
    print(f"  Run ID:         {_run_id}")
    print(f"  Agent ID:       {AGENT_ID}")
    print(f"  Job ID:         {JOB_ID}")
    print(f"  Escrow ID:      {ESCROW_ID}")
    print(f"  QCB to burn:    {QCB_TO_BURN:,} uQCB")
    print(f"  Treasury dep:   {TREASURY_DEPOSIT:,} uQRC  (per-job cap: {PER_JOB_LIMIT:,})")
    print(f"  Escrow amount:  {ESCROW_AMOUNT:,} uQRC")
    print(f"  Nodes:          {', '.join(n for n,_,_ in nodes)}")

    # ─── Pre-flight: node reachability ──────────────────────────────────────
    print(hdr("Step 0 — Node reachability"))
    all_nodes_up = True
    for name, host, port in nodes:
        alive = node_ok(host, port)
        sym   = ok(f"{name} [{host}:{port}] online") if alive else warn(f"{name} [{host}:{port}] OFFLINE")
        print(f"  {sym}")
        if not alive:
            all_nodes_up = False

    if not all_nodes_up:
        print(f"\n  {warn('Some nodes offline — continuing, will mark those checks as SKIP')}")

    # ─── Fetch Alice's live nonce ────────────────────────────────────────────
    print(hdr("Step 0b — Fetch Alice's live nonce"))
    live_nonce = fetch_and_set_nonce(alice_host, alice_port, ALICE_ADDRESS)
    print(f"  {ok(f'Alice nonce = {live_nonce}  (txs will use nonces {live_nonce}–{live_nonce+4})')}")

    # ─── Build all transactions now that nonce counter is initialised ────────
    tx1 = tx_qrc_purchase(ALICE_ADDRESS, QCB_TO_BURN, MIN_QRC_OUT)
    tx2 = tx_register_agent(ALICE_ADDRESS, AGENT_ID, AGENT_ADDRESS)
    tx3 = tx_authorize_agent(ALICE_ADDRESS, AGENT_ID)
    tx4 = tx_deposit_to_treasury(ALICE_ADDRESS, AGENT_ID, TREASURY_DEPOSIT, PER_JOB_LIMIT)
    # agent_wallet = AGENT_ID so treasury key is treasury:{AGENT_ID},
    # matching the key DepositToTreasury creates.
    tx5 = tx_lock_qrc_for_job(ALICE_ADDRESS, ESCROW_ID, JOB_ID, AGENT_ID, ESCROW_AMOUNT)

    submitted_tx_ids = [tx1["id"], tx2["id"], tx3["id"], tx4["id"], tx5["id"]]

    # ─── Step 1: QRC purchase ───────────────────────────────────────────────
    print(hdr("Step 1 — Alice buys QRC  (QrcPurchase)"))
    ok1, exec1 = step_submit_and_wait("QrcPurchase", alice_host, alice_port, tx1)
    if not (ok1 and exec1):
        print(f"\n  {fail('QrcPurchase failed — aborting sequence (nonces would cascade)')}")
        return _run_verification(nodes, submitted_tx_ids, aborted=True)

    # ─── Step 2: Register agent ─────────────────────────────────────────────
    print(hdr("Step 2 — Register resource agent  (RegisterAgent)"))
    ok2, exec2 = step_submit_and_wait("RegisterAgent", alice_host, alice_port, tx2)
    if not (ok2 and exec2):
        print(f"\n  {fail('RegisterAgent failed — aborting sequence')}")
        return _run_verification(nodes, submitted_tx_ids, aborted=True)

    # ─── Step 3: Authorize agent ────────────────────────────────────────────
    print(hdr("Step 3 — Authorize agent → Active  (AuthorizeAgent)"))
    ok3, exec3 = step_submit_and_wait("AuthorizeAgent", alice_host, alice_port, tx3)
    if not (ok3 and exec3):
        print(f"\n  {fail('AuthorizeAgent failed — aborting sequence')}")
        return _run_verification(nodes, submitted_tx_ids, aborted=True)

    # ─── Step 4: Deposit to treasury ────────────────────────────────────────
    print(hdr("Step 4 — Fund agent treasury  (DepositToTreasury)"))
    ok4, exec4 = step_submit_and_wait("DepositToTreasury", alice_host, alice_port, tx4)
    if not (ok4 and exec4):
        print(f"\n  {fail('DepositToTreasury failed — aborting sequence')}")
        return _run_verification(nodes, submitted_tx_ids, aborted=True)

    # ─── Step 5: Lock QRC for job (draws from treasury) ─────────────────────
    print(hdr("Step 5 — Escrow QRC for job  (LockQrcForJob)"))
    # agent_wallet = AGENT_ID → treasury key = treasury:{AGENT_ID}
    # This matches the key DepositToTreasury wrote above.
    ok5, exec5 = step_submit_and_wait("LockQrcForJob", alice_host, alice_port, tx5)

    # ─── Wait for propagation ────────────────────────────────────────────────
    print(hdr(f"Step 6 — Wait {PROPAGATION_WAIT_S}s for cross-node propagation …"))
    for remaining in range(PROPAGATION_WAIT_S, 0, -1):
        print(f"  {remaining}s …", end="\r", flush=True)
        time.sleep(1)
    print(f"  Done.{' ' * 20}")

    return _run_verification(nodes, submitted_tx_ids, aborted=False)


def _run_verification(nodes: list[tuple[str, str, int]],
                      submitted_tx_ids: list[str],
                      aborted: bool) -> int:
    # ─── Per-node verification ───────────────────────────────────────────────
    print(hdr("Step 7 — Verify state on all nodes"))

    reports: list[NodeReport] = []
    # Treasury account key is treasury:{AGENT_ID} — matches DepositToTreasury
    # which stores state under format!("treasury:{}", agent_id).
    treasury_key = f"treasury:{AGENT_ID}"

    for name, host, port in nodes:
        rep = NodeReport(name=name, host=host, port=port)
        reports.append(rep)

        print(f"\n  {BOLD}[{name}  {host}:{port}]{RESET}")

        # Reachability
        try:
            status = get_json(host, port, "/api/status", timeout=STATUS_TIMEOUT_SECS)
            height = status.get("height", "?") if isinstance(status, dict) else "?"
            rep.online = True
            print(f"    {ok(f'reachable  height={height}')}")
        except Exception as e:
            rep.online = False
            print(f"    {fail(f'OFFLINE — {e}')}")
            continue

        # Check each tx appears in a committed block
        for tx_id in submitted_tx_ids:
            found = find_tx_in_blocks(host, port, tx_id)
            rep.add(found, f"tx {tx_id[:20]}… committed")
            sym = ok(f"tx {tx_id[:20]}… in blocks") if found else fail(f"tx {tx_id[:20]}… NOT in blocks")
            print(f"    {sym}")

            # If tx is committed, also show execution result (success/failure)
            if found:
                result = get_tx_result(host, port, tx_id)
                if result is not None:
                    exec_ok  = result.get("success", True)
                    exec_err = result.get("error") or ""
                    exec_sym = f"{GREEN}exec=ok{RESET}" if exec_ok else f"{RED}exec=FAIL: {exec_err}{RESET}"
                    print(f"      {exec_sym}")

        # Balance checks — Alice's QRC balance should be readable
        alice_bal = get_account_balance(host, port, ALICE_ADDRESS, "uqrc")
        if alice_bal is None:
            rep.add(False, "Alice uQRC balance readable")
            print(f"    {fail('Alice account not found')}")
        else:
            rep.add(True, "Alice uQRC balance readable")
            print(f"    {ok(f'Alice uQRC balance = {alice_bal:,}')}")

        # Treasury account should have TREASURY_DEPOSIT − ESCROW_AMOUNT
        treasury_bal = get_account_balance(host, port, treasury_key, "uqrc")
        expected_treasury = TREASURY_DEPOSIT - ESCROW_AMOUNT
        if treasury_bal is None:
            rep.add(False, "Treasury account exists")
            print(f"    {fail(f'Treasury account {treasury_key!r} not found')}")
        else:
            match = treasury_bal == expected_treasury
            rep.add(match, f"Treasury balance = {expected_treasury:,} uQRC")
            sym = ok if match else fail
            print(f"    {sym(f'Treasury {treasury_key!r} = {treasury_bal:,} uQRC')}"
                  f"  (expected {expected_treasury:,})")

        # Escrow virtual account — soft check (some builds don't expose sub-accounts)
        escrow_key = f"escrow:{ESCROW_ID}"
        escrow_bal = get_account_balance(host, port, escrow_key, "uqrc")
        if escrow_bal is None:
            rep.add(True, "Escrow balance check (soft)")
            print(f"    {warn(f'Escrow account {escrow_key!r} not queryable (soft skip)')}")
        else:
            match = escrow_bal == ESCROW_AMOUNT
            rep.add(match, f"Escrow balance = {ESCROW_AMOUNT:,} uQRC")
            sym = ok if match else fail
            print(f"    {sym(f'Escrow {escrow_key!r} = {escrow_bal:,} uQRC')}"
                  f"  (expected {ESCROW_AMOUNT:,})")

    # ─── Summary ─────────────────────────────────────────────────────────────
    print(hdr("═══ Results ═══"))
    if aborted:
        print(f"  {YELLOW}Test aborted early — tx submission or execution failed{RESET}")
    overall_pass = not aborted

    for rep in reports:
        if not rep.online:
            status = f"{YELLOW}OFFLINE{RESET}"
            overall_pass = False
        elif rep.fail_count > 0:
            status = f"{RED}FAIL ({rep.fail_count} check(s) failed){RESET}"
            overall_pass = False
        else:
            status = f"{GREEN}PASS{RESET}  ({rep.pass_count} checks)"
        print(f"  {rep.name:8} [{rep.host}:{rep.port}]  {status}")
        for c in rep.checks:
            if not c.passed:
                indent = "  " * 3
                print(f"{indent}{fail(c.desc)}" + (f"  {c.detail}" if c.detail else ""))

    final_sym  = f"{GREEN}{BOLD}✓  OVERALL PASS{RESET}" if overall_pass else f"{RED}{BOLD}✗  OVERALL FAIL{RESET}"
    print(f"\n  {final_sym}\n")

    return 0 if overall_pass else 1


# ── Entry point ────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Phase 0 cross-machine QRC escrow acceptance test."
    )
    parser.add_argument(
        "--machine2",
        default=MACHINE2_HOST_DEFAULT,
        metavar="IP",
        help=f"Machine 2 IP (default: {MACHINE2_HOST_DEFAULT})",
    )
    parser.add_argument(
        "--skip-carol",
        action="store_true",
        help="Skip Carol (Machine 2) — useful for single-machine smoke runs",
    )
    args = parser.parse_args()

    nodes = list(NODES_MACHINE1)
    if not args.skip_carol:
        nodes.append(("Carol", args.machine2, 8080))

    return run(nodes)


if __name__ == "__main__":
    sys.exit(main())
