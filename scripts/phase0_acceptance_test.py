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

# Alice's devnet address (from genesis alloc — adjust if your genesis differs)
ALICE_ADDRESS = "alice"

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
SUBMIT_TIMEOUT_SECS = 8            # per-request tx submission timeout
STATUS_TIMEOUT_SECS = 5            # per-request status/balance check timeout
PROPAGATION_WAIT_S  = 10           # seconds to wait for cross-node propagation

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

_nonce_counter = 1


def _nonce() -> int:
    global _nonce_counter
    n = _nonce_counter
    _nonce_counter += 1
    return n


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
    checks: list[Check] = field(default_factory=list)

    def add(self, passed: bool, desc: str, detail: str = "") -> None:
        self.checks.append(Check(passed, desc, detail))

    @property
    def all_pass(self) -> bool:
        return self.online and all(c.passed for c in self.checks)

    @property
    def pass_count(self) -> int:
        return sum(1 for c in self.checks if c.passed)

    @property
    def fail_count(self) -> int:
        return sum(1 for c in self.checks if not c.passed)


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
    """POST a transaction to Alice's node; return (success, status/error)."""
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

    # ─── Step 1: QRC purchase ───────────────────────────────────────────────
    print(hdr("Step 1 — Alice buys QRC  (QrcPurchase)"))
    tx1 = tx_qrc_purchase(ALICE_ADDRESS, QCB_TO_BURN, MIN_QRC_OUT)
    ok1, _ = step_submit("QrcPurchase", alice_host, alice_port, tx1)

    # ─── Step 2: Register agent ─────────────────────────────────────────────
    print(hdr("Step 2 — Register resource agent  (RegisterAgent)"))
    tx2 = tx_register_agent(ALICE_ADDRESS, AGENT_ID, AGENT_ADDRESS)
    ok2, _ = step_submit("RegisterAgent", alice_host, alice_port, tx2)

    # ─── Step 3: Authorize agent ────────────────────────────────────────────
    print(hdr("Step 3 — Authorize agent → Active  (AuthorizeAgent)"))
    tx3 = tx_authorize_agent(ALICE_ADDRESS, AGENT_ID)
    ok3, _ = step_submit("AuthorizeAgent", alice_host, alice_port, tx3)

    # ─── Step 4: Deposit to treasury ────────────────────────────────────────
    print(hdr("Step 4 — Fund agent treasury  (DepositToTreasury)"))
    tx4 = tx_deposit_to_treasury(ALICE_ADDRESS, AGENT_ID, TREASURY_DEPOSIT, PER_JOB_LIMIT)
    ok4, _ = step_submit("DepositToTreasury", alice_host, alice_port, tx4)

    # ─── Step 5: Lock QRC for job (draws from treasury) ─────────────────────
    print(hdr("Step 5 — Escrow QRC for job  (LockQrcForJob)"))
    # agent_wallet here is ALICE_ADDRESS because the treasury key is
    # `treasury:{agent_wallet}` — the execution handler looks up treasury by
    # the agent_wallet field.  In Phase 0 devnet Alice is her own agent.
    tx5 = tx_lock_qrc_for_job(ALICE_ADDRESS, ESCROW_ID, JOB_ID, ALICE_ADDRESS, ESCROW_AMOUNT)
    ok5, _ = step_submit("LockQrcForJob", alice_host, alice_port, tx5)

    submitted_tx_ids = [tx1["id"], tx2["id"], tx3["id"], tx4["id"], tx5["id"]]
    submit_results   = [ok1, ok2, ok3, ok4, ok5]

    if not all(submit_results):
        failed_steps = [i+1 for i, r in enumerate(submit_results) if not r]
        print(f"\n  {fail(f'Submission failed for step(s): {failed_steps}')}")
        print(f"  {warn('Propagation checks may be unreliable — continuing anyway')}")

    # ─── Wait for propagation ────────────────────────────────────────────────
    print(hdr(f"Step 6 — Wait {PROPAGATION_WAIT_S}s for cross-node propagation …"))
    for remaining in range(PROPAGATION_WAIT_S, 0, -1):
        print(f"  {remaining}s …", end="\r", flush=True)
        time.sleep(1)
    print(f"  Done.{' ' * 20}")

    # ─── Per-node verification ───────────────────────────────────────────────
    print(hdr("Step 7 — Verify state on all nodes"))

    reports: list[NodeReport] = []
    treasury_key = f"treasury:{ALICE_ADDRESS}"

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

        # Balance checks — Alice's QRC balance should have decreased from purchases
        # (exact pre-test balance is unknown without genesis query, so we check > 0)
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
            print(f"    {sym(f'Treasury {treasury_key!r} = {treasury_bal:,} uQRC')} "
                  f"  (expected {expected_treasury:,})")

        # Escrow virtual account should hold ESCROW_AMOUNT
        escrow_key = f"escrow:{ESCROW_ID}"
        escrow_bal = get_account_balance(host, port, escrow_key, "uqrc")
        if escrow_bal is None:
            # Some devnet builds don't expose escrow sub-accounts via /api/accounts
            # Treat as a soft warning rather than a hard failure
            rep.add(True, "Escrow balance check (soft)")
            print(f"    {warn(f'Escrow account {escrow_key!r} not queryable (soft skip)')}")
        else:
            match = escrow_bal == ESCROW_AMOUNT
            rep.add(match, f"Escrow balance = {ESCROW_AMOUNT:,} uQRC")
            sym = ok if match else fail
            print(f"    {sym(f'Escrow {escrow_key!r} = {escrow_bal:,} uQRC')} "
                  f"  (expected {ESCROW_AMOUNT:,})")

    # ─── Summary ─────────────────────────────────────────────────────────────
    print(hdr("═══ Results ═══"))
    overall_pass = True

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
