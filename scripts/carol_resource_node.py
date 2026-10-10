#!/usr/bin/env python3
"""
carol_resource_node.py — Carol's Resource Node Daemon (Phase 0)

Carol's machine polls /api/jobs?state=Created for open jobs that are
assigned to her machine.  When a matching job is found it:

  1. Submits AcceptJob  (transitions Created → Running)
  2. Executes the workload (Phase 0: simulates work, hashes the payload)
  3. Submits CompleteJob (transitions Running → Completed)

Carol does NOT call VerifyJob — that's the requester's job (self-verify in
Phase 0).  This daemon runs continuously until stopped with Ctrl-C.

Usage:
    python3 scripts/carol_resource_node.py \\
        --node    127.0.0.1:8080 \\
        --machine carol-machine-1 \\
        --sender  qcb1carol

Environment (for integration tests):
    CAROL_NODE_URL     override node base URL  (http://HOST:PORT)
    CAROL_MACHINE_ID   machine_id Carol owns
    CAROL_SENDER       carol's on-chain address

Options:
    --node      HOST:PORT of the node Carol talks to (default 127.0.0.1:8080)
    --machine   machine_id Carol registered on-chain
    --sender    carol's on-chain address
    --poll      seconds between job polls (default 2)
    --once      process at most one job then exit (useful for tests)
    --dry-run   print what would happen but don't submit txs
"""

import argparse
import hashlib
import json
import os
import sys
import time
import uuid
import urllib.request
import urllib.error
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

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


def now() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S UTC")


# ── HTTP helpers ───────────────────────────────────────────────────────────

def get_json(url: str, timeout: int = 5) -> Optional[dict | list]:
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        raise RuntimeError(f"HTTP {e.code} from {url}: {body}")
    except Exception as e:
        raise RuntimeError(f"GET {url} failed: {e}")


def post_json(url: str, payload: dict, timeout: int = 8) -> dict:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
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


# ── Nonce management ───────────────────────────────────────────────────────

_nonce: int = -1  # -1 = not yet fetched


def refresh_nonce(base_url: str, sender: str) -> int:
    global _nonce
    try:
        data = get_json(f"{base_url}/api/accounts/{sender}")
        if isinstance(data, dict):
            _nonce = int(data.get("nonce", 0))
        else:
            _nonce = 0
    except Exception:
        _nonce = 0
    return _nonce


def next_nonce(base_url: str, sender: str) -> int:
    global _nonce
    if _nonce < 0:
        refresh_nonce(base_url, sender)
    n = _nonce
    _nonce += 1
    return n


# ── Transaction builders ───────────────────────────────────────────────────
# Carol signs nothing (Phase 0 devnet has no signature enforcement for Carol).
# The node accepts txs without a valid signature on devnet.

def _tx(sender: str, nonce: int, body: dict) -> dict:
    return {
        "id":         f"tx-carol-{uuid.uuid4().hex[:12]}",
        "sender":     sender,
        "nonce":      nonce,
        "body":       body,
        "gas_limit":  50_000,
        "signature":  [],
        "public_key": [],
    }


def tx_accept_job(sender: str, nonce: int, job_id: str, machine_id: str) -> dict:
    return _tx(sender, nonce, {
        "AcceptJob": {
            "job_id":     job_id,
            "machine_id": machine_id,
        }
    })


def tx_complete_job(
    sender: str, nonce: int,
    job_id: str, machine_id: str,
    output_hash: str, receipt_id: str,
    execution_stats_json: str,
) -> dict:
    return _tx(sender, nonce, {
        "CompleteJob": {
            "job_id":               job_id,
            "machine_id":           machine_id,
            "output_hash":          output_hash,
            "receipt_id":           receipt_id,
            "execution_stats_json": execution_stats_json,
        }
    })


# ── Workload execution ─────────────────────────────────────────────────────

def execute_workload(job: dict) -> tuple[str, dict]:
    """
    Phase 0 simulated execution.

    Real resource nodes will plug in actual workload runners here
    (e.g. Python subprocess, Docker, WASM sandbox).  For Phase 0 we:
      - Compute SHA-256 of the workload_payload string.
      - Record execution time.

    Returns (output_hash_hex, stats_dict).
    """
    payload     = job.get("workload_payload", "")
    workload_type = job.get("workload_type", "unknown")

    t0 = time.monotonic()

    # Simulated work: hash the payload.
    output_hash = hashlib.sha256(payload.encode()).hexdigest()

    elapsed = time.monotonic() - t0

    stats = {
        "workload_type":   workload_type,
        "input_bytes":     len(payload),
        "output_hash":     output_hash,
        "elapsed_seconds": round(elapsed, 6),
        "executor":        "carol-phase0-sim",
        "phase":           0,
    }
    return output_hash, stats


# ── Wait for tx to commit ──────────────────────────────────────────────────

def wait_for_tx(base_url: str, tx_id: str,
                timeout_s: int = 20, poll_interval: float = 0.5) -> dict:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            result = get_json(f"{base_url}/api/tx/{tx_id}")
            if isinstance(result, dict) and result.get("status") == "ok":
                return result
            if isinstance(result, dict) and result.get("status") == "error":
                raise RuntimeError(f"tx {tx_id} failed on-chain: {result.get('error', result)}")
        except RuntimeError:
            raise
        except Exception:
            pass
        time.sleep(poll_interval)
    raise TimeoutError(f"tx {tx_id} not committed after {timeout_s}s")


# ── Core daemon loop ───────────────────────────────────────────────────────

@dataclass
class Config:
    base_url:   str
    machine_id: str
    sender:     str
    poll_s:     float
    once:       bool
    dry_run:    bool


def process_job(cfg: Config, job: dict) -> bool:
    """
    Attempt to accept, execute, and complete one job.
    Returns True if the job was successfully completed.
    """
    job_id       = job.get("job_id", "")
    machine_id   = job.get("machine_id", "")
    assigned_mid = job.get("machine_id", "")

    # Verify this job is for Carol's machine.
    if assigned_mid != cfg.machine_id:
        return False

    print(info(f"[{now()}] Found job {job_id} for machine {machine_id}"))

    # ── Step 1: AcceptJob ──────────────────────────────────────────────────
    nonce = next_nonce(cfg.base_url, cfg.sender)
    accept_tx = tx_accept_job(cfg.sender, nonce, job_id, cfg.machine_id)
    print(info(f"  Submitting AcceptJob  nonce={nonce}  tx={accept_tx['id']}"))

    if cfg.dry_run:
        print(warn("  [DRY RUN] would POST /api/tx (AcceptJob)"))
    else:
        try:
            resp = post_json(f"{cfg.base_url}/api/tx", accept_tx)
            if resp.get("status") != "ok":
                print(fail(f"  AcceptJob rejected: {resp.get('error', resp)}"))
                _nonce -= 1  # rewind nonce on failure
                return False
            wait_for_tx(cfg.base_url, accept_tx["id"])
            print(ok(f"  AcceptJob committed  tx={accept_tx['id']}"))
        except Exception as e:
            print(fail(f"  AcceptJob failed: {e}"))
            return False

    # ── Step 2: Execute workload ───────────────────────────────────────────
    print(info(f"  Executing workload type={job.get('workload_type', '?')}"))
    output_hash, stats = execute_workload(job)
    print(ok(f"  Workload done  output_hash={output_hash[:16]}…"))

    # ── Step 3: CompleteJob ────────────────────────────────────────────────
    receipt_id = f"rcpt-{uuid.uuid4().hex[:12]}"
    stats_json = json.dumps(stats)
    nonce = next_nonce(cfg.base_url, cfg.sender)
    complete_tx = tx_complete_job(
        cfg.sender, nonce, job_id, cfg.machine_id,
        output_hash, receipt_id, stats_json,
    )
    print(info(f"  Submitting CompleteJob  receipt={receipt_id}  tx={complete_tx['id']}"))

    if cfg.dry_run:
        print(warn("  [DRY RUN] would POST /api/tx (CompleteJob)"))
        print(ok(f"  [DRY RUN] Job {job_id} would be completed"))
        print(f"  output_hash: {output_hash}")
        print(f"  receipt_id:  {receipt_id}")
        return True
    else:
        try:
            resp = post_json(f"{cfg.base_url}/api/tx", complete_tx)
            if resp.get("status") != "ok":
                print(fail(f"  CompleteJob rejected: {resp.get('error', resp)}"))
                return False
            wait_for_tx(cfg.base_url, complete_tx["id"])
            print(ok(f"  CompleteJob committed  tx={complete_tx['id']}"))
            print(ok(f"  Job {job_id} → Completed  output_hash={output_hash[:16]}…  receipt={receipt_id}"))
            # Print for the test script to capture
            print(f"CAROL_OUTPUT_HASH={output_hash}")
            print(f"CAROL_RECEIPT_ID={receipt_id}")
            return True
        except Exception as e:
            print(fail(f"  CompleteJob failed: {e}"))
            return False


def run_daemon(cfg: Config) -> None:
    print(f"\n{BOLD}Carol Resource Node Daemon{RESET}")
    print(f"  node:       {cfg.base_url}")
    print(f"  machine_id: {cfg.machine_id}")
    print(f"  sender:     {cfg.sender}")
    print(f"  poll:       {cfg.poll_s}s")
    if cfg.dry_run:
        print(f"  {YELLOW}DRY RUN mode — no txs will be submitted{RESET}")
    print()

    # Initial nonce fetch
    refresh_nonce(cfg.base_url, cfg.sender)
    print(info(f"Initial nonce for {cfg.sender}: {_nonce}"))
    print(info("Polling for jobs…\n"))

    processed = set()

    while True:
        try:
            jobs = get_json(f"{cfg.base_url}/api/jobs?state=Created")
            if not isinstance(jobs, list):
                jobs = []
        except Exception as e:
            print(warn(f"[{now()}] Poll error: {e}"))
            time.sleep(cfg.poll_s)
            continue

        for job in jobs:
            job_id     = job.get("job_id", "")
            machine_id = job.get("machine_id", "")
            if not job_id or job_id in processed:
                continue
            if machine_id != cfg.machine_id:
                continue

            processed.add(job_id)
            success = process_job(cfg, job)
            if cfg.once:
                sys.exit(0 if success else 1)

        time.sleep(cfg.poll_s)


# ── Entry point ────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Carol's Phase 0 resource node daemon"
    )
    parser.add_argument(
        "--node", default=os.environ.get("CAROL_NODE_URL", "http://127.0.0.1:8080"),
        help="Node base URL (http://HOST:PORT)"
    )
    parser.add_argument(
        "--machine",
        default=os.environ.get("CAROL_MACHINE_ID", "carol-machine-1"),
        help="Carol's machine_id registered on-chain",
    )
    parser.add_argument(
        "--sender",
        default=os.environ.get("CAROL_SENDER", "qcb1carol"),
        help="Carol's on-chain address",
    )
    parser.add_argument(
        "--poll", type=float, default=2.0,
        help="Seconds between job polls (default 2)",
    )
    parser.add_argument(
        "--once", action="store_true",
        help="Process at most one matching job then exit (for tests)",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Print what would happen without submitting txs",
    )
    args = parser.parse_args()

    # Normalise node URL: strip trailing slash, ensure http://
    node_url = args.node.rstrip("/")
    if not node_url.startswith("http"):
        node_url = f"http://{node_url}"

    # Quick sanity check that the node is reachable.
    try:
        get_json(f"{node_url}/api/status", timeout=5)
        print(ok(f"Node reachable: {node_url}"))
    except Exception as e:
        print(fail(f"Cannot reach node at {node_url}: {e}"))
        print(warn("Is the chain-forge-node running?"))
        sys.exit(1)

    cfg = Config(
        base_url=node_url,
        machine_id=args.machine,
        sender=args.sender,
        poll_s=args.poll,
        once=args.once,
        dry_run=args.dry_run,
    )

    try:
        run_daemon(cfg)
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Carol daemon stopped.{RESET}")
        sys.exit(0)


if __name__ == "__main__":
    main()
