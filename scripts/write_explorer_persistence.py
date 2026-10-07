#!/usr/bin/env python3
"""
write_explorer_persistence.py — QCB Chain Explorer Data Bridge

Polls the live devnet node REST API every few seconds and writes JSON
snapshot files to a data/ directory. The React frontend at
C:\Dev\chain-forge-frontend reads these files to show live chain state.

Usage:
    python3 write_explorer_persistence.py [--port PORT] [--out DIR] [--interval SECS]

Defaults:
    --port     8080       (Alice's API port on Machine 1)
    --out      ./data     (output directory)
    --interval 3          (seconds between polls)

The script polls all three node ports (Alice: 8080, Bob: 8081, Dave: 8082)
and merges their views. The highest-height node wins for block data.

Output files:
    data/status.json      — node health + chain height
    data/blocks.json      — recent blocks (last 50), newest first
    data/accounts.json    — all account balances + nonces
    data/qrc.json         — QRC economic metrics
    data/peers.json       — peer list
    data/gc_receipts.json — Grand Challenge receipts (newest first)
    data/meta.json        — last-updated timestamp, which node responded
"""

import argparse
import json
import os
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone

# ── Config ────────────────────────────────────────────────────────────────

NODE_PORTS = [8080, 8081, 8082]   # Alice, Bob, Dave on Machine 1
DEFAULT_HOST     = "127.0.0.1"
DEFAULT_OUT_DIR  = "./data"
DEFAULT_INTERVAL = 3              # seconds
TIMEOUT_SECS     = 4             # per-request timeout
MAX_BLOCKS       = 50            # how many recent blocks to keep in output

# ── Helpers ───────────────────────────────────────────────────────────────

def fetch_json(host: str, port: int, path: str) -> dict | list | None:
    """GET http://host:port/path  → parsed JSON, or None on any error."""
    url = f"http://{host}:{port}{path}"
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECS) as resp:
            raw = resp.read()
            return json.loads(raw)
    except Exception:
        return None


def write_json(path: str, data) -> None:
    """Atomically write JSON to path (write temp file, then rename)."""
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)


def best_node(host: str, ports: list[int]) -> tuple[int | None, dict | None]:
    """
    Try each port; return (port, status_json) for the node at the highest
    committed height.  Returns (None, None) if no node responds.
    """
    best_port   = None
    best_status = None
    best_height = -1

    for port in ports:
        s = fetch_json(host, port, "/api/status")
        if s is None:
            continue
        height = s.get("height", -1)
        if height > best_height:
            best_height = height
            best_port   = port
            best_status = s

    return best_port, best_status


def collect_all_blocks(host: str, ports: list[int]) -> list:
    """
    Collect blocks from all responding nodes, deduplicate by height, sort
    newest-first, keep MAX_BLOCKS.
    """
    by_height = {}
    for port in ports:
        blocks = fetch_json(host, port, "/api/blocks")
        if not isinstance(blocks, list):
            continue
        for b in blocks:
            h = b.get("height", -1)
            if h not in by_height:
                by_height[h] = b
    sorted_blocks = sorted(by_height.values(), key=lambda b: b.get("height", 0), reverse=True)
    return sorted_blocks[:MAX_BLOCKS]


def collect_accounts(host: str, port: int) -> list:
    """Get all accounts from the best node."""
    data = fetch_json(host, port, "/api/accounts")
    if isinstance(data, list):
        return data
    return []


def collect_qrc(host: str, port: int) -> dict:
    """Get QRC metrics from the best node."""
    data = fetch_json(host, port, "/api/qrc")
    if isinstance(data, dict):
        return data
    return {}


def collect_peers(host: str, port: int) -> list:
    """Get peer list from the best node."""
    data = fetch_json(host, port, "/api/peers")
    if isinstance(data, list):
        return data
    return []


def collect_gc_receipts(host: str, ports: list[int]) -> list:
    """
    Collect Grand Challenge receipts from all responding nodes,
    deduplicate by receipt_id, sort newest-first.
    """
    by_id: dict = {}
    for port in ports:
        receipts = fetch_json(host, port, "/api/gc-receipts")
        if not isinstance(receipts, list):
            continue
        for r in receipts:
            rid = r.get("receipt_id", "")
            if rid and rid not in by_id:
                by_id[rid] = r
    # Sort by timestamp_utc descending (string sort works for ISO 8601)
    return sorted(by_id.values(), key=lambda r: r.get("timestamp_utc", ""), reverse=True)


# ── Main poll loop ────────────────────────────────────────────────────────

def run(host: str, ports: list[int], out_dir: str, interval: float) -> None:
    os.makedirs(out_dir, exist_ok=True)
    print(f"[QCB Explorer Persistence] Polling {host} ports {ports}")
    print(f"  Output:   {os.path.abspath(out_dir)}/")
    print(f"  Interval: {interval}s")
    print()

    consecutive_failures = 0

    while True:
        try:
            t0 = time.monotonic()

            port, status = best_node(host, ports)

            if port is None:
                consecutive_failures += 1
                msg = f"[{now()}] ⚠  No node responding (attempt {consecutive_failures})"
                print(msg, flush=True)

                # Write a degraded status file so the frontend shows "offline"
                write_json(os.path.join(out_dir, "meta.json"), {
                    "last_updated": now(),
                    "status": "offline",
                    "consecutive_failures": consecutive_failures,
                })
                time.sleep(interval)
                continue

            consecutive_failures = 0
            height = status.get("height", 0)

            # Collect data from the best node (blocks + gc_receipts: merge all nodes)
            blocks      = collect_all_blocks(host, ports)
            accounts    = collect_accounts(host, port)
            qrc         = collect_qrc(host, port)
            peers       = collect_peers(host, port)
            gc_receipts = collect_gc_receipts(host, ports)

            # Write snapshot files
            write_json(os.path.join(out_dir, "status.json"),      status)
            write_json(os.path.join(out_dir, "blocks.json"),      blocks)
            write_json(os.path.join(out_dir, "accounts.json"),    accounts)
            write_json(os.path.join(out_dir, "qrc.json"),         qrc)
            write_json(os.path.join(out_dir, "peers.json"),       peers)
            write_json(os.path.join(out_dir, "gc_receipts.json"), gc_receipts)
            write_json(os.path.join(out_dir, "meta.json"), {
                "last_updated":      now(),
                "status":            "online",
                "best_port":         port,
                "height":            height,
                "block_count":       len(blocks),
                "account_count":     len(accounts),
                "gc_receipt_count":  len(gc_receipts),
            })

            elapsed = time.monotonic() - t0
            print(
                f"[{now()}] ✓  height={height}  blocks={len(blocks)}"
                f"  accounts={len(accounts)}  gc_receipts={len(gc_receipts)}"
                f"  ({elapsed*1000:.0f}ms)",
                flush=True,
            )

        except KeyboardInterrupt:
            print("\n[QCB Explorer Persistence] Stopped.")
            break
        except Exception as e:
            print(f"[{now()}] ERROR: {e}", flush=True)

        time.sleep(interval)


def now() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S UTC")


# ── Entry point ───────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Poll QCB devnet nodes and write explorer JSON snapshots."
    )
    parser.add_argument("--host",     default=DEFAULT_HOST,     help="Node host (default: 127.0.0.1)")
    parser.add_argument("--ports",    default=",".join(str(p) for p in NODE_PORTS),
                        help="Comma-separated ports (default: 8080,8081,8082)")
    parser.add_argument("--out",      default=DEFAULT_OUT_DIR,  help="Output directory (default: ./data)")
    parser.add_argument("--interval", default=DEFAULT_INTERVAL, type=float,
                        help="Poll interval in seconds (default: 3)")
    args = parser.parse_args()

    ports = [int(p.strip()) for p in args.ports.split(",")]
    run(args.host, ports, args.out, args.interval)


if __name__ == "__main__":
    main()
