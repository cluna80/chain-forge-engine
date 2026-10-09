#!/usr/bin/env python3
"""
pocd_miner.py — Continuous PoCD miner for the QCB devnet / testnet.

Polls for active challenges, mines SHA256 seals, and submits proofs in a
loop.  Run one instance per machine; pass --node to target the local node.

Usage:
  python3 scripts/pocd_miner.py --node alice          # mines on :8080
  python3 scripts/pocd_miner.py --node bob            # mines on :8081
  python3 scripts/pocd_miner.py --node dave           # mines on :8082
  python3 scripts/pocd_miner.py --node alice --once   # single proof then exit

Options:
  --node     alice | bob | dave | <host:port>  (default: alice)
  --machine  machine-id tag embedded in each proof  (default: auto from node)
  --once     mine and submit exactly one proof then exit
  --verbose  print every failed seal attempt batch count
  --track    prefer this challenge track (default: Mathematics)

Requirements:
  Python 3.8+ stdlib only (hashlib, struct, http.client, json, time, random)

Stop: Ctrl+C
"""

import argparse
import hashlib
import http.client
import json
import random
import string
import struct
import sys
import time

# ── Node map ─────────────────────────────────────────────────────────────────

NODE_MAP = {
    "alice": ("127.0.0.1", 8080),
    "bob":   ("127.0.0.1", 8081),
    "dave":  ("127.0.0.1", 8082),
}

# Batch size for inner mining loop (tune for your CPU)
HASH_BATCH = 4_096

# Max attempts before giving up on a single seal (then we re-poll challenges)
MAX_SEAL_ATTEMPTS = 1_000_000

# How long to wait between challenge polls when no challenges are active (s)
POLL_INTERVAL = 15

# Colours
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"
PASS   = f"{GREEN}✓{RESET}"
FAIL   = f"{RED}✗{RESET}"
INFO   = f"{CYAN}·{RESET}"


# ── Crypto helpers ────────────────────────────────────────────────────────────

def compute_seal_hash(seal_nonce: int, output_hash_hex: str, challenge_id: str) -> str:
    """SHA256(seal_nonce_be8 || output_hash_bytes || challenge_id_bytes)"""
    nonce_bytes       = struct.pack(">Q", seal_nonce)
    output_hash_bytes = bytes.fromhex(output_hash_hex)
    return hashlib.sha256(
        nonce_bytes + output_hash_bytes + challenge_id.encode()
    ).hexdigest()


def meets_difficulty(seal_hash_hex: str, difficulty_bits: int) -> bool:
    if difficulty_bits == 0:
        return True
    full_nibbles = difficulty_bits // 4
    rem_bits     = difficulty_bits % 4
    need = full_nibbles + (1 if rem_bits else 0)
    if len(seal_hash_hex) < need:
        return False
    for ch in seal_hash_hex[:full_nibbles]:
        if ch != "0":
            return False
    if rem_bits:
        nibble = int(seal_hash_hex[full_nibbles], 16)
        if (nibble >> (4 - rem_bits)) != 0:
            return False
    return True


def find_seal(output_hash_hex: str, challenge_id: str, difficulty_bits: int):
    """
    Mine a valid seal.
    Returns (nonce, seal_hash_hex, attempts) or raises RuntimeError on cap.
    """
    start    = random.randint(0, 2**48)
    attempts = 0
    while attempts < MAX_SEAL_ATTEMPTS:
        batch_end = min(attempts + HASH_BATCH, MAX_SEAL_ATTEMPTS)
        for i in range(attempts, batch_end):
            nonce = (start + i) & 0xFFFFFFFFFFFFFFFF
            seal  = compute_seal_hash(nonce, output_hash_hex, challenge_id)
            if meets_difficulty(seal, difficulty_bits):
                return nonce, seal, i + 1
        attempts = batch_end
    raise RuntimeError(
        f"seal not found after {MAX_SEAL_ATTEMPTS} attempts (difficulty={difficulty_bits})"
    )


def random_output_hash() -> str:
    """Simulated work output — random SHA256 (replace with real work in production)."""
    seed = "".join(random.choices(string.ascii_letters + string.digits, k=64))
    return hashlib.sha256(seed.encode()).hexdigest()


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def http_get(host: str, port: int, path: str):
    try:
        conn = http.client.HTTPConnection(host, port, timeout=10)
        conn.request("GET", path)
        resp = conn.getresponse()
        raw  = resp.read().decode()
        conn.close()
        try:
            return json.loads(raw), resp.status
        except json.JSONDecodeError:
            return raw, resp.status
    except Exception as e:
        return None, -1


def http_post(host: str, port: int, path: str, payload: dict):
    try:
        body = json.dumps(payload).encode()
        conn = http.client.HTTPConnection(host, port, timeout=10)
        conn.request(
            "POST", path, body=body,
            headers={"Content-Type": "application/json"}
        )
        resp = conn.getresponse()
        raw  = resp.read().decode()
        conn.close()
        try:
            return json.loads(raw), resp.status
        except json.JSONDecodeError:
            return raw, resp.status
    except Exception as e:
        return None, -1


# ── Miner state ───────────────────────────────────────────────────────────────

class MinerStats:
    def __init__(self):
        self.start_time     = time.time()
        self.proofs_ok      = 0
        self.proofs_fail    = 0
        self.total_hashes   = 0
        self.last_proof_ts  = None
        self.last_proof_id  = None
        self._seq           = 0   # monotonic counter — guarantees unique proof IDs

    def next_seq(self) -> int:
        self._seq += 1
        return self._seq

    def runtime(self) -> float:
        return time.time() - self.start_time

    def hash_rate(self) -> float:
        rt = self.runtime()
        return self.total_hashes / rt if rt > 0 else 0.0

    def print_banner(self, host, port, machine_id):
        print()
        print(f"{BOLD}{'=' * 68}{RESET}")
        print(f"{BOLD}  QCB PoCD Continuous Miner{RESET}")
        print(f"  Node      : {host}:{port}")
        print(f"  Machine   : {machine_id}")
        print(f"  Started   : {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
        print(f"{BOLD}{'=' * 68}{RESET}")
        print()

    def print_status(self):
        rt  = self.runtime()
        hrs = int(rt // 3600)
        mns = int((rt % 3600) // 60)
        scs = int(rt % 60)
        hr  = self.hash_rate()
        hr_str = f"{hr/1000:.1f} kH/s" if hr >= 1000 else f"{hr:.0f} H/s"
        print(
            f"  {INFO}  runtime={hrs:02d}:{mns:02d}:{scs:02d}  "
            f"proofs={BOLD}{self.proofs_ok}{RESET}  "
            f"failed={self.proofs_fail}  "
            f"hashrate={hr_str}  "
            f"total_hashes={self.total_hashes:,}"
        )


# ── Core mining loop ──────────────────────────────────────────────────────────

def pick_challenge(challenges: list, preferred_track: str):
    """Return the best challenge to mine: preferred track first, else first active."""
    active = [c for c in challenges if c.get("status") == "Active"]
    if not active:
        return None
    for c in active:
        if c.get("track") == preferred_track:
            return c
    return active[0]


def mine_one_proof(
    host: str,
    port: str,
    machine_id: str,
    challenge: dict,
    stats: MinerStats,
    verbose: bool,
) -> bool:
    """
    Mine and submit one proof for `challenge`.
    Returns True on accepted, False on any failure.
    """
    challenge_id = challenge["challenge_id"]
    difficulty   = challenge.get("seal_difficulty_bits", 4)
    output_hash  = random_output_hash()
    input_hash   = random_output_hash()

    t0 = time.time()
    try:
        nonce, seal_hash, attempts = find_seal(output_hash, challenge_id, difficulty)
    except RuntimeError as e:
        print(f"  {FAIL}  seal cap hit: {e}")
        return False

    elapsed = time.time() - t0
    stats.total_hashes += attempts

    proof_id = f"proof-{machine_id}-{int(time.time() * 1000)}-{stats.next_seq()}"

    proof = {
        "proof_id":             proof_id,
        "challenge_id":         challenge_id,
        "machine_id":           machine_id,
        "output_hash":          output_hash,
        "input_hash":           input_hash,
        "methodology_ref":      "ipfs://bafybeiqcbminer",
        "discovery_nonce":      random.randint(0, 2**32),
        "checks_performed":     attempts,
        "elapsed_seconds":      elapsed,
        "timestamp_utc":        time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "machine_signature":    "devnet-no-sig",
        "seal_nonce":           nonce,
        "seal_hash":            seal_hash,
        "seal_difficulty_bits": difficulty,
    }

    data, status = http_post(host, port, "/api/pocd/submit", proof)
    accepted = (
        status == 200
        and isinstance(data, dict)
        and data.get("status") == "accepted"
    )

    hr = attempts / elapsed if elapsed > 0 else 0
    hr_str = f"{hr/1000:.1f} kH/s" if hr >= 1000 else f"{hr:.0f} H/s"

    if accepted:
        stats.proofs_ok    += 1
        stats.last_proof_ts = time.time()
        stats.last_proof_id = proof_id
        print(
            f"  {PASS}  proof #{stats.proofs_ok}  "
            f"challenge={challenge_id.split('::')[-1]}  "
            f"seal={seal_hash[:12]}…  "
            f"attempts={attempts:,}  "
            f"time={elapsed:.3f}s  "
            f"rate={hr_str}"
        )
        if verbose:
            print(f"       proof_id = {proof_id}")
    else:
        stats.proofs_fail += 1
        print(
            f"  {FAIL}  proof rejected  "
            f"status={status}  "
            f"response={data}"
        )

    return accepted


def run_miner(
    host: str,
    port: int,
    machine_id: str,
    preferred_track: str,
    once: bool,
    verbose: bool,
):
    stats = MinerStats()
    stats.print_banner(host, port, machine_id)

    # ── 1. Health check ───────────────────────────────────────────────────────
    data, status = http_get(host, port, "/api/status")
    if status != 200:
        print(f"{FAIL}  Node {host}:{port} not reachable — start devnet first.")
        print("       ./scripts/start-devnet-local.sh --clean")
        sys.exit(1)
    chain_id = data.get("chain_id", "?") if isinstance(data, dict) else "?"
    height   = data.get("height", "?")   if isinstance(data, dict) else "?"
    print(f"  {PASS}  Node online  chain={chain_id}  height={height}")
    print()

    status_tick = time.time()

    while True:
        # ── 2. Fetch active challenges ────────────────────────────────────────
        cdata, cstatus = http_get(host, port, "/api/pocd/challenges")
        if cstatus != 200 or not cdata:
            print(f"  {YELLOW}·{RESET}  No challenges available (status={cstatus}) — "
                  f"retrying in {POLL_INTERVAL}s …")
            try:
                time.sleep(POLL_INTERVAL)
            except KeyboardInterrupt:
                break
            continue

        if isinstance(cdata, dict) and cdata.get("status") == "disabled":
            print(f"  {FAIL}  PoCD disabled on this node — add 'pocd' section to genesis.json")
            sys.exit(1)

        challenge = pick_challenge(cdata, preferred_track)
        if challenge is None:
            print(f"  {YELLOW}·{RESET}  No active challenges — waiting {POLL_INTERVAL}s …")
            try:
                time.sleep(POLL_INTERVAL)
            except KeyboardInterrupt:
                break
            continue

        # ── 3. Mine + submit ──────────────────────────────────────────────────
        try:
            mine_one_proof(host, port, machine_id, challenge, stats, verbose)
        except KeyboardInterrupt:
            break

        # Print periodic status line every 10 proofs or 60 s
        now = time.time()
        if stats.proofs_ok % 10 == 0 or (now - status_tick) > 60:
            stats.print_status()
            status_tick = now

        if once:
            break

    # ── Summary ───────────────────────────────────────────────────────────────
    print()
    print(f"{BOLD}{'=' * 68}{RESET}")
    print(f"  {PASS}  Miner stopped")
    stats.print_status()
    if stats.last_proof_id:
        print(f"  Last accepted proof : {stats.last_proof_id}")
    print(f"{BOLD}{'=' * 68}{RESET}")
    print()


# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description="QCB PoCD continuous miner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--node", default="alice",
        help="alice | bob | dave | host:port  (default: alice → 127.0.0.1:8080)",
    )
    p.add_argument(
        "--machine", default=None,
        help="machine-id tag in proofs (default: derived from --node)",
    )
    p.add_argument(
        "--track", default="Mathematics",
        help="preferred challenge track (default: Mathematics)",
    )
    p.add_argument(
        "--once", action="store_true",
        help="mine and submit exactly one proof then exit",
    )
    p.add_argument(
        "--verbose", action="store_true",
        help="print extra detail per proof",
    )
    return p.parse_args()


def resolve_node(node_arg: str):
    """Return (host, port) from a name or host:port string."""
    low = node_arg.lower()
    if low in NODE_MAP:
        return NODE_MAP[low]
    # Try host:port
    if ":" in node_arg:
        host, port_str = node_arg.rsplit(":", 1)
        try:
            return host, int(port_str)
        except ValueError:
            pass
    print(f"{FAIL}  Unknown node '{node_arg}'. Use alice, bob, dave, or host:port.")
    sys.exit(1)


if __name__ == "__main__":
    args = parse_args()
    host, port = resolve_node(args.node)

    machine_id = args.machine or f"qcb1devminer-{args.node.lower()}"

    try:
        run_miner(
            host=host,
            port=port,
            machine_id=machine_id,
            preferred_track=args.track,
            once=args.once,
            verbose=args.verbose,
        )
    except KeyboardInterrupt:
        print("\n  Interrupted — exiting.")
        sys.exit(0)
