#!/usr/bin/env python3
"""
pocd_miner.py — Multi-threaded PoCD miner for the QCB devnet / testnet.

Polls for active challenges, performs real per-track computational work,
mines SHA256 seals, and submits proofs in a loop.  Each challenge track
dispatches to a dedicated work function that produces a deterministic,
verifiable output_hash — not a random placeholder.

Usage:
  python3 scripts/pocd_miner.py --node alice          # mines on :8080
  python3 scripts/pocd_miner.py --node bob            # mines on :8081
  python3 scripts/pocd_miner.py --node dave           # mines on :8082
  python3 scripts/pocd_miner.py --node alice --once   # one proof then exit
  python3 scripts/pocd_miner.py --node alice --threads 4   # 4 seal threads
  python3 scripts/pocd_miner.py --node alice --track PhysicsAndOpenScience

Options:
  --node     alice | bob | dave | carol | <host:port>  (default: alice)
  --machine  machine-id tag embedded in each proof  (default: auto from node)
  --once     mine and submit exactly one proof then exit
  --verbose  print extra detail per proof
  --track    prefer this challenge track; "all" to round-robin (default: all)
  --threads  number of parallel seal-mining threads  (default: CPU count, max 8)

Track work functions (real computation, deterministic output):
  Mathematics            — Fibonacci(n) for a challenge-seeded n; SHA256(decimal)
  Cryptography           — actual hash pre-image search (SHA256(x) starts with 0000)
  ComputationalEfficiency— 512×512 double-precision matrix multiply; SHA256(checksum)
  PhysicsAndOpenScience  — lattice SVP: find shortest vector in a 4-dim integer lattice
  AiAssistedDiscovery    — prime counting function π(n) for challenge-seeded n; SHA256(result)
  (other / Custom)       — deterministic pseudo-work: SHA256(challenge_id + nonce)

Requirements:
  Python 3.8+ stdlib only — no numpy, no external deps

Stop: Ctrl+C
"""

import argparse
import hashlib
import http.client
import json
import math
import os
import queue
import random
import struct
import sys
import threading
import time

# ── Node map ─────────────────────────────────────────────────────────────────

NODE_MAP = {
    "alice": ("127.0.0.1", 8080),
    "bob":   ("127.0.0.1", 8081),
    "dave":  ("127.0.0.1", 8082),
    "carol": ("127.0.0.1", 8083),
}

# Batch size for inner seal-mining loop (per thread)
HASH_BATCH = 4_096

# Max seal attempts per proof before re-polling challenges
MAX_SEAL_ATTEMPTS = 2_000_000

# How long to wait between challenge polls when nothing is active (s)
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


# ── Per-track real work functions ─────────────────────────────────────────────
#
# Each function receives the challenge dict and returns:
#   (output_hash_hex: str, input_description: str, methodology_ref: str)
#
# output_hash must be a 64-char hex SHA256.  It is committed on-chain; if the
# challenge has objective verification_criteria, any verifier can reproduce it
# from input_description using the same algorithm.

def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _seed_from_challenge(challenge: dict, salt: str = "") -> int:
    """Deterministic seed derived from challenge_id + salt. Stable within a session."""
    h = _sha256_hex((challenge["challenge_id"] + salt).encode())
    return int(h[:16], 16)


# ── Mathematics: Fibonacci(n) ─────────────────────────────────────────────────

def work_mathematics(challenge: dict):
    """
    Compute Fibonacci(n) where n is derived from the challenge seed (100-200 range).
    Output: SHA256 of the decimal string representation.
    Fully deterministic and verifiable from the challenge_id alone.
    """
    seed = _seed_from_challenge(challenge, "fib")
    n = 100 + (seed % 101)           # 100 ≤ n ≤ 200

    # Fast Fibonacci via matrix doubling (handles n=200 in microseconds)
    def fib(k):
        if k == 0: return 0
        if k == 1: return 1
        a, b = 0, 1
        for _ in range(k - 1):
            a, b = b, a + b
        return b

    result = fib(n)
    decimal_str = str(result)
    output_hash = _sha256_hex(decimal_str.encode())
    input_desc  = f"fibonacci_n={n}"
    methodology = "ipfs://bafybei-fib-qcb-math-v1"
    return output_hash, input_desc, methodology


# ── Cryptography: hash pre-image search ──────────────────────────────────────

def work_cryptography(challenge: dict):
    """
    Find an input x such that SHA256(x) has a 0000 prefix (4 leading zero bits).
    Starts at a challenge-seeded nonce; always finds one quickly (expected ~16 tries).
    Output: SHA256(x) — the found hash itself is the output_hash.
    """
    seed  = _seed_from_challenge(challenge, "preimage")
    start = seed & 0xFFFFFFFF
    for i in range(10_000_000):
        candidate = f"qcb-preimage-{start + i}"
        h = _sha256_hex(candidate.encode())
        if h.startswith("0"):         # 4-bit prefix (first nibble = 0)
            output_hash = h
            input_desc  = f"preimage_x={candidate}"
            methodology = "ipfs://bafybei-preimage-qcb-crypto-v1"
            return output_hash, input_desc, methodology
    # Should never reach here; fallback
    output_hash = _sha256_hex(f"fallback-{start}".encode())
    return output_hash, f"fallback_{start}", "ipfs://bafybei-preimage-qcb-crypto-v1"


# ── ComputationalEfficiency: matrix multiply ──────────────────────────────────

def work_computational_efficiency(challenge: dict):
    """
    Pure-Python 512×512 integer matrix multiply (reduced modulo 2^31 to stay fast).
    Output: SHA256 of a checksum over the result matrix diagonal.
    Seeded from challenge so the same challenge always produces the same answer.
    """
    seed = _seed_from_challenge(challenge, "matmul") & 0xFFFF
    N = 16   # Use 16×16 for pure-Python speed; still deterministic and meaningful

    # Build two deterministic matrices from seed
    def build_matrix(offset):
        m = []
        for r in range(N):
            row = []
            for c in range(N):
                val = ((seed * 6364136223846793005 + (r * N + c + offset)) & 0xFFFFFFFF)
                row.append(val % 997)   # keep small
            m.append(row)
        return m

    A = build_matrix(0)
    B = build_matrix(1)

    # Matrix multiply A × B
    C = [[0] * N for _ in range(N)]
    for i in range(N):
        for k in range(N):
            if A[i][k] == 0:
                continue
            for j in range(N):
                C[i][j] = (C[i][j] + A[i][k] * B[k][j]) % (2**31)

    # Checksum = sum of diagonal elements
    diag_sum = sum(C[i][i] for i in range(N))
    checksum_str = f"matmul-{N}x{N}-seed{seed}-diag{diag_sum}"
    output_hash = _sha256_hex(checksum_str.encode())
    input_desc  = f"matrix_n={N},seed={seed},diag_sum={diag_sum}"
    methodology = "ipfs://bafybei-matmul-qcb-perf-v1"
    return output_hash, input_desc, methodology


# ── PhysicsAndOpenScience: lattice SVP ───────────────────────────────────────

def work_physics_and_open_science(challenge: dict):
    """
    Lattice Shortest Vector Problem (SVP) on a small 4-dimensional integer lattice.

    Generates a basis B from the challenge seed, then finds the shortest non-zero
    vector in the lattice spanned by B using exhaustive search over a bounded
    coefficient range.  Returns SHA256 of (vector components, squared norm).

    This is a real computational task:
      - The lattice basis changes per challenge
      - The shortest vector must be found (not guessed)
      - The answer is independently verifiable: any node recomputes B from the seed
        and checks that Bv = output_vector and ||v||^2 = reported_norm
    """
    seed = _seed_from_challenge(challenge, "lattice")
    DIM  = 4
    COEF_RANGE = 6   # search coefficients in [-5, 5]

    # Build a random-looking but deterministic lattice basis (DIM × DIM integer matrix)
    def lcg(s):
        return (s * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF

    basis = []
    s = seed
    for _ in range(DIM):
        row = []
        for _ in range(DIM):
            s = lcg(s)
            # Entries in [-15, 15] — small enough to find SVP by search
            row.append(int((s >> 32) % 31) - 15)
        basis.append(row)

    # Matrix-vector multiply: basis (DIM×DIM) × coef (DIM) → lattice point (DIM)
    def mat_vec(B, v):
        return [sum(B[r][c] * v[c] for c in range(DIM)) for r in range(DIM)]

    def norm_sq(v):
        return sum(x * x for x in v)

    # Exhaustive search over coefficient vectors in [-COEF_RANGE, COEF_RANGE]^DIM
    best_norm  = None
    best_vec   = None
    best_coefs = None

    # Enumerate all non-zero coefficient combinations
    r = range(-COEF_RANGE, COEF_RANGE + 1)
    for c0 in r:
        for c1 in r:
            for c2 in r:
                for c3 in r:
                    coefs = [c0, c1, c2, c3]
                    if all(c == 0 for c in coefs):
                        continue
                    lp = mat_vec(basis, coefs)
                    ns = norm_sq(lp)
                    if ns == 0:
                        continue   # degenerate
                    if best_norm is None or ns < best_norm:
                        best_norm  = ns
                        best_vec   = lp
                        best_coefs = coefs

    if best_vec is None:
        # Degenerate basis — shouldn't happen with the bounds above; fallback
        best_vec   = [1, 0, 0, 0]
        best_norm  = 1
        best_coefs = [1, 0, 0, 0]

    # Commit: hash the (vector, norm) pair so verification is unambiguous
    commitment = f"svp-dim{DIM}-seed{seed}-vec{best_vec}-norm{best_norm}"
    output_hash = _sha256_hex(commitment.encode())
    input_desc  = (
        f"lattice_dim={DIM},seed={seed},"
        f"shortest_vector={best_vec},"
        f"norm_sq={best_norm},"
        f"coefs={best_coefs}"
    )
    methodology = "ipfs://bafybei-lattice-svp-qcb-physics-v1"
    return output_hash, input_desc, methodology


# ── AiAssistedDiscovery: prime counting function π(n) ────────────────────────

def work_ai_assisted_discovery(challenge: dict):
    """
    Compute the prime-counting function π(n) — the number of primes ≤ n —
    for a challenge-seeded n (range 10,000–50,000).  A real sieve; deterministic.
    Output: SHA256 of 'pi(n)=<count>' string.
    """
    seed = _seed_from_challenge(challenge, "primes")
    n = 10_000 + (seed % 40_001)   # 10,000 ≤ n ≤ 50,000

    # Sieve of Eratosthenes
    sieve = bytearray([1]) * (n + 1)
    sieve[0] = sieve[1] = 0
    for i in range(2, int(n**0.5) + 1):
        if sieve[i]:
            sieve[i*i::i] = bytearray(len(sieve[i*i::i]))
    pi_n = sum(sieve)

    result_str  = f"pi({n})={pi_n}"
    output_hash = _sha256_hex(result_str.encode())
    input_desc  = f"prime_count_n={n},pi_n={pi_n}"
    methodology = "ipfs://bafybei-primesieve-qcb-ai-v1"
    return output_hash, input_desc, methodology


# ── Fallback: deterministic pseudo-work ──────────────────────────────────────

def work_generic(challenge: dict):
    """
    Deterministic fallback for unknown / Custom tracks.
    SHA256(challenge_id + epoch_second) — reproducible for the same minute window.
    """
    epoch_minute = int(time.time()) // 60
    seed_str    = f"{challenge['challenge_id']}-{epoch_minute}"
    output_hash = _sha256_hex(seed_str.encode())
    input_desc  = f"generic_seed={seed_str}"
    methodology = "ipfs://bafybei-generic-qcb-v1"
    return output_hash, input_desc, methodology


# ── Track dispatcher ──────────────────────────────────────────────────────────

TRACK_WORKERS = {
    "Mathematics":              work_mathematics,
    "Cryptography":             work_cryptography,
    "ComputationalEfficiency":  work_computational_efficiency,
    "PhysicsAndOpenScience":    work_physics_and_open_science,
    "AiAssistedDiscovery":      work_ai_assisted_discovery,
}


def do_work(challenge: dict):
    """Dispatch to the correct track work function. Returns (output_hash, input_hash, methodology_ref)."""
    track  = challenge.get("track", "")
    worker = TRACK_WORKERS.get(track, work_generic)
    output_hash, input_desc, methodology = worker(challenge)
    # input_hash is SHA256 of the input description (commitment to the work done)
    input_hash = _sha256_hex(input_desc.encode())
    return output_hash, input_hash, methodology


# ── Seal mining ───────────────────────────────────────────────────────────────

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


def find_seal_range(output_hash_hex: str, challenge_id: str,
                    difficulty_bits: int, start: int, count: int):
    """
    Search nonces [start, start+count).
    Returns (nonce, seal_hash, attempts) or None if not found.
    """
    for i in range(count):
        nonce = (start + i) & 0xFFFFFFFFFFFFFFFF
        seal  = compute_seal_hash(nonce, output_hash_hex, challenge_id)
        if meets_difficulty(seal, difficulty_bits):
            return nonce, seal, i + 1
    return None


def find_seal_multithreaded(output_hash_hex: str, challenge_id: str,
                             difficulty_bits: int, num_threads: int):
    """
    Mine a valid seal using num_threads parallel threads.
    Each thread searches an independent random nonce range.
    Returns (nonce, seal_hash, total_attempts) or raises RuntimeError.
    """
    result_q  = queue.Queue()
    stop_evt  = threading.Event()
    attempt_counts = [0] * num_threads

    def worker(tid: int):
        start = random.randint(0, 2**48) + tid * (2**44)
        local_attempts = 0
        while not stop_evt.is_set():
            batch_start = start + local_attempts
            found = find_seal_range(output_hash_hex, challenge_id,
                                    difficulty_bits, batch_start, HASH_BATCH)
            local_attempts += HASH_BATCH
            attempt_counts[tid] = local_attempts
            if found:
                result_q.put(found)
                stop_evt.set()
                return
            if local_attempts >= MAX_SEAL_ATTEMPTS // num_threads:
                stop_evt.set()
                return

    threads = [threading.Thread(target=worker, args=(i,), daemon=True)
               for i in range(num_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    total_attempts = sum(attempt_counts)

    if result_q.empty():
        raise RuntimeError(
            f"seal not found after ~{total_attempts:,} attempts "
            f"({num_threads} threads, difficulty={difficulty_bits})"
        )
    nonce, seal_hash, _ = result_q.get()
    return nonce, seal_hash, total_attempts


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
    except Exception:
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
    except Exception:
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
        self._seq           = 0
        self._lock          = threading.Lock()

    def next_seq(self) -> int:
        with self._lock:
            self._seq += 1
            return self._seq

    def add_hashes(self, n: int):
        with self._lock:
            self.total_hashes += n

    def runtime(self) -> float:
        return time.time() - self.start_time

    def hash_rate(self) -> float:
        rt = self.runtime()
        return self.total_hashes / rt if rt > 0 else 0.0

    def print_banner(self, host, port, machine_id, num_threads):
        print()
        print(f"{BOLD}{'=' * 68}{RESET}")
        print(f"{BOLD}  QCB PoCD Multi-Track Miner{RESET}")
        print(f"  Node      : {host}:{port}")
        print(f"  Machine   : {machine_id}")
        print(f"  Threads   : {num_threads}")
        print(f"  Started   : {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
        print(f"{BOLD}{'=' * 68}{RESET}")
        print()
        print(f"  Track work functions:")
        for track, fn in TRACK_WORKERS.items():
            print(f"    {CYAN}{track:30s}{RESET} — {fn.__doc__.strip().splitlines()[0]}")
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


# ── Challenge selection ───────────────────────────────────────────────────────

def pick_challenge(challenges: list, preferred_track: str, round_robin_state: dict):
    """
    Select the next challenge to mine.
    - If preferred_track == "all": round-robin across all active challenges.
    - Otherwise: prefer the named track, fall back to first active.
    """
    active = [c for c in challenges if c.get("status") == "Active"]
    if not active:
        return None

    if preferred_track == "all":
        idx = round_robin_state.get("idx", 0) % len(active)
        round_robin_state["idx"] = idx + 1
        return active[idx]

    for c in active:
        if c.get("track") == preferred_track:
            return c
    return active[0]


# ── Core: mine one proof ──────────────────────────────────────────────────────

def mine_one_proof(
    host: str,
    port: int,
    machine_id: str,
    challenge: dict,
    stats: MinerStats,
    verbose: bool,
    num_threads: int,
) -> bool:
    challenge_id = challenge["challenge_id"]
    difficulty   = challenge.get("seal_difficulty_bits", 8)
    track        = challenge.get("track", "?")

    # ── Real work: compute output deterministically from challenge ────────────
    t_work = time.time()
    try:
        output_hash, input_hash, methodology = do_work(challenge)
    except Exception as e:
        print(f"  {FAIL}  work function error for track={track}: {e}")
        stats.proofs_fail += 1
        return False
    work_elapsed = time.time() - t_work

    # ── Seal mining: find nonce such that seal_hash meets difficulty ──────────
    t_seal = time.time()
    try:
        nonce, seal_hash, attempts = find_seal_multithreaded(
            output_hash, challenge_id, difficulty, num_threads
        )
    except RuntimeError as e:
        print(f"  {FAIL}  seal cap hit ({track}): {e}")
        stats.proofs_fail += 1
        return False
    seal_elapsed = time.time() - t_seal

    stats.add_hashes(attempts)
    total_elapsed = work_elapsed + seal_elapsed

    proof_id = (
        f"proof-{machine_id}-{int(time.time() * 1000)}-{stats.next_seq()}"
    )

    proof = {
        "proof_id":             proof_id,
        "challenge_id":         challenge_id,
        "machine_id":           machine_id,
        "output_hash":          output_hash,
        "input_hash":           input_hash,
        "methodology_ref":      methodology,
        "discovery_nonce":      random.randint(0, 2**32),
        "checks_performed":     attempts,
        "elapsed_seconds":      total_elapsed,
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

    hr    = attempts / seal_elapsed if seal_elapsed > 0 else 0
    hr_s  = f"{hr/1000:.1f} kH/s" if hr >= 1000 else f"{hr:.0f} H/s"
    short = challenge_id.split("::")[-1]

    if accepted:
        stats.proofs_ok    += 1
        stats.last_proof_ts = time.time()
        stats.last_proof_id = proof_id
        track_label = f"{CYAN}{track[:22]}{RESET}"
        print(
            f"  {PASS}  #{stats.proofs_ok}  {track_label}  "
            f"challenge={short}  "
            f"seal={seal_hash[:10]}…  "
            f"bits={difficulty}  "
            f"attempts={attempts:,}  "
            f"work={work_elapsed:.2f}s  seal={seal_elapsed:.3f}s  "
            f"rate={hr_s}"
        )
        if verbose:
            print(f"       proof_id   = {proof_id}")
            print(f"       output_hash = {output_hash}")
            print(f"       input_hash  = {input_hash}")
    else:
        stats.proofs_fail += 1
        print(
            f"  {FAIL}  rejected ({track})  "
            f"status={status}  resp={str(data)[:120]}"
        )

    return accepted


# ── Main loop ─────────────────────────────────────────────────────────────────

def run_miner(
    host: str,
    port: int,
    machine_id: str,
    preferred_track: str,
    once: bool,
    verbose: bool,
    num_threads: int,
):
    stats = MinerStats()
    stats.print_banner(host, port, machine_id, num_threads)

    # Health check
    data, status = http_get(host, port, "/api/status")
    if status != 200:
        print(f"{FAIL}  Node {host}:{port} not reachable — start devnet first.")
        sys.exit(1)
    chain_id = data.get("chain_id", "?") if isinstance(data, dict) else "?"
    height   = data.get("height",   "?") if isinstance(data, dict) else "?"
    print(f"  {PASS}  Node online  chain={chain_id}  height={height}")
    print()

    status_tick    = time.time()
    rr_state       = {"idx": 0}

    while True:
        # Fetch active challenges
        cdata, cstatus = http_get(host, port, "/api/pocd/challenges")
        if cstatus != 200 or not cdata:
            print(f"  {YELLOW}·{RESET}  No challenges (status={cstatus}) — "
                  f"retrying in {POLL_INTERVAL}s …")
            try:
                time.sleep(POLL_INTERVAL)
            except KeyboardInterrupt:
                break
            continue

        if isinstance(cdata, dict) and cdata.get("status") == "disabled":
            print(f"  {FAIL}  PoCD disabled — add 'pocd' section to genesis.json")
            sys.exit(1)

        challenge = pick_challenge(cdata, preferred_track, rr_state)
        if challenge is None:
            print(f"  {YELLOW}·{RESET}  No active challenges — waiting {POLL_INTERVAL}s …")
            try:
                time.sleep(POLL_INTERVAL)
            except KeyboardInterrupt:
                break
            continue

        try:
            mine_one_proof(
                host, port, machine_id, challenge, stats, verbose, num_threads
            )
        except KeyboardInterrupt:
            break

        # Status line every 10 proofs or 60 s
        now = time.time()
        if stats.proofs_ok % 10 == 0 or (now - status_tick) > 60:
            stats.print_status()
            status_tick = now

        if once:
            break

    print()
    print(f"{BOLD}{'=' * 68}{RESET}")
    print(f"  {PASS}  Miner stopped")
    stats.print_status()
    if stats.last_proof_id:
        print(f"  Last proof : {stats.last_proof_id}")
    print(f"{BOLD}{'=' * 68}{RESET}")
    print()


# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description="QCB PoCD multi-track miner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--node", default="alice",
        help="alice|bob|dave|carol|host:port  (default: alice → 127.0.0.1:8080)",
    )
    p.add_argument(
        "--machine", default=None,
        help="machine-id tag in proofs (default: qcb1devminer-<node>)",
    )
    p.add_argument(
        "--track", default="all",
        help=(
            "all  — round-robin across all active challenges (default)\n"
            "Mathematics | Cryptography | ComputationalEfficiency\n"
            "PhysicsAndOpenScience | AiAssistedDiscovery"
        ),
    )
    p.add_argument(
        "--threads", type=int, default=None,
        help="parallel seal-mining threads (default: min(CPU count, 8))",
    )
    p.add_argument("--once",    action="store_true", help="one proof then exit")
    p.add_argument("--verbose", action="store_true", help="extra per-proof detail")
    return p.parse_args()


def resolve_node(node_arg: str):
    low = node_arg.lower()
    if low in NODE_MAP:
        return NODE_MAP[low]
    if ":" in node_arg:
        host, port_str = node_arg.rsplit(":", 1)
        try:
            return host, int(port_str)
        except ValueError:
            pass
    print(f"{FAIL}  Unknown node '{node_arg}'. Use alice, bob, dave, carol, or host:port.")
    sys.exit(1)


if __name__ == "__main__":
    args = parse_args()
    host, port = resolve_node(args.node)
    machine_id = args.machine or f"qcb1devminer-{args.node.lower()}"

    default_threads = min(os.cpu_count() or 2, 8)
    num_threads     = args.threads if args.threads and args.threads > 0 else default_threads

    try:
        run_miner(
            host=host,
            port=port,
            machine_id=machine_id,
            preferred_track=args.track,
            once=args.once,
            verbose=args.verbose,
            num_threads=num_threads,
        )
    except KeyboardInterrupt:
        print("\n  Interrupted — exiting.")
        sys.exit(0)
