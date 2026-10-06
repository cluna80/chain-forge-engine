"""
QCB Grand Challenge — Devnet Discovery Simulation
==================================================
Simulates a three-machine parallel hash preimage search.
Each "machine" searches a different range of the nonce space.
First to find a hash with the target prefix wins.
The winning result is committed as a signed UsefulWorkReceipt.
An independent verifier machine checks the result.

This proves the full coordination + verification flow before
the real chain-forge-resource crate exists.
"""

import hashlib
import json
import time
import hmac
import os
from dataclasses import dataclass, asdict
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─── Challenge Definition ────────────────────────────────────────────────────

CHALLENGE_ID   = "GC-DEVNET-001"
CHALLENGE_DESC = "Find a nonce N such that SHA256('QCB:' + N) begins with '0000'"
TARGET_PREFIX  = "0000"          # 4 leading hex zeros — ~1-in-65536 chance per try
SEARCH_SPACE   = 10_000_000      # total nonce range
CHUNK_SIZE     = SEARCH_SPACE // 3  # each machine gets an equal slice

# ─── Machine Identities (simulated MachineIDs) ───────────────────────────────

MACHINES = [
    {"id": "MACH-ALICE-001", "name": "Alice",  "range_start": 0,              "range_end": CHUNK_SIZE},
    {"id": "MACH-BOB-002",   "name": "Bob",    "range_start": CHUNK_SIZE,     "range_end": CHUNK_SIZE * 2},
    {"id": "MACH-CAROL-003", "name": "Carol",  "range_start": CHUNK_SIZE * 2, "range_end": SEARCH_SPACE},
]

# Simulated signing keys (in prod these are Ed25519 seeds — never committed)
SIGNING_KEYS = {
    "MACH-ALICE-001": os.urandom(32).hex(),
    "MACH-BOB-002":   os.urandom(32).hex(),
    "MACH-CAROL-003": os.urandom(32).hex(),
}

VERIFIER_ID = "MACH-DAVE-VERIFIER-004"

# ─── Core Search ─────────────────────────────────────────────────────────────

def search_range(machine: dict, stop_flag: list) -> Optional[dict]:
    """Search nonces in this machine's assigned range."""
    machine_id = machine["id"]
    name       = machine["name"]
    start      = machine["range_start"]
    end        = machine["range_end"]
    checked    = 0
    t_start    = time.time()

    print(f"  [{name}] searching nonces {start:,} → {end:,}")

    for nonce in range(start, end):
        if stop_flag[0]:
            elapsed = time.time() - t_start
            print(f"  [{name}] stopped after {checked:,} checks ({elapsed:.2f}s) — another machine won")
            return None

        candidate = f"QCB:{nonce}"
        digest    = hashlib.sha256(candidate.encode()).hexdigest()
        checked  += 1

        if digest.startswith(TARGET_PREFIX):
            elapsed = time.time() - t_start
            stop_flag[0] = True
            print(f"  [{name}] ✓ FOUND after {checked:,} checks ({elapsed:.2f}s)")
            return {
                "machine_id":  machine_id,
                "machine_name": name,
                "nonce":       nonce,
                "input":       candidate,
                "hash":        digest,
                "checks":      checked,
                "elapsed_s":   round(elapsed, 4),
                "range":       [start, end],
            }

    elapsed = time.time() - t_start
    print(f"  [{name}] exhausted range after {checked:,} checks ({elapsed:.2f}s) — not found")
    return None

# ─── Receipt Signing (HMAC-SHA256 simulating Ed25519) ────────────────────────

def sign_receipt(payload: dict, machine_id: str) -> str:
    key     = SIGNING_KEYS[machine_id].encode()
    message = json.dumps(payload, sort_keys=True).encode()
    return hmac.new(key, message, hashlib.sha256).hexdigest()

# ─── UsefulWorkReceipt ────────────────────────────────────────────────────────

@dataclass
class UsefulWorkReceipt:
    receipt_id:        str
    challenge_id:      str
    work_type:         str       # "ResearchContribution"
    machine_id:        str
    input_hash:        str       # SHA256 of the challenge input string
    output_hash:       str       # the discovered hash
    methodology_ref:   str       # description of the search method
    nonce:             int
    checks_performed:  int
    elapsed_seconds:   float
    timestamp_utc:     str
    signature:         str       # HMAC-SHA256 of payload (simulates Ed25519)
    verified:          bool = False
    verifier_id:       str = ""
    verifier_signature: str = ""

def build_receipt(result: dict) -> UsefulWorkReceipt:
    payload = {
        "challenge_id":    CHALLENGE_ID,
        "work_type":       "ResearchContribution",
        "machine_id":      result["machine_id"],
        "input_hash":      hashlib.sha256(result["input"].encode()).hexdigest(),
        "output_hash":     result["hash"],
        "methodology_ref": "SHA256 sequential nonce search; target prefix '0000'; input format 'QCB:<nonce>'",
        "nonce":           result["nonce"],
        "checks_performed": result["checks"],
        "elapsed_seconds": result["elapsed_s"],
        "timestamp_utc":   time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    sig = sign_receipt(payload, result["machine_id"])
    return UsefulWorkReceipt(
        receipt_id        = f"REC-{CHALLENGE_ID}-{result['machine_id']}-{result['nonce']}",
        challenge_id      = payload["challenge_id"],
        work_type         = payload["work_type"],
        machine_id        = payload["machine_id"],
        input_hash        = payload["input_hash"],
        output_hash       = payload["output_hash"],
        methodology_ref   = payload["methodology_ref"],
        nonce             = payload["nonce"],
        checks_performed  = payload["checks_performed"],
        elapsed_seconds   = payload["elapsed_seconds"],
        timestamp_utc     = payload["timestamp_utc"],
        signature         = sig,
    )

# ─── Independent Verification ─────────────────────────────────────────────────

def verify_receipt(receipt: UsefulWorkReceipt) -> UsefulWorkReceipt:
    """Verifier machine independently reproduces the result."""
    print(f"\n[{VERIFIER_ID}] verifying receipt {receipt.receipt_id} ...")

    # 1. Recompute the hash from the nonce
    candidate      = f"QCB:{receipt.nonce}"
    recomputed     = hashlib.sha256(candidate.encode()).hexdigest()
    hash_matches   = recomputed == receipt.output_hash
    prefix_matches = recomputed.startswith(TARGET_PREFIX)

    # 2. Verify input hash
    input_recomputed = hashlib.sha256(candidate.encode()).hexdigest()
    input_matches    = input_recomputed == receipt.input_hash

    if hash_matches and prefix_matches and input_matches:
        print(f"  ✓ Hash reproduced:   {recomputed}")
        print(f"  ✓ Prefix '{TARGET_PREFIX}' confirmed")
        print(f"  ✓ Input hash matches")
        verifier_payload = {
            "receipt_id":   receipt.receipt_id,
            "output_hash":  receipt.output_hash,
            "verdict":      "VERIFIED",
            "verifier_id":  VERIFIER_ID,
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        verifier_sig = hmac.new(
            b"VERIFIER-KEY-DAVE",
            json.dumps(verifier_payload, sort_keys=True).encode(),
            hashlib.sha256
        ).hexdigest()
        receipt.verified           = True
        receipt.verifier_id        = VERIFIER_ID
        receipt.verifier_signature = verifier_sig
        print(f"  ✓ Verifier signature: {verifier_sig[:32]}...")
    else:
        print(f"  ✗ VERIFICATION FAILED")
        print(f"    hash_matches={hash_matches}, prefix_matches={prefix_matches}, input_matches={input_matches}")

    return receipt

# ─── Main ─────────────────────────────────────────────────────────────────────

def run_simulation():
    print("=" * 65)
    print("  QCB GRAND CHALLENGE — DEVNET SIMULATION")
    print(f"  Challenge: {CHALLENGE_ID}")
    print(f"  Target:    SHA256('QCB:<nonce>') starts with '{TARGET_PREFIX}'")
    print(f"  Machines:  {len(MACHINES)} (Alice, Bob, Carol)")
    print(f"  Verifier:  Dave")
    print("=" * 65)

    stop_flag = [False]
    winner    = None
    t_total   = time.time()

    print("\n[Phase 1] Parallel search across three machines:\n")
    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = {executor.submit(search_range, m, stop_flag): m for m in MACHINES}
        for future in as_completed(futures):
            result = future.result()
            if result and winner is None:
                winner = result

    total_elapsed = time.time() - t_total
    print(f"\n[Phase 1 complete] Total wall time: {total_elapsed:.2f}s")

    if not winner:
        print("\n✗ No solution found in search space. Try a wider range.")
        return

    print(f"\n[Phase 2] Building UsefulWorkReceipt ...\n")
    receipt = build_receipt(winner)
    print(f"  Receipt ID:    {receipt.receipt_id}")
    print(f"  Machine:       {receipt.machine_id}")
    print(f"  Nonce:         {receipt.nonce:,}")
    print(f"  Output hash:   {receipt.output_hash}")
    print(f"  Checks done:   {receipt.checks_performed:,}")
    print(f"  Elapsed:       {receipt.elapsed_seconds}s")
    print(f"  Signature:     {receipt.signature[:32]}...")

    print(f"\n[Phase 3] Independent verification by {VERIFIER_ID}:\n")
    receipt = verify_receipt(receipt)

    print(f"\n[Phase 4] Final discovery record:\n")
    record = asdict(receipt)
    print(json.dumps(record, indent=2))

    # Save to file
    out_path = "/tmp/claude-0/-home-claude/a5fcb468-a7f8-58f4-b182-04a4f548f027/scratchpad/qcb_discovery_GC-DEVNET-001.json"
    with open(out_path, "w") as f:
        json.dump(record, f, indent=2)

    print(f"\n{'=' * 65}")
    if receipt.verified:
        print(f"  ✓ DISCOVERY VERIFIED — GC-DEVNET-001")
        print(f"  Winner:  {winner['machine_name']} ({winner['machine_id']})")
        print(f"  Hash:    {receipt.output_hash}")
        print(f"  Nonce:   {receipt.nonce:,}")
        print(f"  Record saved to: qcb_discovery_GC-DEVNET-001.json")
    else:
        print(f"  ✗ Verification failed.")
    print(f"{'=' * 65}\n")

    return receipt

if __name__ == "__main__":
    run_simulation()
