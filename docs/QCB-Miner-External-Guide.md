# QCB Miner — External Operator Guide

**Version**: 0.1 (Phase 0 / Devnet)
**Binary**: `qcb-miner`
**Crate**: `chain-forge-miner`

---

## Overview

`qcb-miner` is the standalone PoCD (Proof of Cryptographic Discovery) miner
for the QCB blockchain. It connects to a running QCB scheduler, polls for
cryptographic challenge tasks, solves them, and submits results. Successfully
submitted and independently verified results earn research rewards from the
`treasury:pocd-research` account.

### What the miner does

1. **Registers** with the scheduler (`POST /scheduler/miners/register`)
2. **Polls** for an available task (`GET /scheduler/miners/{id}/task`)
3. **Solves** the assigned cryptographic challenge (CPU-bound SHA-256 work)
4. **Submits** the result (`POST /scheduler/tasks/{id}/result`)
5. Loops back to step 2

The miner operates in a **two-phase cascade** (see [Two-Phase PoCD Cascade](#two-phase-pocd-cascade) below). Each discovery requires two independent machines contributing independent hashes; a single machine cannot satisfy both phases of the same objective.

---

## Prerequisites

### Runtime requirements

| Requirement | Minimum | Notes |
|-------------|---------|-------|
| OS | Linux, macOS, Windows | Any OS with Rust toolchain |
| Rust | 1.75+ | Only needed to build from source |
| CPU | Any x86-64 or ARM64 | SHA-256 hashing is the workload; more cores = more throughput via parallel processes |
| Network | TCP to scheduler host | No inbound connections required |

### What you need from the network operator

Before running the miner you need:

- **Scheduler URL** — e.g. `http://192.168.137.1:8080`
- **Objective ID** — the UUID of the research objective to mine (ask the network operator)
- **A miner ID** — any unique string identifying your machine, e.g. `"machine3"` or `"bossking"`

---

## Building from Source

```bash
# Clone the repo
git clone <repo-url>
cd chain-forge-engine

# Build the miner binary (release mode recommended for hashing speed)
cargo build --release --bin qcb-miner

# Binary location
./target/release/qcb-miner --help
```

---

## Quick Start

```bash
qcb-miner \
  --node-url    http://192.168.137.1:8080 \
  --miner-id    my-machine \
  --objective-id 023807d7-6b28-43a4-8761-2ffa014ecb43
```

The miner will register, then begin polling for tasks every 5 seconds (configurable).

---

## CLI Reference

```
qcb-miner [OPTIONS]

Options:
  --node-url <URL>
      Base URL of the QCB scheduler node.
      Default: http://127.0.0.1:8080
      Env: QCB_NODE_URL

  --miner-id <ID>
      Unique identifier for this miner instance.
      Must be distinct from other miners on the same scheduler.
      Env: QCB_MINER_ID

  --objective-id <UUID>
      The research objective to mine against.
      Obtain from the network operator.
      Env: QCB_OBJECTIVE_ID

  --workload-class <CLASS>
      Advertised workload capability.
      Default: cpu
      Env: QCB_WORKLOAD_CLASS

  --poll-interval-secs <SECS>
      Seconds to wait between polls when no task is available.
      Default: 5

  --algorithm-version <VER>
      Algorithm tag embedded in result submissions.
      Default: sha256-preimage-v1

  --workload-version <VER>
      Workload version tag embedded in result submissions.
      Default: pocd-challenge-v1

  -h, --help     Print help
  -V, --version  Print version
```

All `--` flags can also be set via environment variable (shown above). Environment variables take lower priority than CLI flags.

---

## Two-Phase PoCD Cascade

The QCB research protocol requires that each cryptographic discovery be the product of **two independent machines** performing sequential, chained hashing work. A single machine alone cannot complete a full discovery.

### Phase 1

- **Input**: A 64-bit seed assigned by the scheduler
- **Algorithm**: `SHA-256(seed_bytes_le64 || nonce_bytes_le64)`
- **Target**: ≥ 16 leading zero bits in the output
- **Content hash**: `SHA-256(H1_bytes)` where `H1` is the winning hash

The miner searches nonces in the range `[range_start, range_end)` assigned by the scheduler. When a winning nonce is found, the result (including `H1`) is submitted.

### Phase 2

- **Input**: `H1` (the hex-encoded phase-1 winning hash) — supplied by the scheduler from the phase-1 winner
- **Algorithm**: `SHA-256(H1_bytes || nonce_bytes_le64)`
- **Target**: ≥ 8 leading zero bits in the output
- **Content hash**: `SHA-256(H1_bytes || H2_bytes)` — the combined two-machine proof
- **Constraint**: Must be performed by a **different** machine than the one that solved phase 1

The scheduler enforces the two-machine constraint: a miner will never be assigned a phase-2 task for an objective it solved phase 1 for.

### Avalanche Experiments

Some objectives assign **avalanche experiment** tasks instead of PoCD challenges. These are fully deterministic — no nonce search is required:

1. A canonical 32-byte seed is derived: `SHA-256("qcb-avalanche-v1" || objective_id_utf8 || seed_index_le64)`
2. The seed's output `original_hash = SHA-256(canonical_seed)` is computed
3. One input bit is flipped: `flipped_hash = SHA-256(canonical_seed_with_bit_flipped)`
4. The miner records: `xor_diff`, `hamming_dist`, `content_hash = SHA-256(original || flipped)`

Avalanche tasks are fast (two SHA-256 calls) and cannot be "not found" — every task completes.

---

## Understanding Task Leases

Every task assigned to a miner comes with a **lease** that expires at `lease_expires_at`. If you cannot submit a result before the lease expires, the scheduler reassigns the task to another miner. The expired result is safely dropped (HTTP 410). Your miner logs this and moves on:

```
WARN  task_id="..." reason="..." Lease expired — dropping result
```

To reduce lease expiry, run the miner on faster hardware, or set `--poll-interval-secs 1` to start new tasks sooner.

---

## Running Multiple Miners

You can run multiple `qcb-miner` processes on the same machine or across machines. Each must have a **distinct `--miner-id`**.

```bash
# Terminal 1 — miner A
qcb-miner --node-url http://192.168.137.1:8080 \
           --miner-id machine3-a \
           --objective-id <uuid>

# Terminal 2 — miner B
qcb-miner --node-url http://192.168.137.1:8080 \
           --miner-id machine3-b \
           --objective-id <uuid>
```

The scheduler distributes tasks across all registered miners. Because phase-2 tasks require a different machine from phase-1, having at least **two distinct machines** (not just two processes on the same machine) participating in an objective maximises throughput.

> **Note**: The scheduler tracks miner identity by `miner_id` string. Two processes with the same `miner_id` will share a registration and may interfere with each other's task assignments. Always use distinct IDs.

---

## Log Output

The miner uses structured logging via `tracing`. By default it logs at `INFO` level.

To enable verbose debug output:

```bash
RUST_LOG=debug qcb-miner --node-url ... --miner-id ... --objective-id ...
```

Key log events:

| Level | Message | Meaning |
|-------|---------|---------|
| INFO  | `QCB miner starting` | Startup parameters logged |
| INFO  | `Registered with scheduler` | Successfully joined scheduler |
| INFO  | `Task assigned — starting work` | Task received, solver running |
| INFO  | `Phase-1 challenge: SHA-256(seed\|\|nonce), 16-bit difficulty` | Phase-1 work starting |
| INFO  | `Phase-2 challenge: SHA-256(H1\|\|nonce), 8-bit difficulty` | Phase-2 work starting |
| INFO  | `PoCD solution found — submitting` | Winning nonce found |
| INFO  | `Result accepted by scheduler` | Scheduler confirmed receipt |
| INFO  | `No task available — waiting Xs` | Polling loop sleeping |
| WARN  | `No solution found in range` | Range exhausted, task will expire |
| WARN  | `Lease expired — dropping result` | Work submitted too late |
| WARN  | `Lease superseded — dropping result` | Another miner submitted first (409) |
| ERROR | `Miner exited with error` | Fatal error (network failure, etc.) |

---

## Environment Variables

All CLI flags have environment variable equivalents:

| Variable | Flag | Example |
|----------|------|---------|
| `QCB_NODE_URL` | `--node-url` | `http://192.168.137.1:8080` |
| `QCB_MINER_ID` | `--miner-id` | `bossking` |
| `QCB_OBJECTIVE_ID` | `--objective-id` | `023807d7-6b28-43a4-8761-2ffa014ecb43` |
| `QCB_WORKLOAD_CLASS` | `--workload-class` | `cpu` |
| `RUST_LOG` | — | `debug` / `info` / `warn` |

---

## System Service Example (systemd)

Save as `/etc/systemd/system/qcb-miner.service`:

```ini
[Unit]
Description=QCB PoCD Miner
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=qcb
ExecStart=/usr/local/bin/qcb-miner \
    --node-url http://192.168.137.1:8080 \
    --miner-id my-machine \
    --objective-id 023807d7-6b28-43a4-8761-2ffa014ecb43
Restart=on-failure
RestartSec=10
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now qcb-miner
sudo journalctl -u qcb-miner -f
```

---

## What Happens to Results

After the miner submits a result, the scheduler:

1. Validates the lease generation (rejects expired or superseded leases)
2. Stores the result in the research database
3. Queues the task for independent **verification** (other registered verifiers reproduce the hash)
4. When enough independent verifications are collected (quorum), accepts the result as canonical
5. The **settlement operator** can then claim a reward from the chain's `treasury:pocd-research` account for the winning miner

The miner itself does not need to interact with the settlement or verification steps. The scheduler and verifiers handle those autonomously.

---

## Troubleshooting

### `register failed: HTTP 404`
The scheduler URL is wrong or the scheduler is not running. Check `--node-url` and verify the scheduler is reachable:
```bash
curl http://<scheduler-host>:<port>/scheduler/objectives
```

### `get_task: HTTP 5XX`
The scheduler has an internal error. Check the scheduler's logs.

### `Lease expired` warnings on every result
The solver is taking too long for the assigned range. Either:
- Use faster hardware
- Set a shorter `--poll-interval-secs` to start sooner
- Contact the operator to see if task ranges can be reduced

### `Lease superseded` (HTTP 409)
Another miner submitted a phase-2 result for the same phase-1 hash before you did. This is normal in a competitive environment. Your miner moves on automatically.

### Result accepted but no reward credited
Rewards are only claimed after the result passes the verifier quorum. Ensure the network has at least two independent verifiers registered with the scheduler. The settlement step is performed by the operator, not the miner.

---

## Security Notes

- `qcb-miner` makes **outbound** HTTP connections only. It does not open any listening ports.
- The miner submits `miner_id` (a plain string) to the scheduler. Anyone who knows your `miner_id` could register the same ID on a different process, potentially intercepting task assignments. Use an ID that is not easily guessable, especially on a public network.
- In a future release, miner registration will be authenticated via ML-DSA-65 key files.

---

## Advisory Capacity Advertisements (Change Set T)

When a node broadcasts `CapacityAd` gossip, the scheduler can consult
`GET /api/peers/capacity` to prefer idle nodes for task assignment. `qcb-miner` 
does **not** send capacity ads directly — those are emitted by the `chain-forge-node` 
process on each validator. The miner's queue depth is indirectly reflected in the 
node's own capacity ad if the miner shares a host with a running node.

---

## Invariants (Preserved Throughout All Versions)

These guarantees are hard-wired into the protocol and will not change:

- **No result is automatically classified as a cryptographic breakthrough.**
- **No experimental result is automatically classified as a cryptographic anomaly or scientific discovery.** Human review is always required before any such claim.
- **Consensus is not affected by miner activity.** PoCD mining runs on a separate scheduler layer; the BFT consensus engine and token economics operate independently.
- **The two-phase constraint is enforced by the scheduler.** A single machine cannot earn a full phase-1 + phase-2 reward for the same task.
- **Task ownership, lease protections, and result deduplication are preserved.** The protocol rejects duplicate or late submissions cleanly (HTTP 409 / 410).

---

## API Endpoints Used by `qcb-miner`

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/scheduler/miners/register` | Register miner on startup |
| GET  | `/scheduler/miners/{id}/task` | Poll for next task (`?objective_id=...&workload_class=...`) |
| POST | `/scheduler/tasks/{id}/result` | Submit a completed result |

These endpoints are served by the `chain-forge-scheduler` binary, **not** the `chain-forge-node` binary. The scheduler and node are separate processes; the node runs on port 8080 by default and the scheduler also defaults to 8080 — on a shared machine the scheduler is typically run on a different port (e.g. 8081) or on a dedicated host.

---

*For questions, open an issue in the repository or contact the network operator.*
