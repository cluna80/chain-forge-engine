# chain-forge-miner

QCB PoCD miner — polls the scheduler for cryptographic challenge tasks,
performs SHA-256 preimage work, and submits results for independent verification.

**Binary**: `qcb-miner`

For a complete operator guide see [`docs/QCB-Miner-External-Guide.md`](../docs/QCB-Miner-External-Guide.md).

---

## Build

```bash
# Development
cargo build --bin qcb-miner

# Release (recommended — 5–10× faster for SHA-256 search)
cargo build --release --bin qcb-miner
```

---

## Run

```bash
./target/release/qcb-miner \
  --node-url    http://192.168.137.1:8080 \
  --miner-id    my-machine \
  --objective-id 023807d7-6b28-43a4-8761-2ffa014ecb43
```

Debug logging:

```bash
RUST_LOG=debug ./target/release/qcb-miner ...
```

Full flag reference: `qcb-miner --help`

---

## Test

```bash
cargo test -p chain-forge-miner
```

Tests live in `src/challenge.rs` and cover:

- Phase-1 SHA-256 preimage search (16-bit difficulty)
- Phase-2 chained search (8-bit difficulty, parent-hash dependency)
- Determinism across multiple solver runs
- Phase-2 cross-miner content-hash agreement
- Avalanche seed derivation (deterministic by `(objective_id, seed_index)`)
- Avalanche hamming-distance consistency check
- Invalid-hex parent-hash returns `None` gracefully

---

## Architecture

```
src/
  main.rs      — CLI (clap), event loop: register → poll → solve → submit
  client.rs    — Thin async HTTP wrapper for scheduler API
  challenge.rs — CPU-bound solvers: solve_phase1, solve_phase2, solve_avalanche
  error.rs     — MinerError enum (Http, Scheduler, LeaseExpired, LeaseSuperseded, …)
```

### Two-phase cascade

The QCB PoCD protocol requires **two independent machines**:

| Phase | Algorithm | Difficulty | Content hash |
|-------|-----------|------------|--------------|
| 1 | `SHA-256(seed_le64 ∥ nonce_le64)` | ≥ 16 leading zero bits | `SHA-256(H1)` |
| 2 | `SHA-256(H1_bytes ∥ nonce_le64)` | ≥ 8 leading zero bits | `SHA-256(H1 ∥ H2)` |

Phase-2 tasks are always assigned to a **different** miner than the phase-1 solver.
The scheduler enforces this constraint; the miner binary is unaware of it.

### Avalanche experiments

Some objectives assign deterministic `avalanche_experiment` or
`avalanche_replication` tasks instead of PoCD challenges:

```
canonical_seed = SHA-256("qcb-avalanche-v1" ∥ objective_id ∥ seed_index_le64)
original_hash  = SHA-256(canonical_seed)
flipped_seed   = canonical_seed with bit `bit_index` flipped
flipped_hash   = SHA-256(flipped_seed)
xor_diff       = original_hash XOR flipped_hash  (256 bits)
hamming_dist   = popcount(xor_diff)
content_hash   = SHA-256(original_hash_bytes ∥ flipped_hash_bytes)
```

These complete deterministically in two SHA-256 calls.

### Task dispatch in main.rs

```
task.task_kind
  "avalanche_experiment" | "avalanche_replication"
      → challenge::solve_avalanche(objective_id, seed_index, bit_index)
  _ (default)
      → phase == 1  →  challenge::solve_phase1(seed, range_start, range_end)
      → phase == 2  →  challenge::solve_phase2(parent_hash, range_start, range_end)
```

All CPU-bound work runs in `tokio::task::spawn_blocking` so the async runtime
is never blocked.

### Scheduler API surface consumed

| Method | Path | Body / Query |
|--------|------|--------------|
| POST | `/scheduler/miners/register` | `{miner_id, workload_class}` |
| GET  | `/scheduler/miners/{id}/task` | `?objective_id=…&workload_class=…` |
| POST | `/scheduler/tasks/{id}/result` | `{miner_id, submitted_generation, result: {…}}` |

HTTP 204 on task poll → no task available, sleep and retry.
HTTP 409 on submit → lease superseded by another miner (log and continue).
HTTP 410 on submit → lease expired (log and continue).

---

## Dependencies

| Crate | Purpose |
|-------|---------|
| `tokio` | Async runtime |
| `reqwest` | HTTP client (rustls-tls, no OpenSSL dependency) |
| `sha2` | SHA-256 — the core algorithm |
| `hex` | Encoding hash bytes as hex strings |
| `clap` | CLI argument parsing |
| `serde` / `serde_json` | Serialize/deserialize scheduler API payloads |
| `tracing` / `tracing-subscriber` | Structured logging |
| `uuid` | Generate `receipt_id` on result submission |
| `chrono` | Parse `lease_expires_at` timestamps |
| `urlencoding` | URL-encode miner IDs in path segments |
| `thiserror` | `MinerError` derive |

No chain-forge crates are imported — `qcb-miner` communicates with the
scheduler entirely over HTTP and has no compile-time dependency on any
other crate in this workspace.

---

## Invariants

These are guaranteed by the protocol and preserved across all `qcb-miner` versions:

- No result is automatically classified as a cryptographic breakthrough.
- No experimental result is automatically classified as a cryptographic anomaly or scientific discovery.
- The miner does not participate in consensus or token economics.
- The two-phase cascade enforces independent machine cooperation.
- Lease protections and result deduplication are server-side; the miner handles HTTP 409/410 gracefully.
