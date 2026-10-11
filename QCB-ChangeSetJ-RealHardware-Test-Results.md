# Change Set J — Two-Phase PoCD Cascade: Real Hardware Test Results

**Date:** 2026-10-11  
**Status:** ✅ CONFIRMED on real hardware, two physical machines

---

## Test Objective

Prove that the two-phase PoCD (Proof of Coordinated Difficulty) cascade correctly enforces the **different-miner rule** across two physical machines on a local network — Phase-2 work cannot be self-assigned by the same miner that completed Phase-1.

---

## Environment

| Role | Machine | OS | Miner ID | IP |
|------|---------|----|-----------|----|
| Phase-1 miner + scheduler | BossKing | Windows 11 (MINGW64) | `machine-a` | `192.168.137.1` |
| Phase-2 miner | OptiPlex 990 | Ubuntu 22.04 | `machine-b` | `192.168.137.2` |

**Network:** Hyper-V virtual switch subnet `192.168.137.0/24` — shared between both machines.

**Scheduler:** `qcb-scheduler.exe` running in-memory mode on BossKing, bound to `0.0.0.0:8080`.

---

## Cryptographic Protocol

### Phase 1
```
H1 = SHA-256(seed || nonce)
Target: H1 has ≥ 16 leading zero bits (difficulty = 16)
Assigned to: machine-a
```

### Phase 2
```
H2 = SHA-256(H1 || nonce)
Target: H2 has ≥ 8 leading zero bits (difficulty = 8)
Assigned to: any miner EXCEPT the Phase-1 solver (exclude_miner rule)
```

---

## Test Execution

### Seed
```
Objective ID: 023807d7-6b28-43a4-8761-2ffa014ecb43
Tasks seeded: 100 Phase-1 tasks
```

### Phase-1 Run (BossKing — machine-a)
```
qcb-miner.exe --node-url http://127.0.0.1:8080 \
              --miner-id machine-a \
              --objective-id 023807d7-6b28-43a4-8761-2ffa014ecb43
```
- Completed all 100 Phase-1 tasks
- Each completion triggered scheduler to spawn a corresponding Phase-2 task with `exclude_miner = "machine-a"`
- machine-a received "No task available" for all Phase-2 tasks (correctly blocked)

### Phase-2 Run (OptiPlex — machine-b)
```
qcb-miner --node-url http://192.168.137.1:8080 \
           --miner-id machine-b \
           --objective-id 023807d7-6b28-43a4-8761-2ffa014ecb43
```
- Picked up and completed all 100 Phase-2 tasks
- Connected cross-machine over Hyper-V subnet

### Example Phase-2 Solutions
| Nonce | H1 (Phase-1 hash used as seed) | H2 (Phase-2 result) |
|-------|-------------------------------|----------------------|
| 5 | `0000...` (16-bit prefix) | `00...` (8-bit prefix) |
| 50 | varies | varies |
| 146 | varies | varies |

Small nonces confirm efficient solver at 8-bit difficulty.

---

## Outcome

| Metric | Result |
|--------|--------|
| Phase-1 tasks completed by machine-a | 100 / 100 ✅ |
| Phase-2 tasks spawned by scheduler | 100 / 100 ✅ |
| Phase-2 tasks blocked for machine-a | 100 / 100 ✅ |
| Phase-2 tasks completed by machine-b | 100 / 100 ✅ |
| Cross-machine HTTP connectivity | ✅ `192.168.137.1:8080` |
| Different-miner rule enforced | ✅ Confirmed |

---

## Infrastructure Notes

### Windows Firewall (required for cross-machine access)
```powershell
# Run in Administrator PowerShell on BossKing
netsh advfirewall firewall add rule name="QCB Scheduler 8080" dir=in action=allow protocol=TCP localport=8080 profile=any
```

### OptiPlex — Offline Build (no internet)
The OptiPlex has no internet access. The `chain-forge-miner` crate was built using a vendored dependency bundle:
1. `cargo vendor vendor-miner` run on BossKing (internet-connected)
2. `vendor-miner/` directory scp'd to OptiPlex
3. `.cargo/config.toml` configured to use `vendored-sources`
4. Built successfully with `cargo build --release -p chain-forge-miner`

---

## Relevant Commits

| Commit | Description |
|--------|-------------|
| `ddee87d` | Change Set J: Two-phase PoW cascade with coordinated compute |
| `0ae9989` | Phase-aware challenge solver + DB layer |
| `a5249fe` | `qcb-scheduler` binary — standalone HTTP server |
| `43989f8` | `qcb-seed --node-url` — live scheduler HTTP seeding |

---

## Next Work Items

- [ ] `ReleaseQrcForJob` happy-path and negative-path tests (devnet: Alice/Bob/Dave on OptiPlex)
- [ ] `RefundQrcForJob` happy-path and negative-path tests (devnet)
- [ ] Wire `escrow:esc-{id}` queryability (soft-skip → hard check)
- [ ] 4-node test with Carol (Machine 2) when available
