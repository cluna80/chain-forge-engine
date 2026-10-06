# QCB Grand Challenge — Simulations

Proof-of-concept simulations of the Grand Challenge discovery flow,
run before `chain-forge-resource` exists. Each simulation proves the
coordination + verification logic that the real crate will implement.

## GC-DEVNET-001 — Hash Preimage Search

**Date**: 2026-10-06  
**Status**: ✅ VERIFIED  
**Type**: ResearchContribution (hash preimage)

### What it proved

Three simulated machines (Alice, Bob, Carol) searched parallel nonce
ranges for a SHA256 hash of `'QCB:<nonce>'` starting with `'0000'`.
Carol found nonce `6,682,026` after 15,361 checks in 0.04s.
An independent verifier (Dave) reproduced the hash from the nonce alone
and signed the verification.

### Full discovery record

See `GC-DEVNET-001-discovery-record.json`.

```
receipt_id:        REC-GC-DEVNET-001-MACH-CAROL-003-6682026
work_type:         ResearchContribution
machine_id:        MACH-CAROL-003 (Carol)
nonce:             6,682,026
output_hash:       000050f191ffc75beea3eda52095cb28da8028646673e4e159f88ca864c22b72
checks_performed:  15,361
elapsed_seconds:   0.0403
verified:          true
verifier_id:       MACH-DAVE-VERIFIER-004 (Dave)
```

### What swaps out for the real devnet

| Simulation | Real chain-forge-resource |
|------------|--------------------------|
| HMAC-SHA256 signing | Ed25519 with machine key files |
| JSON file output | On-chain transaction submission |
| Python script | Rust crate on devnet nodes |
| Simulated MachineIDs | Real attested MachineIDs |

The coordination and verification logic is identical.

## Next Simulations

- **GC-DEVNET-002** — Multi-track parallel (two challenges running simultaneously)
- **GC-DEVNET-003** — Disputed result + rejection flow
- **GC-DEVNET-004** — Physics-flavored: tiny lattice simulation with verified output hash
