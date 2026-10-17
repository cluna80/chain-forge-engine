# QCB-CS-001 — Cryptographic Dependency Inventory
**Branch:** `security/cs-001-crypto-hardening`  
**Date:** 2026-10-17  
**Status:** ACTIVE — audit complete, remediation in progress

---

## 1. Executive Summary

Chain Forge uses cryptographic primitives across 17+ crates. A post-quantum migration
requires knowing exactly where each primitive lives, what it protects, and whether it
needs to be algorithm-agile. This document is the canonical audit.

**Finding categories:**

| Category | Count | Risk |
|---|---|---|
| SHA-256 hardcoded (non-security-critical) | 7 crates | LOW — collision-resistance only, preimage attacks infeasible classically |
| SHA-256 hardcoded in auth/signing paths | 2 files | MEDIUM — domain-separates ML-DSA signatures; must be auditable/replaceable |
| SHA-256 hardcoded address derivation | 1 site | HIGH — double-SHA-256 public-key → address; locked to classical scheme |
| SHA3-256/384 hardcoded (block/tx hashes) | 2 crates | LOW — SHA-3 is quantum-resistant to Grover with 256-bit output; no near-term threat |
| BLAKE3 (personhood nullifiers) | 1 crate | LOW — quantum-resistant; keyed-hash construction sound |
| Ed25519 (P2P transport only) | 1 site | LOW — libp2p ephemeral transport key, not on-chain |
| Ed25519 (validator consensus key) | many | NOTE — already behind `SignatureScheme` trait in node/consensus/execution |
| ML-DSA-65 (transaction signing) | wallet + execution | NOTE — already real PQC via `pqcrypto-dilithium`; wired correctly |
| Argon2id + AES-256-GCM (wallet KDF+enc) | 1 crate | NOTE — appropriate; Argon2id is memory-hard and PQ-safe |
| BLS12-381 (Groth16 ZK proofs) | personhood | NOTE — quantum-vulnerable in the long term; tracked separately |
| No versioned scheme tag on chain signatures | all tx | HIGH — cannot migrate algorithm without a hard fork |

---

## 2. Crate-by-Crate Inventory

### 2.1 `chain-forge-crypto` — CANONICAL ABSTRACTION

**File:** `src/lib.rs`

| Primitive | Use | PQ-safe? | Abstracted? |
|---|---|---|---|
| Ed25519 (`ed25519-dalek`) | Validator consensus signing/verification | No | ✅ behind `ClassicalScheme` + `SignatureScheme` trait |
| ML-DSA-65 (`pqcrypto-dilithium`) | PQ transaction/validator signing | Yes (NIST FIPS 204) | ✅ behind `MlDsaScheme` |
| SHA-256 (`sha2`) | ML-DSA signing message digest | No (Grover: 128-bit security) | ⚠️ hardcoded in scheme impl |
| `SchemeRegistry` + `MigrationTrigger` | Algorithm switchover tracking | N/A | ✅ designed |

**Features required:** `real-crypto` (Ed25519) + `real-pqc` (ML-DSA). Both enabled in `chain-forge-node` and `chain-forge-execution`.

**Gap:** No versioned algorithm identifier is stored alongside signatures. Signatures are
raw bytes with no scheme tag — the verifier must be told which scheme to use out-of-band.
This makes live migration impossible without a hard fork.

---

### 2.2 `chain-forge-node` — CRITICAL PATHS

#### `src/auth.rs`

| Line(s) | Primitive | What it hashes | Risk |
|---|---|---|---|
| 179–180 | SHA-256 | Challenge ID input (nonce generation) | LOW — entropy only |
| 222–223 | SHA-256 | Auth payload body | MEDIUM — used to produce signing message for validator ops |
| 244–246 | SHA-256 | **Public key → address derivation** (double-SHA-256) | HIGH — locked to classical; must be auditable |
| 359–360 | SHA-256 | Tx payload signing message | MEDIUM — domain-separates signatures |

**Key finding:** Lines 244–246 derive the on-chain address from a public key using
double-SHA-256 (Bitcoin-style). If the key scheme migrates to ML-DSA, the address
derivation function must also be versioned — otherwise an ML-DSA pubkey produces
an address indistinguishable from a classical one, breaking replay protection.

#### `src/bin/gc-daemon.rs`

| Line(s) | Primitive | What it hashes | Risk |
|---|---|---|---|
| 131, 143, 202–204 | SHA-256 | GC challenge ID / challenge candidate | LOW — PoW puzzle, collision resistance sufficient |
| 185 | SHA-256 | `challenge-input:{id}` for challenge record | LOW — audit trail only |

---

### 2.3 `chain-forge-core` — BLOCK AND TX HASHING

**File:** `src/lib.rs`

| Primitive | Use | PQ-safe? | Notes |
|---|---|---|---|
| SHA3-256 | Block hashes, tx hashes (256-bit mode) | ✅ Yes | Grover halves security to 128-bit; remains safe |
| SHA3-384 | Block hashes, tx hashes (384-bit mode) | ✅ Yes | Grover: 192-bit security; conservative choice |

`ChainHash::digest()` is **already abstracted** behind a `HashWidth` enum driven by
genesis config. This is the correct pattern — hash algorithm is configurable at genesis.
No immediate remediation required; SHA-3 family is considered PQ-resistant for hashing.

**`ChainAddress::from_public_key()`** at line 180 delegates to `ChainHash` (SHA-3), which
is safer than the double-SHA-256 in `auth.rs`. However it lacks a scheme-version prefix,
so ML-DSA addresses and Ed25519 addresses would collide in the same namespace.

---

### 2.4 `chain-forge-state` — JELLYFISH MERKLE TREE

**File:** `src/jmt.rs`

| Primitive | Use | PQ-safe? |
|---|---|---|
| SHA3-256 | Leaf, internal node, and root hashes | ✅ Yes |

Domain separators (tag bytes) are applied correctly. No action required.

---

### 2.5 `chain-forge-execution` — TX VERIFICATION

**File:** `src/lib.rs` (lines ~1998, ~7361)

| Primitive | Use | Risk |
|---|---|---|
| SHA-256 | Domain-separated ML-DSA signing message: `SHA-256("chain-forge/pq-tx/v1\n" \|\| chain_id \|\| "\n" \|\| body_json)` | MEDIUM |

This is the canonical message format for ML-DSA transactions. SHA-256 is used only to
produce a 32-byte message digest that ML-DSA then signs. The ML-DSA signature itself is
PQ-safe; SHA-256 here is a pre-hash step (common in hybrid constructions). Risk is that
SHA-256 collision attacks (128-bit quantum security) could theoretically allow forged
messages — but ML-DSA provides 128-bit PQ security anyway, so this doesn't weaken the
overall construction meaningfully.

**Recommendation:** Document the domain separator as a versioned protocol constant
(`MLDSA_TX_HASH_DOMAIN_V1`) and make it easy to swap to SHA3-256 if needed.

---

### 2.6 `chain-forge-miner` + `chain-forge-seed` + `chain-forge-verifier` — PoW PUZZLES

**Files:** `chain-forge-miner/src/challenge.rs`, `chain-forge-seed/src/challenge.rs`,
`chain-forge-verifier/src/engine.rs`

| Primitive | Use | Risk |
|---|---|---|
| SHA-256 (all three crates) | `sha256-preimage-v1` and `sha256-avalanche-v1` PoW puzzles | NONE |

SHA-256 PoW is **intentionally hardcoded** — the puzzle type is part of the protocol
(identified by `algorithm_version: "sha256-preimage-v1"`). Quantum speedup via Grover
halves the effective difficulty but does not break the scheme — miners can adjust
difficulty targets. This is a known and accepted trade-off.

**No remediation required.** The algorithm string in puzzle records makes these versioned.

---

### 2.7 `chain-forge-scheduler` — BEACON / SETTLEMENT

**Files:** `src/beacon.rs`, `src/settlement.rs`

| Primitive | Use | Risk |
|---|---|---|
| SHA-256 | Randomness beacon computation | LOW |
| SHA-256 | Settlement hash integrity | LOW |

Randomness beacon uses SHA-256 of combined validator inputs. Grover does not help
an adversary here — the beacon is collision-resistant, not a signature. Low priority.

---

### 2.8 `chain-forge-analyzer` — RESEARCH TASK HASHING

**File:** `src/compute.rs`

| Primitive | Use | Risk |
|---|---|---|
| SHA-256 | Research task content fingerprinting | LOW — integrity only |

---

### 2.9 `chain-forge-resource` — RECEIPT HASHING

**File:** `src/types/receipt.rs`

| Primitive | Use | Risk |
|---|---|---|
| SHA-256 | Resource receipt content hash | LOW |

---

### 2.10 `chain-forge-qrc` — CAPACITY / PoCD

**File:** `src/pocd_reward.rs`

| Primitive | Use | Risk |
|---|---|---|
| SHA-256 | PoCD reward computation | LOW — uses `ChainHash` correctly in `capacity_report.rs` |

`capacity_report.rs` routes through `ChainHash::digest(, HashWidth::Bits256)` which
goes through the SHA-3 abstraction — correct. `pocd_reward.rs` uses raw `sha2` — inconsistent.

---

### 2.11 `chain-forge-personhood` — NULLIFIERS AND ZK PROOFS

**Files:** `src/eligibility.rs`, `src/lib.rs`, circuits

| Primitive | Use | PQ-safe? | Notes |
|---|---|---|---|
| BLAKE3 (keyed) | Epoch nullifier: `N = BLAKE3-keyed-hash(K, domain \|\| epoch_be)` | ✅ Yes | BLAKE3 is quantum-resistant; keyed construction is sound |
| BLAKE3 (unkeyed) | Credential commitment: `BLAKE3(secret)` | ✅ Yes | |
| BLS12-381 (Groth16) | ZK proof generation/verification for personhood | ⚠️ Vulnerable long-term | BLS12-381 discrete log is broken by Shor's algorithm |
| ark-groth16 `VerifyingKey` | Stored verifying key for ZK circuits | ⚠️ Vulnerable long-term | |

**BLS12-381 note:** Shor's algorithm breaks elliptic curve discrete log, which would
break both BLS12-381 signatures AND Groth16 proofs that use this pairing. This is a
**long-term** concern (10–15 year horizon with fault-tolerant quantum computers).
Tracked as a future item; near-term priority is signature schemes.

---

### 2.12 `chain-forge-wallet` — KEY STORAGE

**File:** `src/lib.rs`

| Primitive | Use | PQ-safe? | Notes |
|---|---|---|---|
| ML-DSA-65 | Signing key storage and tx signing | ✅ Yes | Via `chain-forge-crypto` |
| Argon2id | KDF: passphrase → 32-byte AES key | ✅ Yes | Memory-hard; quantum-safe |
| AES-256-GCM | Key file encryption | ✅ Yes (symmetric 256-bit) | Grover halves to 128-bit; secure |
| SHA-256 | Signing message pre-hash | MEDIUM | Same domain separator as execution |

**Wallet KDF and encryption are correctly implemented.** Argon2id parameters (128 MB /
3 iterations / 4 threads) are appropriate for 2026 hardware.

---

### 2.13 `chain-forge-p2p` — TRANSPORT

**File:** `src/lib.rs:572`

```rust
let local_key = libp2p::identity::Keypair::generate_ed25519();
```

| Primitive | Use | Risk |
|---|---|---|
| Ed25519 (libp2p) | Ephemeral P2P transport identity | LOW |

This key is generated fresh each time the node starts — it is **not persisted**, not
stored on-chain, and not used for consensus. It identifies the node to peers for
transport-layer security only. Low priority; libp2p will adopt PQ transport
independently via Noise protocol evolution.

---

### 2.14 `chain-forge-vca-pq` — VCA / QUORUM

SHA-3 reference found only in test string literals (not actual hash calls).
No raw crypto usage in production code.

---

## 3. Risk Register

| ID | Location | Primitive | Risk | Priority |
|---|---|---|---|---|
| CS-001-H1 | `auth.rs:244-246` | SHA-256 address derivation | **HIGH** | P1 |
| CS-001-H2 | All tx signatures | No scheme version tag | **HIGH** | P1 |
| CS-001-M1 | `auth.rs:222-223, 359-360` | SHA-256 signing message | **MEDIUM** | P2 |
| CS-001-M2 | `execution/src/lib.rs:1998` | SHA-256 ML-DSA pre-hash | **MEDIUM** | P2 |
| CS-001-L1 | `qrc/pocd_reward.rs` | Raw sha2 (inconsistent with ChainHash pattern) | **LOW** | P3 |
| CS-001-L2 | personhood circuits | BLS12-381 (long-term quantum threat) | **LOW** | P4 |
| CS-001-L3 | `p2p/src/lib.rs:572` | Ed25519 ephemeral transport | **LOW** | P4 |

---

## 4. What Is Already PQ-Safe

- **ML-DSA-65 transaction signing** — real Dilithium3, NIST FIPS 204. ✅
- **SHA-3 block/tx hashing** in `chain-forge-core` and `chain-forge-state`. ✅
- **BLAKE3 personhood nullifiers** — quantum-resistant hash. ✅
- **Argon2id + AES-256-GCM wallet encryption** — memory-hard KDF, 256-bit symmetric. ✅
- **`SignatureScheme` trait** — pluggable abstraction exists; Ed25519 and ML-DSA already behind it. ✅

---

## 5. Remediation Plan

### P1 — High priority (this branch)

**CS-001-H1:** Add algorithm version prefix to address derivation  
- `auth.rs`: Replace raw double-SHA-256 with versioned `AddressDeriver` that encodes scheme
  (classical/pq) into the derivation so ML-DSA addresses are in a distinct namespace.

**CS-001-H2:** Add versioned signature envelope to all on-chain transactions  
- Add `sig_scheme: SchemeId` field to the `Transaction` type (or a wrapping `SignedTx`).
- Verifier selects the correct scheme from this tag — enables live migration without hard fork.

### P2 — Medium priority (follow-up PR)

**CS-001-M1 + CS-001-M2:** Extract domain separator constant  
- Define `pub const MLDSA_TX_HASH_DOMAIN_V1: &[u8]` in `chain-forge-crypto`.
- Make pre-hash function pluggable or at least auditable/documented.
- Consider upgrading from SHA-256 to SHA3-256 for consistency with block/tx hashing.

### P3 — Low priority (cleanup)

**CS-001-L1:** Route `qrc/pocd_reward.rs` through `ChainHash` for consistency.

### P4 — Future (tracked, not blocking)

**CS-001-L2:** BLS12-381 / Groth16 quantum migration — requires new ZK proof system
(Plonky3, Nova, or STARK-based). Long-horizon item.

**CS-001-L3:** libp2p PQ transport — follow upstream libp2p NIST PQC adoption.

---

## 6. Non-Findings (Intentional Hardcoding)

These SHA-256 usages are **protocol-versioned** and do not need abstraction:

- `chain-forge-seed` / `chain-forge-miner` / `chain-forge-verifier`: SHA-256 PoW puzzles
  (`sha256-preimage-v1`, `sha256-avalanche-v1`) — algorithm name is embedded in the
  challenge record; upgrading means issuing new challenge types, not changing the code.
- `chain-forge-node/src/bin/gc-daemon.rs`: GC challenge PoW — same reasoning.
- `chain-forge-analyzer`: Research task fingerprinting — content addressing only.
- `chain-forge-resource/receipt.rs`: Receipt content hash — integrity, not authentication.
- `chain-forge-scheduler/beacon.rs`: Randomness beacon — not a signature scheme.

---

*Audit performed: 2026-10-17 | Branch: security/cs-001-crypto-hardening*
