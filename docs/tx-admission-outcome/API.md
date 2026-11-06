# `POST /api/tx` and `GET /api/tx/{id}`: the admission-outcome contract

Approved by the owner on 2026-11-06 as part of PR #116. Pinned by the `contract_*` tests in `chain-forge-node/src/node.rs`.

## Lifecycle
1. `POST /api/tx` runs **stateless** checks only. If they pass it answers `200` with exactly
   `{"status":"queued","state":"queued_for_validation","tx_id":"<id>"}` (unchanged since before this PR). This means *received*, not *admitted*.
2. At its next heartbeat the node admits the transaction (`Node::try_submit_tx`), the only place with account state (bound keys, derived
   addresses, mempool room). Admitted transactions wait in the mempool and are then committed.
3. A transaction the node refuses is **recorded** (bounded: 1,024 entries per node, oldest evicted) and never enters the mempool.

## `GET /api/tx/{id}`
| Situation | HTTP | Body |
|---|---|---|
| committed | 200 | the legacy committed summary: exactly `id, height, sender, kind, success, gas_used, events, error` (unchanged) |
| refused at admission | 200 | exactly `{"tx_id","status":"rejected","state":"rejected","code","message"}` (no `success` field) |
| queued, pending in the mempool, never seen, or a refusal that was evicted | 404 | `{"error":"not found"}` (unchanged) |

A committed result always wins over a recorded refusal for the same id. Reading does not consume a record. If the same id is later admitted,
the refusal is forgotten. `message` is human-readable and may change; **`code` is the contract.**

## Codes (never renamed or reused, only added)
| `code` | Meaning | `message` |
|---|---|---|
| `account_signature_policy` | the chain's `signature_scheme` forbids this transaction's signature kind | policy text |
| `signing_v2_envelope` | structurally invalid under signing v2 (E1-E5) | the stable E-code, e.g. `E4_SIGNATURE_WRONG_LENGTH` |
| `signing_v2_authorization` | wrong key for the sender, or the signature does not verify (bound key or derived address) | verifier text |
| `admission_bounds` | a sender, address or denom field is over its length bound | bound text |
| `mempool_full` | the mempool had no room; **retryable** | fixed text |

`duplicate_pending` and `already_committed` also exist internally but are **never reported**: the original outcome stands.

## Limits
Per node, in memory, lost on restart; a flood of newer refusals can evict an old record (the caller then sees 404 again); only refusals of
transactions submitted through this node's API are recorded (gossip-received transactions are verified but not recorded).
