# Scheduler signing boundary: audit and design

Status: written **before** the implementation. Audited tree: `9c56b3d` (PR #105, `feat/signers-v2-scheduler`). Scope: the scheduler's settlement endpoint, which today receives the settlement operator's ML-DSA-65 **private key** in an HTTP request body.

## 1. Audit: where private-key material crosses a boundary

| # | Boundary | Evidence | Risk |
|---|---|---|---|
| 1 | **Operator client → scheduler, over the network** | `SettleRequest.operator_secret_key_hex` (`settlement.rs`), deserialised by `settle_handler` (`api.rs`) from `POST /scheduler/objectives/:id/settle` | The key travels in a JSON body over **plain HTTP**. `qcb-scheduler` binds `0.0.0.0:8080` by default (`main.rs`), has **no TLS**, and the settle route has **no caller authentication** (authentication exists only for verifier registration). Anyone on the path, or any process able to read request bodies, sees the key. |
| 2 | Scheduler process memory | the field is a `String`; it is hex-decoded into a `Vec<u8>` and copied into a `KeyPair`; nothing is zeroized | key material lives in ordinary heap for the life of the request and beyond; a core dump, swap or memory read exposes it |
| 3 | Accidental logging | `#[derive(Debug)]` on `SettleRequest` while it holds the key | any `{:?}`, `tracing::…(?req)` or panic message prints the key. Not done today (verified by grep), but one line away |
| 4 | Error responses | `KeyDecode(format!("secret key: {e}"))` is returned to the client | a `hex` error message names the offending character and its position, which is a (small) disclosure about the key, to whoever can read the response or the server log |
| 5 | Scheduler → node | the transaction posted to `/api/tx` | **signed transaction only**; no key. Fine. |
| 6 | Scheduler → database | `insert_reward_claim(output.claim)` | the claim row has no key fields. Fine. |
| 7 | Operator's shell | the caller must put the key in a request (`curl -d`, scripts) | key in shell history, process lists, CI logs. Outside this repository's code but a direct consequence of the design |
| 8 | Repository | grep across `.rs/.py/.sh/.md/.json` | the only production reader of the field is `settlement.rs`; `tests/devnet/results/pocd-e2e-2026-10-11.md` records a settle call **without** key material; there are **no in-repo callers** of the endpoint (scripts or CLIs), so removing it breaks only external operator tooling |

Also noted (separate findings, not fixed here): the request chooses `node_url`, so the scheduler will POST to any URL a caller names (SSRF-style); `dis-test-helper` prints test keys to stdout; the scheduler API has no authentication on this route.

## 2. Design

**Principle: the scheduler never holds, receives or derives the operator's private key.** Signing happens in a separate signer process that holds the key (encrypted wallet file, passphrase from its own environment). The scheduler is treated as **untrusted by the signer**, because a compromised scheduler is exactly the threat.

Two-step flow:

1. `POST /scheduler/objectives/:id/settle/prepare` with **public** data only (task, reward kind, recipient, chain id, operator address, operator **public** key, nonce, `signing_profile = "qattice-v2"`). The scheduler computes the claim from its database, stores it `pending`, and returns the **unsigned transaction** and a **signing request** (profile, FIPS 204 context `qattice/tx/v2`, chain id, signer, the full canonical v2 preimage).
2. The signer (`qcb-claim-signer`) recomputes the preimage itself from the unsigned transaction (it never trusts the scheduler's `preimage_hex`), checks it is exactly a `ClaimResearchReward` from its own address for the chain it was told to expect, signs it (hedged ML-DSA-65, context `qattice/tx/v2`), and returns the signed transaction.
3. `POST /scheduler/objectives/:id/settle/submit` with the **signed transaction**. The scheduler rebuilds the expected claim body from its **database row** and accepts the transaction only if body, id and gas limit match it exactly (so the endpoint is not a generic relay and a replaced recipient or amount is refused even under a valid signature), checks the v2 envelope and verifies the signature when the key is carried, forwards it unchanged to the node, and marks the claim `submitted`. The node remains the authority on signature, key binding and settlement-operator membership.

Rejection of key material: every settlement endpoint scans the raw body **before** parsing or storing anything and refuses (`400 private_key_material_rejected`, generic message, nothing echoed) any request that has a field name containing `secret`, `private`, `seed`, `mnemonic`, `passphrase`, `password` or `privkey` (at any depth, case-insensitive), a PEM private-key header, or a string that is exactly the encoding of an ML-DSA-65 secret key (8,064 hex characters). Request types also use `deny_unknown_fields`. The old `POST …/settle` route returns `410 Gone` and never reads its body. **No type in the scheduler has a field that could hold a secret key**, and none derives `Debug` over one.

No legacy fallback: the only accepted profile is `qattice-v2`; the legacy prehash signing path is removed from the scheduler.

## 3. What this does and does not fix
Fixes: boundaries 1-4 and 7 for the scheduler (the key is never sent to, or held by, the scheduler).
Does **not** fix: the signer process still holds the key in memory while it runs (zeroization is best effort); the scheduler API has no authentication or TLS (the data it now handles is public, but unauthenticated callers can still create pending claims); `node_url` chosen by the caller; the signer's passphrase source is the environment or stdin; a hardware key vault or separate-host signer is a further step; wallet files are the legacy-library container, not the `qattice-key` format of #109 (a later unification); breaks any external operator tool that used the old endpoint (documented below).

## 4. Compatibility and migration
The old `POST …/settle` is removed for all profiles. External operator tooling must switch to prepare → sign → submit. Legacy (profile-less) chains are no longer settled through the scheduler. The in-repo devnet scripts do not call the endpoint.
