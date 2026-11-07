# H0-4 (nonce / replay) and H0-6 (key-binding race) — findings (DRAFT)

Base: `origin/main` @ `486bd22`. This PR adds **tests and this document only**: no production, signing, genesis, state-root or Chain Forge change. Not merged. Results are from the Linux sandbox; **Windows (BossKing) confirmation is pending** (commands in §5). Nothing here is marked ✅.

## 1. Headline

**H0-4 found a real, reproduced defect: an ML-DSA transaction signature does not cover the nonce, id, or gas limit, so any observer of a signed ML-DSA transaction can replay it under the sender's next nonce.** Reproduced at executor level (E-H04-1). Ed25519 signatures do cover those fields and are not affected (control test). **H0-6 did not find a defect**: its properties hold in every case tested.

Severity (proposed): **Critical for ML-DSA accounts**, which are all user accounts on an ML-DSA-only chain (`signature_scheme = "pqc-native"`, the supported devnet). It is a public-testnet **BLOCKER** unless the owner accepts a documented waiver, which I do not recommend.

## 2. H0-4

### 2.1 The defect (SR + reproduced)

- **Source:** `chain-forge-execution` `verify_mldsa_authorization` builds the message as `mldsa_tx_prehash(chain_id, serde_json::to_string(&tx.body))`; `chain-forge-crypto::mldsa_tx_prehash` hashes only `MLDSA_TX_DOMAIN_V1 || chain_id || "\n" || body_json`. The Ed25519 path signs `(id, sender, nonce, body, gas_limit, public_key)` (`Transaction::signing_bytes`). The ML-DSA message therefore omits `id`, `sender` (bound only indirectly, through which key is looked up), `nonce`, `gas_limit` and `pq_public_key`. The nonce is checked separately against account state, but it is not signed.
- **Reproduction (E-H04-1, sandbox, 3 identical runs):** an ML-DSA-signed `Transfer` of 100 executes at nonce 0 (receiver 100). The attacker changes only `id` and `nonce` to 1 and resubmits the **unchanged signature**: it executes (receiver **200**). Changing only `gas_limit` (also unsigned) at nonce 2 is accepted too. Test: `h0_4_characterization_mldsa_signed_tx_replays_under_a_new_nonce`.
- **Control:** the same manipulation on an Ed25519-signed transaction is rejected with `invalid signature` (`h0_4_control_ed25519_signed_tx_does_not_replay_under_a_new_nonce`, passes).
- **Desired-behavior test:** `h0_4_mldsa_signature_must_bind_the_nonce` is `#[ignore]`d and **fails today** (sandbox).

**Impact (reasoned from the reproduction, not exploited end to end):** anyone who sees a signed ML-DSA transaction (block explorer, gossip, mempool, the block itself) can re-execute it repeatedly, each time choosing the sender's current nonce, until the sender's balance (or the transaction's authority, e.g. a repeated bond/stake/governance action) is exhausted. They need no key. They can also alter `gas_limit` and `id`.

**Limits of the evidence:** reproduced at the executor (`execute_tx`) only. I did **not** run it through the HTTP API and mempool or across nodes. The API skips signature verification for ML-DSA transactions at ingress (RPC audit, F10) and relies on execution, so the replay would reach the executor. The duplicate-id rule added in RPC-TX-1 does not stop it because the replay uses a new id. Whether other transaction types behave identically was not tested (the body is signed, but the nonce is not, for every body).

### 2.2 Other H0-4 results (all pass, sandbox)

| Test | Result |
|---|---|
| Same-nonce replay of a committed tx at later heights (2, 3, 1000) | rejected `nonce mismatch`; `fee_charged == 0`; state root, balances and nonce unchanged (`h0_4_same_nonce_replay_across_blocks_is_rejected_with_no_state_change`) |
| Nonce boundaries 1, 2, 100, 101, `u64::MAX-1`, `u64::MAX` against an account at nonce 0 | all rejected, no mutation (`h0_4_nonce_boundaries_are_rejected_without_mutation`) |
| Committed tx replayed after a **restart** (new id, same nonce), through `submit_tx` and `propose_block` | no change to nonce or either balance (`h0_4_committed_tx_replayed_after_restart_changes_no_state`, node-level) |
| Nonce overflow at `u64::MAX` | `AccountState::increment_nonce` is `self.nonce += 1`: **panics in a debug build** (observed); in a release build the workspace sets no `overflow-checks`, so it would wrap to 0 and re-open nonce 0 (**source reading, release not run**). Practically unreachable (2^64 transactions, or a tampered state file such as the E2/E3 class). Hardening item, low |

Related and already fixed: the API's early nonce check was wrong after restart and capped accounts at 101 transactions (KNOWN_ISSUES §10, fixed by #91; doc PR #92).

## 3. H0-6

| Property | Result |
|---|---|
| Two transactions in one block try to bind **different keys** to the same unbound account | exactly one winner. The key the address derives from binds; a foreign-key tx is refused (`signing key does not match the key bound` / `not derived from the signing key`). Order `[a,b]` → `[true,false]`, order `[b,a]` → `[false,true]`, and the **same key ends up bound** in both orders (`h0_6_conflicting_key_bindings_in_one_block_have_exactly_one_deterministic_winner`) |
| Determinism | two independent runs give identical results, bound key and state root (same test) |
| ML-DSA first use cannot claim a **named** unbound account | refused (`not derived from the signing key`); no key bound, nonce unchanged (`h0_6_mldsa_first_use_cannot_claim_a_named_unbound_account`) |

Why it holds (SR): first-use binding requires `sender == address derived from the signing key` for both schemes, and `bind_key_if_unbound` only writes when no key is bound and only after a **successful** transaction. Ownership therefore follows the address derivation, so two different keys cannot both validly bind one derived address, and a named genesis account can only be bound in genesis.

**Not covered by H0-6 tests:** key rotation and recovery (`RotateAccountKey`, `RecoverAccountKey`, `CancelRecovery`), `RegisterValidatorKey`, simultaneous submissions across **different nodes** (this is executor-level determinism, not a multi-node run), and the Ed25519/ML-DSA mixed-scheme cases on a hybrid chain. Multi-node state-root agreement for these is not demonstrated here.

## 4. Proposed fix for the ML-DSA replay (DESIGN ONLY — needs owner approval; changes signing bytes)

1. **New domain `chain-forge/pq-tx/v2\n`** with a pre-hash over a canonical, length-prefixed encoding of `(chain_id, id, sender, nonce, body, gas_limit, pq_public_key)`, mirroring what Ed25519 already signs. Do not reuse JSON-tuple ambiguity: use explicit lengths and vectors (PR-A method: Python reference encoder + golden vectors, then Rust).
2. **Activation by genesis profile, not per-transaction marker:** a v2-profile chain (the fresh alpha genesis) accepts **only** v2; legacy chains keep v1. This fits the fresh-v2-genesis direction and avoids a new transaction field. Adding a genesis field is a genesis-format change that needs its own decision (see the Q3 decision record in #85).
3. **Signers to update:** `chain-forge-wallet` (two call sites), `chain-forge-scheduler` settlement, the node `tx` CLI, test helpers, and the Android wallet path (#63).
4. **Tests first:** the existing ignored test becomes the acceptance test; add a v1-signature-rejected-under-v2 test and the reverse; golden vectors; mutation checks (drop each field from the pre-hash, one test must fail per field).
5. **Interim, non-consensus:** a node-local cache of seen ML-DSA signatures in the mempool would only reduce casual replay; it does not protect against a block proposer, so it is **not** a fix.
6. Legacy v1 chains remain exposed; if any is kept running publicly it needs a published disclosure.

## 5. Evidence and Windows commands

Sandbox (Linux): the new execution tests: 8 run, 7 pass, 1 intentionally fails when `--include-ignored` is used (`h0_4_mldsa_signature_must_bind_the_nonce`); characterization output was identical over 3 runs; full `chain-forge-execution` suite 159 passed, 0 failed, 2 ignored; node test 1/1.

```bash
cd /c/Dev/chain-forge-engine
git fetch origin test/h0-4-h0-6
git worktree add ../h04-wt origin/test/h0-4-h0-6 && cd ../h04-wt
export CARGO_INCREMENTAL=0
cargo test -j 2 -p chain-forge-execution --lib -- h0_4_ h0_6_ --include-ignored --nocapture --test-threads=1
cargo test -j 2 -p chain-forge-node --bin chain-forge-node h0_4_ -- --test-threads=1
```
Expected: the execution run shows **7 passed, 1 failed** (`h0_4_mldsa_signature_must_bind_the_nonce` fails on purpose) and prints `mldsa-replay: first_ok=true replay_ok=true recv_after_first=100 recv_after_replay=200`; the node run shows 1 passed.

## 6. Disposition (proposed)

- **H0-4: stays 🔲 and is a launch BLOCKER** until the ML-DSA signing-domain fix is designed, approved, implemented and Windows-confirmed.
- **H0-6: no defect found** within the scope above; recommend marking it "tested, no finding" only after Windows confirmation and a decision on the uncovered paths (rotation, recovery, validator key registration).
