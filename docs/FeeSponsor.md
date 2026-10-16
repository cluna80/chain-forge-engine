# FeeSponsor — Design Specification

Status: Draft

This document defines the FeeSponsor feature for Qattice (QCB Chain). It encodes the security, determinism, and operational rules needed to safely let third parties (sponsors) pay transaction fees on behalf of users.

Goals
- Allow pre-funded SponsorAccounts to pay uQCB transaction fees for user-submitted transactions.
- Require dual authorization: user's transaction signature + sponsor-signed authorization bound to a canonical unsigned transaction body.
- No automatic fallback to user wallet: a transaction that requests sponsorship must fail if the sponsor cannot or will not pay (unless the user separately attaches an explicit fallback authorization).
- Deterministic on-chain semantics: every node must deterministically reach the same decision about whether a transaction is accepted and which account is debited for fees.
- Scalable single-use authorizations with clear replay and revocation rules.

High-level decisions and responses to prior review
1. No automatic fallback to user's wallet
   - If a transaction includes a SponsorAuthorization and the sponsor cannot or will not pay (policy, expired auth, insufficient sponsor_balance, revocation), the transaction is rejected with `Err::SponsorUnavailable` and NOT charged to the user's wallet.
   - If users want fallback, the user must attach an explicit `FallbackAuthorization` (signed by the user) that authorizes charging the user's wallet if sponsorship fails. This explicitness prevents accidental charges.

2. Canonical transaction hashing (no circular hashes)
   - Define `CanonicalUnsignedTx` as the transaction body that excludes any fee sponsorship envelope fields (SponsorAuthorization or Sponsor metadata). The sponsor signs the hash of `CanonicalUnsignedTx`.
   - The node computes `tx_hash = SHA256(canonical_serialize(CanonicalUnsignedTx))` and requires SponsorAuthorization.tx_body_hash == tx_hash.
   - SponsorAuthorization is attached separately to the transaction envelope and is not included in the hashed payload used for the sponsor signature.

3. Fee charging vs. transaction success
   - Fee calculation is deterministic and performed before invoking state transitions for the transaction's application logic. Execution pipeline (per-node) is:
     1. Validate user signature(s) and canonical format.
     2. Compute `intrinsic_gas` and `fee = gas_price * intrinsic_gas` deterministically.
     3. Validate SponsorAuthorization (if present): signature, expiry, policy, and `tx_body_hash` match.
     4. Ensure fee payer (sponsor if valid & allowed; otherwise user) has sufficient balance to cover `fee`. If sponsor path selected but sponsor cannot cover, reject immediately (no fallback).
     5. Reserve (debit) `fee` from fee payer as part of the atomic execution transaction. The atomic commit must debit fee and update other application-state writes in a single deterministic commit.
     6. Run application logic (state transition). If application logic fails:
        - Fee charging policy decides whether the previously-reserved fee remains charged or is refunded. The default protocol policy (safe and deterministic) is: fee is retained — sponsors who sponsor accepted transactions pay gas even when the transaction body fails. This matches relayer economics and prevents sponsored denial-of-service attack vectors. SponsorPolicy allows opting out but the default is deterministic.
        - Application state writes are rolled back by the execution environment; only fee debit persists per its deterministic policy.
   - Rationale: separating fee debit from application success keeps accounting deterministic and avoids partial state commits that could differ across nodes.

4. Scalable, single-use authorizations & revocation
   - SponsorAuthorization is a single-use authorization token with a strong random `auth_id` (128-bit or 256-bit). Single-use prevents reuse without requiring a global incrementing nonce.
   - Storage model:
     - `SponsorAccount` includes: sponsor_id, pubkey, balance_uqcb, policy, revoked_until_block (optional), and `consumed_auths` mapping pointing to auth_id → expiry_block. Nodes store consumed auth IDs until expiry_block and may prune them once block > expiry_block + GC_WINDOW.
     - Each SponsorAuthorization must include `auth_id` and `expires_at_block`; nodes reject authorizations already present in `consumed_auths`.
   - Revocation semantics:
     - Immediate revoke of a sponsor (stop new sponsorships) is supported by setting `SponsorAccount.revoked = true` or `revoked_until_block = B`. Any SponsorAuthorization with `issued_at_block <= revocation_block` and not consumed may be considered invalid. To avoid race conditions for in-flight short-lived auths, we require that SponsorAuthorization contains `issued_at_block` and nodes consider revocation if `issued_at_block <= revoked_until_block`.
     - Batch revocation: sponsor may publish `RevokeAuthPrefix { sponsor_id, before_block }` that makes all authorizations issued before `before_block` invalid. This avoids iterating over thousands of auths.
   - Expiry window & pruning:
     - SponsorAuthorization must expire within a bounded time (recommended default: 12 hours). Short expiry bounds storage needs because consumed_auths are stored only until expiry + GC_WINDOW (e.g., GC_WINDOW = 1 week). This keeps on-chain storage bounded and predictable.

Data model (suggested Rust-like types)
- SponsorAccount
```rust
struct SponsorAccount {
  sponsor_id: SponsorId,
  pubkey: Vec<u8>, // ML-DSA-65 pubkey
  balance_uqcb: u128,
  policy: SponsorPolicy,
  revoked_until_block: Option<u64>,
  // mapping used to prevent reuse: auth_id -> expiry_block
  consumed_auths: BTreeMap<AuthId, u64>,
}
```

- SponsorPolicy
```rust
struct SponsorPolicy {
  per_tx_max_fee_uqcb: u128,
  epoch_budget_uqcb: u128,
  allowed_tx_kinds: Option<Vec<TxKind>>,
  allowed_recipients: Option<Vec<Address>>,
  allowed_users: Option<Vec<Address>>, // user addresses sponsor allowed to pay for
  pay_on_failure: bool, // default true
}
```

- SponsorAuthorization (signed by sponsor's private key)
```rust
struct SponsorAuthorization {
  auth_id: [u8;16], // 128-bit random
  sponsor_id: SponsorId,
  tx_body_hash: [u8;32], // SHA256 of CanonicalUnsignedTx
  max_fee_uqcb: u128,
  issued_at_block: u64,
  expires_at_block: u64,
  scope: Option<Scope>,
  signature: String, // mldsa65:<hex>
}
```

CanonicalUnsignedTx (what sponsor signs)
- The canonical unsigned transaction serialization that excludes any sponsor envelope fields and any other meta fields that would otherwise create circularity.
- All nodes must use the same canonical serializer (documented serialized field order) to compute `tx_body_hash = SHA256(canonical_serialize(CanonicalUnsignedTx))`.

Transaction envelope
- The final wire transaction is:
  { user_signed_body, optional SponsorAuthorization, optional FallbackAuthorization }
- Nodes validate user signature(s) against `user_signed_body` and compute tx_body_hash from `user_signed_body` only.
- If SponsorAuthorization is present, nodes verify binding to tx_body_hash and sponsor signature.

Execution flow (deterministic)
1. Validate user signature(s). Reject if invalid.
2. Compute `tx_body_hash` from the canonical unsigned tx body.
3. If SponsorAuthorization present:
   - Verify sponsor signature over canonical string:
     "qcb/sponsor-auth/v1\n" || chain_id || "\n" || hex(tx_body_hash) || "\n" || auth_id || "\n" || max_fee || "\n" || issued_at_block || "\n" || expires_at_block
   - Check `issued_at_block <= current_block <= expires_at_block` and `expired` guard.
   - Check SponsorAccount.revoked_until_block and RevokeAuthPrefix rules.
   - Check sponsor policy: `max_fee <= per_tx_max_fee` && tx_kind in allowed_tx_kinds && user in allowed_users (if present).
4. Compute `intrinsic_gas` and `fee = gas_price * intrinsic_gas` deterministically.
5. If SponsorAuthorization present and valid: ensure sponsor `balance_uqcb >= fee` and `epoch_budget` available. If not sufficient, reject immediately with `Err::SponsorUnavailable` (no fallback). If sufficient, debit sponsor balance and mark `auth_id` consumed atomically in the same commit.
6. If SponsorAuthorization not present: default payer is user. Use existing semantics for user fee debit.
7. Execute application-level tx body. The execution environment must guarantee atomicity: fee debit + auth_id consumption + application state writes commit together. If execution fails, roll back application state writes; persist fee debit depending on policy `pay_on_failure` (default true).

Anti-replay & cross-chain protection
- SponsorAuthorization includes `chain_id` binding in the signed payload. Nodes reject SponsorAuthorization where the chain_id differs.
- Single-use `auth_id` prevents replay. Nodes reject consumed `auth_id`.
- Because auths expire and expired consumed auths are pruned, storage cost remains bounded.

Revocation & race handling
- To avoid race conditions where sponsor revokes after issuing authorizations but before consumption, we use `issued_at_block` + `revoked_until_block` semantics:
  - If sponsor publishes `RevokeAuthPrefix { before_block = X }`, all authorizations issued at or before X are invalid afterwards (deterministic and immediate). Nodes enforce this in validation step.
- Sponsors that need immediate stop-of-service can mark `revoked = true` which rejects all future sponsorship validations.

Deterministic budgeting (epoch enforcement)
- Track `epoch_spent` per SponsorAccount. Epoch periods are canonical (e.g., defined by block height: epoch = floor(block_height / EPOCH_LENGTH_BLOCKS)).
- When charging fee, also decrement `epoch_budget` and reject when exhausted.

Acceptance tests (automatable)
- Valid happy-path sponsored tx: sponsor signs auth, sponsor has balance & policy allows, transaction is accepted, sponsor balance debited by fee.
- Sponsor insufficient balance: transaction rejected with `SponsorUnavailable` (no fallback charged).
- Sponsor auth expired: rejected.
- Forged sponsor signature: rejected.
- Cross-chain replay: sponsor auth for chain A rejected on chain B (chain_id binding).
- Duplicate auth_id usage: second attempt rejected.
- Revocation before consumption: any auth with `issued_at_block <= revoked_until_block` is rejected.
- Policy-enforcement tests: denied tx kinds, denied recipients, per_tx_max_fee exceeded.
- Multi-node deterministic test: submit same sponsored tx to 3 nodes; nodes agree on final state (balances, applied tx result/fee debit). Run adversarial sequence (sponsor spends balance between issue and execution) and verify deterministic rejection.

Implementation notes & incremental plan
1. Add docs/FeeSponsor.md to repo (this document) — establish canonical serialization and signing strings.
2. Implement SponsorAccount storage and CreateSponsorAccount/DepositSponsor txs with unit tests.
3. Implement SponsorAuthorization verification utilities and canonical tx hashing helper.
4. Extend transaction envelope parsing to accept SponsorAuthorization; ensure it is excluded from canonical tx hash.
5. Modify execution engine to compute deterministic fee, validate sponsor path, and perform atomic debit + auth consumption + application execution.
6. Add explorer endpoints: /api/sponsors/{id}, /api/sponsors/{id}/policy, /api/sponsors/{id}/consumed-auths (optional read-only, respect privacy if needed).
7. Add SDK helpers for sponsor signing (Rust + TypeScript) and example flows.

Engine modularization
- Recommend implementing FeeSponsor as an optional engine module (feature flag) in the Chain Forge Engine. Qattice can enable it by default. This keeps the capability reusable for other chains without forcing it into all deployments.

Open questions for maintainers
- Default sponsor `pay_on_failure` policy: we recommend `true` (sponsor pays gas on failure). Confirm.
- Sponsor auth expiry default: recommend 12 hours. Confirm tolerance for expected wallet/sponsor latency.
- GC window for consumed_auths pruning: recommend 1 week. Confirm storage budget.
- On-chain storage format for consumed_auths: BTreeMap vs. a specialized paged storage. If sponsors are high-volume, consider compacting consumed auth ids per epoch into bitmaps or Bloom filters with epoched replay windows (tradeoff: false positive risks). For now keep exact set to avoid FP.

Next steps
- If this draft is acceptable I will commit it into `docs/FeeSponsor.md` (this commit) and then create a small issue listing the first implementation tasks (SponsorAccount + Deposit). After that I can open PRs implementing the pieces incrementally with tests and devnet runs.

Security invariants (brief)
- SponsorAuthorization must be single-use and bound to tx_body_hash & chain_id.
- Sponsor cannot withdraw balance that would allow previously-signed authorizations to be executed (consumption checks cover this at execution time; if sponsor spends between signing and execution, the tx is rejected deterministically).
- No implicit fallback charging of user wallets.
- All nodes must compute fee and policy checks deterministically.

References
- Chain Forge canonical tx serialization rules (TBD) — must be added to this doc as soon as `serialize_tx()` helpers are finalized.
- ML-DSA signing scheme conventions used across the repo.

