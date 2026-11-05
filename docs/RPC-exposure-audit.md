# Public RPC exposure audit — node HTTP API (DRAFT, read-only)

Base: `origin/main` @ `b09df3b`; file audited: `chain-forge-node/src/api.rs` (2,113 lines), with `auth.rs`, `main.rs` and `node.rs` where cited. Documentation only: no production change, no server started, nothing exposed. Not merged. Companion to #88 (release plan) and #89 (G0 inventory).

## 0. Method and limits

- **Done:** read every route handler in the `serve()` dispatch (`api.rs` lines ~225–1625), the request reader, CORS helpers, the challenge store, the tx queue drain in `node.rs`, and the CLI bind options. Grepped for feature gates, auth, rate limits, key handling.
- **Not done:** no request was sent to any server; no finding below was **reproduced**. Everything is **source reading** ("SR"). Severity is a proposal.
- **Not covered:** the libp2p listener (P2P port) is a separate surface; the Android wallet; the contents of `NodeStatus`; whether ML-DSA signatures are verified later in execution (found only that ingress skips them, see F10).
- Line numbers are approximate and from the file at `b09df3b`.

## 1. Surface summary (SR)

| Property | Finding | Evidence |
|---|---|---|
| Listener | One plain-TCP HTTP listener for **all** routes, bound to `0.0.0.0:{--api-port}` (default 8080). There is no bind-address option. | `api.rs ~148`; `main.rs ~73–95` |
| TLS | None. | no TLS code in `api.rs` |
| Authentication | **None on any route.** `/api/auth/*` is a signed-challenge protocol for wallet identity, not API access control. | whole dispatch |
| Authorization | Only inside `POST /api/tx` body checks (settlement operators, attestation coordinator, governance authorities). No caller-level role. | `api.rs ~456–560` |
| Feature gates | **None.** Only `#[cfg(test)]` appears in `api.rs`. Every route below is compiled into the default build. | grep `cfg(` → lines 1726, 1781 (tests) |
| Routing | `first_line.starts_with(...)` prefix match, first match wins; no exact-path or method validation (e.g. `POST /api/txanything`, `GET /api/statusX` route to the handlers). | `api.rs ~225–1619` |
| CORS | `Access-Control-Allow-Origin: *` on every response; preflight allows `GET, POST, OPTIONS`, header `Content-Type`. | `api.rs ~1736, 1749` |
| Request limits | Header block ≤ 16 KiB; body ≤ `max_tx_bytes` (0 ⇒ 1 MiB) read with a timeout of 5 s + 1 s per 16 KiB (≤ 60 s); one request per connection. | `api.rs ~1639–1680`, `~178–215` |
| Connection limits / rate limiting | **None found**: `listener.accept()` spawns a task per connection; no cap, no per-IP limit, no request-rate limit. | `api.rs ~151–175` |
| Shared state | Handlers lock `Arc<Mutex<..>>` (`explorer`, `status`, `peers`, `tx_queue`, `pocd_registry`, `challenge_store`). The node commit path takes the **same** `explorer` mutex (22 `explorer.lock()` occurrences in `node.rs`, some in tests). | `node.rs` grep `explorer.lock()` |
| Key material | No handler reads, writes or returns private keys. Signing keys come from `--key-file` at start-up, not over the API. | grep of `api.rs` |

## 2. Endpoint matrix

Classes: **PR** public read-only, **PS** public transaction submission, **AO** authenticated operator (none exist), **DEV** development/debug only, **INT** internal-only. "Release build" = reachable in the default build (all are, see §1). Side effects are mutations of node memory/disk.

| # | Method + path (as matched) | Line | Class (proposed) | Auth / checks | Side effects | Resource-exhaustion notes | Reachable in release build |
|---|---|---|---|---|---|---|---|
| 1 | `GET /api/status` | ~225 | PR | none | none | small | yes |
| 2 | `GET /api/health` | ~229 | PR | none | none | constant | yes |
| 3 | `POST /api/tx` | ~231 | **PS** | JSON depth ≤ 32, body ≤ `max_tx_bytes`, policy/size/module checks, replay + nonce-gap, balance check on `Transfer`, signature check (non-ML-DSA), operator/coordinator/governance sender checks | pushes to `tx_queue` (unbounded `Vec`, drained once per heartbeat) | **queue unbounded between ticks**; ML-DSA txs skip ingress signature verification; response says "queued" before `submit_tx` runs (F10, F13) | yes |
| 4 | `POST /api/build` | ~587 | DEV | none | none: parses JSON, logs `chain_id`, returns "accepted" (stub; hard-codes port 8080 in the reply) | parse cost ≤ body limit | yes |
| 5 | `GET /api/blocks/{h}` | ~620 | PR | none | none | linear scan of `explorer.blocks` under the shared lock | yes |
| 6 | `GET /api/blocks` | ~631 | PR (**needs pagination**) | none | none | serializes **all** retained blocks while holding the `explorer` lock (F2) | yes |
| 7 | `GET /api/tx/{id}` | ~636 | PR | none | none | map lookup | yes |
| 8 | `GET /api/identity/{addr}` | ~645 | PR (decision: exposes `attested_by`, `frozen`, `sybil_confirmed`) | none | none | map lookup | yes |
| 9 | `GET /qcb/resource/balance?account=` | ~684 | PR (**QRC-era route, flag**) | none | none | map lookup | yes |
| 10 | `GET /api/accounts/{addr}` | ~700 | PR | none | none | map lookup | yes |
| 11 | `GET /api/accounts` | ~709 | PR (**enumerates every account; needs pagination or removal**) | none | none | full sort + serialize under lock (F2) | yes |
| 12 | `GET /api/qrc` | ~715 | PR (**QRC route, flag; retired protocol**) | none | none | small | yes |
| 13 | `GET /api/validators/status` | ~719 | PR | none | none | small | yes |
| 14 | `GET /api/validators` | ~724 | PR | none | none | small | yes |
| 15 | `GET /api/peers/capacity` | ~730 | INT (peer topology/capacity) | none | takes the capacity-table lock, prunes entries | small | yes |
| 16 | `GET /api/peers` | ~745 | INT (peer list leaks network topology) | none | none | small | yes |
| 17 | `POST /api/gc-receipt` | ~749 | **INT** (should be operator-only) | **none; no validation** of any field | inserts arbitrary JSON into `explorer.gc_receipts` (cap `MAX_GC_RECEIPTS = 500` entries, each up to the body limit) | up to 500 × body limit retained (≈ 32 MB at 64 KiB; more with larger `max_tx_bytes`); served back by #18 (F3) | yes |
| 18 | `GET /api/gc-receipts` | ~816 | INT | none | none | serializes up to 500 stored blobs | yes |
| 19 | `GET /api/jobs/{id}`, `GET /api/jobs` | ~822, ~841 | INT (job market state) | none | none | scans `explorer.accounts` for `job:` keys, parses each `role` as JSON, under lock | yes |
| 20 | `POST /genesis` | ~876 | DEV (wizard helper) | none | parses and validates a `GenesisConfig`, returns canonical JSON; I found **no file or state write** | CPU for parse + `validate()`; reply echoes the config | yes |
| 21 | `GET /api/pocd/challenges`, `/receipts`, `/rewards` | ~919, ~936, ~953 | INT | none; "disabled" reply if PoCD is off | none | reads the node-local registry; `/rewards` aggregates per request | yes |
| 22 | `POST /api/pocd/submit` | ~1003 | **INT** (should be miner-authenticated) | seal self-check `verify_seal()` only; receipt is stamped verifier `"self-verifier"`, signature `"devnet-no-sig"` | inserts a receipt into the node-local `DiscoveryRegistry` (HashMap; I found no size cap in the handler) | unbounded growth; not consensus-affecting today (reward consumer is disabled, see STATE-COMMIT-2 §12) (F4) | yes (only matters when PoCD enabled in genesis) |
| 23 | `POST /api/auth/challenge` | ~1094 | PR (wallet-auth protocol) | none | inserts a challenge into `ChallengeStore` (cap `MAX_PENDING_CHALLENGES = 1024`, evict oldest) | each insert does an O(n) `retain` over ≤ 1,024 entries; a flood evicts legitimate pending challenges (F6) | yes |
| 24 | `POST /api/auth/verify` | ~1132 | PR (wallet-auth protocol) | challenge must exist; delegation chain depth ≤ 4; ML-DSA signature verified | consumes the challenge on success | **unauthenticated ML-DSA verification work per request** (CPU) (F6) | yes |
| 25 | `POST /api/dis/verify_delegated` | ~1343 | PR/DEV (**misleading**) | structural checks; depth ≤ `MAX_CHAIN_DEPTH` | updates delegation-usage counters (persisted under `<data_dir>/persist/dis_delegation_usage.json` when a data dir is set) | counter file writes; **when the body is not a `VerifyRequest` it returns `"status":"verified"` with "crypto verification skipped for vendor format"** (F5) | yes |
| 26 | `POST /debug/inject_view_change`, `/api/debug/inject_view_change` | ~1586 | **DEV** | none | none: discards payload, returns 200 "discarded" | constant | yes (**not gated**) |
| 27 | `POST /debug/inject_vote`, `/api/debug/inject_vote` | ~1593 | **DEV** | checks `chain_id` field only | none: discards | constant | yes (**not gated**) |
| 28 | `POST /debug/inject_proposal`, `/nil_block` (+ `/api/debug/…`) | ~1613 | **DEV** | none | none: discards | constant | yes (**not gated**) |
| 29 | `OPTIONS *` | ~1619 | PR | none | none | constant | yes |
| 30 | anything else | ~1625 | – | – | 404 | – | – |

Handlers 26–28 are stubs: I found no path from them into the consensus engine (comments say "discards the payload"). Their risk is surface and credibility, not a demonstrated injection.

## 3. Findings (all SR, not reproduced)

| ID | Finding | Sev. (proposed) | Evidence |
|---|---|---|---|
| F1 | No authentication, TLS, connection cap or rate limit; listener on `0.0.0.0`; all routes on one port | **High** for any public endpoint | §1 |
| F2 | Unbounded list endpoints (`/api/blocks`, `/api/accounts`, `/api/jobs`, `/api/gc-receipts`) serialize large state **while holding the `explorer` mutex that the node's commit path also takes** → an unauthenticated client can stall block processing by repeated large reads, and memory scales with chain/account count | **High** | rows 6, 11, 18, 19; `node.rs`: 22 `explorer.lock()` occurrences, some in tests. Needs a reproduction test before relying on it |
| F3 | `POST /api/gc-receipt` stores arbitrary unvalidated JSON and `GET /api/gc-receipts` serves it back (content injection for any explorer UI; ≤ 500 blobs) | Medium | row 17 |
| F4 | `POST /api/pocd/submit` is unauthenticated and creates "devnet-no-sig" receipts in an uncapped node-local registry | Medium (node-local; no consensus effect today) | row 22 |
| F5 | `POST /api/dis/verify_delegated` can return `"verified"` for a body that only passes structural checks (crypto skipped). A client that treats `"verified"` as proof is misled | **Medium–High** if any consumer relies on it | row 25 |
| F6 | `/api/auth/challenge` is an unauthenticated store write (cap 1,024, oldest evicted) and `/api/auth/verify` triggers ML-DSA verification per request → challenge-eviction and CPU DoS | Low–Medium | rows 23–24; `auth.rs ~510–550` |
| F7 | Debug/inject stubs compiled into the release build with no gate | Low (surface) | rows 26–28 |
| F8 | `POST /api/build` and `POST /genesis` are wizard helpers on the production listener (no state write found); they add parse cost and an unnecessary surface | Low | rows 4, 20 |
| F9 | CORS `*` for all routes incl. `POST`; acceptable for read-only and signed submission, but combined with F1 any web page can drive the API from a visitor's browser | Low | §1 |
| F10 | `POST /api/tx` skips `verify_signature` for ML-DSA transactions at ingress (`sig_scheme == MlDsa`) and queues them in an unbounded `Vec`; the "queued" reply is returned **before** the heartbeat drain runs `Node::submit_tx` (which now enforces the O8 bounds and the signature policy). Clients can be told "queued" for a tx that is then dropped. Where ML-DSA signatures are verified afterwards was **not** established here | Medium | `api.rs ~440`; `node.rs ~2939` |
| F11 | Prefix routing means the node accepts non-canonical paths; a proxy allowlist must match exactly and must not rely on the node to reject odd paths | Low (design note) | §1 |
| F12 | Open KNOWN_ISSUES §10 caps each account at ~101 API-submitted transactions; this directly limits a public faucet or tester | High for usability | KNOWN_ISSUES §10 |
| F13 | QRC-era routes (`GET /api/qrc`, `GET /qcb/resource/balance`) remain on the public surface; QRC is retired — flagged for the later cleanup, not changed here | Info | rows 9, 12 |

## 4. Proposed minimal public-RPC allowlist (reverse proxy in front; node API not exposed)

Exact-match, method-pinned, everything else denied by default. The node itself should keep listening on loopback or a private interface.

| Allow | Notes |
|---|---|
| `GET /api/health` | liveness for load balancers |
| `GET /api/status` | after review of the `NodeStatus` fields exposed |
| `GET /api/blocks/{height}` | numeric height only; reject non-digits |
| `GET /api/blocks?from=&limit=` | **only once the node (or proxy cache) paginates**; until then serve a cached latest-N snapshot from the proxy |
| `GET /api/tx/{id}` | id charset and length-limited |
| `GET /api/accounts/{addr}` | address length-limited (≤ 256, matches O8) |
| `GET /api/validators`, `GET /api/validators/status` | |
| `POST /api/tx` | body ≤ `max_tx_bytes`, `Content-Type: application/json`, per-IP and per-account rate limits |
| `GET /api/identity/{addr}` | optional; decide whether attestation relationships may be public |

**Deny at the proxy:** `GET /api/accounts` (list), `GET /api/peers*`, all `/api/gc-receipt*`, all `/api/pocd/*`, all `/api/jobs*`, `/api/auth/*` and `/api/dis/*` (unless the wallet-auth feature is part of the alpha, then separate rate limits), `POST /genesis`, `POST /api/build`, all `/debug/*` and `/api/debug/*`, `/api/qrc`, `/qcb/resource/*`.

## 5. Hardening recommendations (for separate, tested PRs; none done here)

1. **Gate or remove** the debug stubs and the wizard helpers (`/api/build`, `/genesis`) from release builds (Cargo feature or `cfg`), so they cannot be reached even if the proxy is misconfigured.
2. **Add a bind-address option** (default loopback) so validators do not expose the API; keep `0.0.0.0` an explicit choice.
3. **Do not hold the `explorer` mutex while serializing**: clone a bounded snapshot, release, then serialize; add limits/pagination to the list endpoints (F2).
4. **Bound** `tx_queue` (reject with 503 when full), `gc_receipts` size per entry, and the PoCD registry; authenticate or remove `/api/gc-receipt` and `/api/pocd/submit` (F3, F4).
5. **Make `verify_delegated` honest**: never return `"verified"` for a structural-only pass; use a distinct status (`structure_ok`) or remove (F5).
6. **Connection cap and per-IP rate limits** (in the proxy at least; in the node as defense in depth); request-rate limits on `/api/auth/*` (F6).
7. **Make the tx reply truthful**: run the same admission (`check_admission_bounds`, signature policy, duplicate check) before replying "queued", or reply "accepted-for-validation" and expose a status lookup (F10).
8. **Fix KNOWN_ISSUES §10** before launching a faucet (F12).
9. **Exact-path routing** with a method check, 405 for known paths with wrong methods (F11).
10. TLS and CORS policy at the proxy: restrict origins for `POST` if a first-party web client is the only intended browser caller (F9).

## 6. Negative security-test plan (proposed; **none written or run**)

Tests run against a test server on loopback; nothing is exposed publicly. IDs are proposals. Each should be tests-first (expected to fail where the finding is real), then fixed, then confirmed on Linux and Windows per CLAUDE.md.

| ID | Test | Expected after fix |
|---|---|---|
| RPC-N01 | A release-feature build answers 404 to every `/debug/*`, `/api/debug/*`, `POST /api/build`, `POST /genesis` | 404 |
| RPC-N02 | With 5,000 accounts and 5,000 blocks, concurrent `GET /api/accounts` and `GET /api/blocks` do not delay block commit beyond a bound (measure commit latency with and without the load) | bounded; list endpoints paginated |
| RPC-N03 | `POST /api/tx` ×N faster than the drain interval does not grow `tx_queue` beyond its cap | 503/429 past the cap |
| RPC-N04 | `POST /api/tx` with an over-bound address/denom returns **rejected**, not "queued" (E5 at the API) | 400 with reason |
| RPC-N05 | A forged/invalid ML-DSA transaction is rejected at ingress or provably dropped before block inclusion, and never reported "queued" as valid | rejected |
| RPC-N06 | `POST /api/gc-receipt` and `POST /api/pocd/submit` without credentials are refused; stored entries are size-bounded | 401/403 |
| RPC-N07 | `verify_delegated` with a non-`VerifyRequest` body never returns `"verified"` | `structure_ok` or error |
| RPC-N08 | 1,500 `POST /api/auth/challenge` from one client cannot evict another client's pending challenge (per-client quota) | other client's challenge survives |
| RPC-N09 | Slow-header/slow-body connections beyond a cap are refused or timed out without exhausting file descriptors | cap enforced |
| RPC-N10 | Non-canonical paths (`/api/txfoo`, `/api/statusX`, `//api/tx`, encoded slashes) are 404/405 | 404/405 |
| RPC-N11 | A request with `Content-Length` larger than the limit gets 413 and the connection is drained | 413 |
| RPC-N12 | Allowlist proxy: every denied route in §4 returns 403/404 and every allowed route returns the node's response unchanged | per table |
| RPC-N13 | Account with > 101 API-submitted transactions still accepted (KNOWN_ISSUES §10) | accepted |
| RPC-N14 | Response never contains private-key material (scan all GET responses on a seeded node for key-file contents) | none |

## 7. What this audit does not establish

It does not show any finding is exploitable in practice (nothing was run), does not cover the P2P listener or the wallet apps, does not decide that any route is removed, and does not claim the allowlist is sufficient: a real deployment also needs TLS, monitoring, abuse handling and an owner decision on which of the optional routes (identity, wallet-auth) belong in the alpha.
