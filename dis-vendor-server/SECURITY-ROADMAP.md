# DIS-SEC-002 — Vendor Server Security Hardening

## Issues fixed

1. **Authenticated enrollment** — wallet must prove key ownership with a signature at /enroll
2. **Protected /sessions endpoint** — require API key header
3. **Proper RP identity** — vendor registers with its own rp_id/rp_origin, not derived from wallet_id
4. **Tighter CORS** — replace * with explicit allowed origins
5. **Authorization isolation** — per-vendor grant tables, not shared resource list

## Status: ✅ COMPLETE (2026-10-21)

## What was implemented
- Fix #1: Two-step authenticated enrollment (nonce challenge + ownership proof)
- Fix #2: /sessions protected with Bearer API key (401 without auth)
- Fix #3: Vendors register with their own rp_id and rp_origin
- Fix #4: CORS restricted to explicit allowed origins via ALLOWED_ORIGINS env var
- Fix #5: Per-vendor resource/action authorization isolation

---

# DIS-STATE-003 — Multi-Instance and Distributed-State Security

## Status: ✅ COMPLETE (2026-10-21)

## Architectural change

SQLite/in-memory state replaced by a shared PostgreSQL backend.
Postgres is the **single authoritative security store** — no Redis, no
second data store. Any number of server instances can serve the same
vendor fleet.

## Security invariants enforced

| Invariant | Mechanism |
|-----------|-----------|
| ML-DSA-65 signature verified **before** any DB write | `verify_inner` phases: (1) read-only checks, (2) signature check, (3) atomic consume transaction |
| Challenge consumption and revocation check are one atomic DB transaction | `SELECT … FOR UPDATE` on both the key row and the challenge row inside a single Postgres transaction |
| Challenge keys are namespaced | `dis:v1:challenge:{vendor_id}:{challenge_id}` enforced by a `CHECK` constraint in the DB schema |
| Challenge TTL in DB equals server-enforced expiration window | `CHECK (expires_at - issued_at = 299)` in `challenges` table; server constant `CHALLENGE_TTL_SECS = 299` |
| Fail closed on any DB error | Every state-dependent handler wraps `finish(…)`; any `sqlx::Error` returns HTTP 503, never "verified" |
| Revocation/verification serialise on the wallet's key row | `/admin/revoke` holds `FOR UPDATE`; `/verify` holds `FOR SHARE`. They cannot interleave |
| Admin endpoints require authentication | `DIS_ADMIN_API_KEY` env var (≥ 32 chars); constant-time digest comparison; absent → endpoints disabled |
| Enrollment nonces are bounded in lifetime | `expires_at` column in `enroll_nonces`; TTL = `ENROLL_NONCE_TTL_SECS = 300 s`; expired nonce deleted on first use attempt |

## Revocation/verification ordering rule (documented)

Both operations lock the wallet's `enrolled_keys` row before reading
or writing revocation state:

- **`/admin/revoke`** acquires `FOR UPDATE` on the key row, then
  inserts into `revocations` and commits.
- **`/verify` (phase 3)** acquires `FOR SHARE` on the key row, then
  re-reads `revocations` before marking the challenge consumed.

These locks are **incompatible**: an in-flight verification holds FOR
SHARE and blocks a concurrent revocation from proceeding; an in-flight
revocation holds FOR UPDATE and blocks any new verification from
entering its atomic phase. Consequently:

- A verification that **commits before** a revocation commits is
  honoured on every instance.
- Once `/admin/revoke` has **responded**, no instance can grant access
  to that key, regardless of which instance receives the request.

## Changes from DIS-STATE-002

| Area | DIS-STATE-002 | DIS-STATE-003 |
|------|---------------|---------------|
| State store | SQLite (per-process file) | PostgreSQL (shared across instances) |
| Challenge tracking | `consumed_challenges` table (challenge ID only) | `challenges` table: full transcript + TTL CHECK |
| Clock authority | `std::time` (per process) | `clock_timestamp()` on Postgres (single authority) |
| Signature order | Challenge consumed **before** signature check | Signature checked **before** any write |
| Admin auth | None (unauthenticated) | `DIS_ADMIN_API_KEY` Bearer token, constant-time |
| Enrollment nonce TTL | None | 300 s, enforced per `expires_at` column |
| Multi-instance replay | Not supported | Enforced by `SELECT FOR UPDATE` in shared DB |

## Acceptance tests — 11/11 passed (2026-10-21)

Tests run three times; all passes were stable. Two server instances
share one fresh Postgres database per test. A TCP proxy intercepts the
DB connection so outages can be simulated in-process.

| Test | What is verified |
|------|-----------------|
| `s3_01_two_instances_share_one_store` | Challenge issued on A is verifiable on B; replay on A rejected; challenge key namespace and TTL CHECK enforced |
| `s3_02_concurrent_proof_accepted_exactly_once` | 24 concurrent submits across both instances → exactly 1 accepted, 23 `Replay` |
| `s3_03_revocation_on_one_instance_enforced_by_other` | Revoke on A; challenge issued before revocation rejected on B; challenges issued after rejected on both |
| `s3_04_forged_proof_cannot_consume_challenge` | Bit-flipped sig, wrong key, zero-byte sig, tampered request, 16-burst concurrent forgeries — none consume the challenge; legitimate proof still accepted |
| `s3_05_server_crash_cannot_restore_consumed_challenge` | SIGKILL A after consumption; B rejects replay; restarted A rejects replay |
| `s3_06_db_outage_fails_closed` | Proxy severed: all state-dependent endpoints return HTTP 503, never "verified"; after recovery the challenge is unconsumed and accepted exactly once |
| `s3_07_db_restart_preserves_guarantees` | Real `service postgresql restart` (if `DIS_PG_RESTART_CMD` set) or simulated via proxy cut; replay and revocation state survive; new challenges accepted post-recovery |
| `s3_08_concurrent_revocation_and_verification_ordering` | (a) revocation in flight blocks verification, which is then rejected; (b) verification lock blocks in-flight revocation; (c) 40-proof race — every grant before revocation committed, every grant recorded exactly once, post-revocation proofs rejected |
| `s3_09_expiry_enforced_from_db_window` | DB-backdated challenge rejected with `Time:`; extending beyond server TTL refused by CHECK constraint |
| `s3_10_admin_endpoints_require_authentication` | Missing token → 401; wrong token → 401; truncated token → 401; state unchanged on all instances |
| `s3_11_enrollment_nonce_expires_and_is_single_use` | Backdated nonce → `expired` error; expired nonce deleted (second attempt → `no enroll challenge`); fresh nonce works; replay of valid nonce after use rejected |

### Test environment note

`s3_07` performs a real `service postgresql restart` only when
`DIS_PG_RESTART_CMD` is set. Without it the test simulates a restart
by severing all proxy connections for one second and reconnecting.
The simulated path exercises pool reconnection but not Postgres
WAL-based durability; consider running with a real restart before
promoting to production.

## Remaining gaps (out of scope for DIS-STATE-003)

- `/vendor/register` has no authentication — any caller can register a vendor.
- Consumed and expired `challenges` rows are never purged (no background sweep).
- `dis_state.db*` SQLite files committed on earlier branches are no longer used and can be removed.
- Enrollment nonces issued by one instance expire on the DB clock but a
  just-expired nonce can still pass a pre-check on an instance with clock
  skew relative to the DB. The `FOR UPDATE` path in `/enroll` re-reads
  the expiry from the DB, so actual acceptance requires the DB to agree.
