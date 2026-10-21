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

---

# DIS-SEC-004 — Authenticated Vendor Registration

## Status: ✅ COMPLETE (2026-10-21)

## Problem

`/vendor/register` was fully unauthenticated. Any caller could:
- Claim an arbitrary vendor identity on first call (squatting).
- Register a vendor pointing at an rp_origin they do not control
  (origin confusion: a challenge issued under that vendor would carry
  an rp_origin mismatch for any legitimate holder).

## What was implemented

| Control | Mechanism |
|---------|-----------|
| **Registration key** | `DIS_VENDOR_REGISTRATION_KEY` env var (≥ 32 chars, same constant-time check as admin key). Absent → HTTP 403 (disabled), wrong/missing token → 401. |
| **Origin ownership proof** | Before writing to the DB the server fetches `{rp_origin}/.well-known/dis-vendor-registration` and checks that the response body equals `SHA-256("{vendor_id}:{registration_token}")`. Token binds to both the origin and the vendor identity, so it cannot be replayed across vendors or origins. |
| **origin_verified_at column** | Set to `clock_timestamp()` on successful origin verification (migration 0003). Rows inserted without origin verification (e.g. migrated from an earlier schema) have `NULL` and cannot issue challenges. |
| **Vendor identity immutability** | Once a vendor_id is registered, re-registration is rejected. The rp_origin is fixed at registration time. |

## Ordering invariant for origin verification

Origin ownership is verified **before** the vendor row is written to the
database. An origin check that fails leaves no trace in the DB, so an
attacker cannot partially claim an identity.

## Acceptance tests — 5 new, 16/16 total passed (2026-10-21)

Five consecutive runs; all 16 tests (11 from DIS-STATE-003, 5 new) passed every run.

| Test | What is verified |
|------|-----------------|
| `s4_01_vendor_register_requires_registration_key` | Missing, wrong, truncated token → 401/403 on both instances; no vendor row created; correct key succeeds |
| `s4_02_origin_ownership_verified_before_registration` | (a) nothing at well-known → 403; (b) wrong token → 403; (c) correct token → registered + `origin_verified_at` set; (d) replay of same vendor_id → rejected |
| `s4_03_vendor_identity_takeover_prevented` | Squatting (second origin claiming same vendor_id) rejected; cross-token confusion (correct origin, wrong token binding) rejected; only one vendor row exists |
| `s4_04_unreachable_origin_rejected` | Dead port → connection refused → 403; no vendor row created |
| `s4_05_unverified_vendor_cannot_issue_challenges` | Vendor row with `origin_verified_at = NULL` (direct DB insert, simulating old-schema migration) → challenge endpoint returns error on both instances |

## Remaining gaps (updated after DIS-SEC-005)

- Consumed/expired `challenges` rows are never purged (no background sweep).
- `dis_state.db*` SQLite files on earlier branches are no longer used.
- Vendor registration tokens are single-use by convention but not enforced by
  the DB (a second registration attempt with the same token is rejected by the
  `already registered` check, not by a used-token table).
- DNS rebinding: the pre-flight IP check and the outbound request use the OS
  resolver independently; an attacker who controls DNS TTLs can change the
  answer between the two calls. Mitigated by requiring HTTPS (which requires
  a valid cert for the hostname) and by the per-connection TLS handshake, which
  would fail for an IP the attacker doesn't control a cert for.

---

# DIS-SEC-005 — SSRF Hardening for Origin Verification

## Status: ✅ COMPLETE (2026-10-21)

## Problem

`verify_origin_ownership` constructed an outbound URL from the caller-supplied
`rp_origin` and made an HTTP GET request without:
- enforcing HTTPS (plain HTTP allowed any caller to use an unencrypted channel)
- validating URL structure (path/query/fragment components not rejected)
- blocking private/loopback/internal IP destinations (SSRF)
- rejecting HTTP redirects (a redirect could steer the request to an internal endpoint)

## What was implemented

| Control | Mechanism |
|---------|-----------|
| **HTTPS enforcement** | `validate_origin_url` rejects any scheme other than `https` (or `http` when `DIS_ALLOW_HTTP_ORIGINS=1` is set for tests). |
| **URL structure validation** | `validate_origin_url` rejects credentials, path components beyond `/`, query strings, and fragments. |
| **Internal IP blocking** | `validate_origin_ips` resolves the hostname before making the request and rejects loopback (127/8, ::1), private RFC1918 (10/8, 172.16/12, 192.168/16), link-local (169.254/16), CGNAT (100.64/10), multicast, broadcast, and unspecified addresses. IP literals in the origin hostname are also checked directly. |
| **Redirect suppression** | `reqwest::redirect::Policy::none()` set at client construction — a 302/301/etc. response from the well-known endpoint causes the request to fail, not follow. |
| **Test-mode bypass** | `DIS_ALLOW_HTTP_ORIGINS=1` env var (read once at startup) enables HTTP origins and skips the IP check for integration tests that use localhost OriginMock servers. Set in `Server::start_on()` only. |
| **Well-known URL constructed from parsed origin** | The outbound URL is built from the `url::Url`-parsed origin, not the raw string, preventing path traversal or parser inconsistency. |

## Acceptance tests — 3 new, 19/19 total passed (2026-10-21)

| Test | What is verified |
|------|-----------------|
| `s4_06_ssrf_internal_addresses_rejected_in_prod_mode` | HTTP scheme, loopback IPv4/IPv6 literals, private RFC1918, link-local, CGNAT, and `localhost` hostname all rejected in production mode; no vendor row created |
| `s4_07_redirect_from_well_known_blocked` | Well-known endpoint returning 302 redirect → registration rejected; redirect destination not contacted |
| `s4_08_malformed_origin_url_rejected` | Non-URL string, FTP scheme, credentials, path, query, fragment, empty host, HTTP without allow flag — all rejected with appropriate error messages; no vendor row created |

## Remaining gaps

- Consumed/expired `challenges` rows are never purged (no background sweep).
- `dis_state.db*` SQLite files on earlier branches are no longer used.
- Vendor registration tokens are single-use by convention but not enforced by the DB.
- DNS rebinding window between IP pre-check and actual connection (see note above).
