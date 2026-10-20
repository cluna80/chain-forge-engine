# DIS-SEC-002 — Vendor Server Security Hardening

## Issues to fix (in priority order)

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

# DIS-SEC-002 — Vendor Server Security Hardening

## Issues to fix (in priority order)

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

