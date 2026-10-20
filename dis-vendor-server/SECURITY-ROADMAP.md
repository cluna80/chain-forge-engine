# DIS-SEC-002 — Vendor Server Security Hardening

## Issues to fix (in priority order)

1. **Authenticated enrollment** — wallet must prove key ownership with a signature at /enroll
2. **Protected /sessions endpoint** — require API key header
3. **Proper RP identity** — vendor registers with its own rp_id/rp_origin, not derived from wallet_id
4. **Tighter CORS** — replace * with explicit allowed origins
5. **Authorization isolation** — per-vendor grant tables, not shared resource list

## Status: Pending — next session
# DIS-SEC-002 — Vendor Server Security Hardening

## Issues to fix (in priority order)

1. **Authenticated enrollment** — wallet must prove key ownership with a signature at /enroll
2. **Protected /sessions endpoint** — require API key header
3. **Proper RP identity** — vendor registers with its own rp_id/rp_origin, not derived from wallet_id
4. **Tighter CORS** — replace * with explicit allowed origins
5. **Authorization isolation** — per-vendor grant tables, not shared resource list

## Status: Pending — next session
