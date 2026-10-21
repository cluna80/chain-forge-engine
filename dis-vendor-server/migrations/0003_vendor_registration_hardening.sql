-- DIS-SEC-004: authenticated vendor registration.
--
-- registration_token_hash  SHA-256 of the one-time token the operator issued
--                          for this registration. Stored only for audit; the
--                          token itself is never stored.
-- origin_verified_at       Unix timestamp set when the server confirmed the
--                          vendor controls its rp_origin via the well-known
--                          endpoint. NULL means unverified (cannot be used).
ALTER TABLE vendors
    ADD COLUMN IF NOT EXISTS registration_token_hash TEXT,
    ADD COLUMN IF NOT EXISTS origin_verified_at       BIGINT;
