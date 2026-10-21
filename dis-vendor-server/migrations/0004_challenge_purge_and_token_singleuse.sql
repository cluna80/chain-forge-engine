-- DIS-GAP-001: Registration token single-use enforcement.
-- Stores the hash of each used registration token so a second registration
-- attempt with the same token is rejected by the DB (not just the "already
-- registered" conflict on the vendors table).
CREATE TABLE IF NOT EXISTS used_registration_tokens (
    token_hash TEXT PRIMARY KEY,
    vendor_id  TEXT NOT NULL,
    used_at    BIGINT NOT NULL
);

-- DIS-GAP-002: Index to accelerate the background challenge-purge sweep.
-- Challenges are purged once both conditions hold:
--   (a) expires_at < now (expired), AND
--   (b) consumed_at IS NOT NULL OR expires_at < now - purge_grace_secs
-- The existing challenges_expires_at_idx already covers (a); this index
-- covers (b) so the purge query stays fast even on large tables.
CREATE INDEX IF NOT EXISTS challenges_consumed_at_idx ON challenges (consumed_at)
    WHERE consumed_at IS NOT NULL;
