-- Enrollment nonces get a bounded lifetime (ENROLL_NONCE_TTL_SECS in src/main.rs).
-- Nonces created before this migration have no known age and expire immediately.
ALTER TABLE enroll_nonces ADD COLUMN IF NOT EXISTS expires_at BIGINT NOT NULL DEFAULT 0;
