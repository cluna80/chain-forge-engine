-- DIS-STATE-003: shared PostgreSQL security store.
-- Postgres is the single authoritative store for every piece of vendor-server
-- security state, so any number of server instances can share it safely.

CREATE TABLE IF NOT EXISTS vendors (
    vendor_id         TEXT PRIMARY KEY,
    rp_origin         TEXT NOT NULL,
    allowed_resources TEXT NOT NULL,   -- JSON array
    allowed_actions   TEXT NOT NULL,   -- JSON array
    api_key_hash      TEXT NOT NULL
);

-- key_id = hex(SHA-256(ML-DSA-65 public key)).
CREATE TABLE IF NOT EXISTS enrolled_keys (
    wallet_id      TEXT PRIMARY KEY,
    public_key_hex TEXT NOT NULL,
    key_id         TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS enroll_nonces (
    wallet_id TEXT PRIMARY KEY,
    nonce     TEXT NOT NULL
);

-- Issued challenges. The server-built canonical transcript is stored so any
-- instance can verify a proof for a challenge issued by any other instance.
-- Times are Unix seconds from the database clock (one clock for all instances).
CREATE TABLE IF NOT EXISTS challenges (
    challenge_key TEXT PRIMARY KEY,   -- dis:v1:challenge:{vendor_id}:{challenge_id}
    challenge_id  TEXT NOT NULL,      -- 32 lowercase hex chars (16 random bytes)
    vendor_id     TEXT NOT NULL REFERENCES vendors(vendor_id) ON DELETE CASCADE,
    wallet_id     TEXT NOT NULL,
    transcript    BYTEA NOT NULL,
    issued_at     BIGINT NOT NULL,
    expires_at    BIGINT NOT NULL,
    consumed_at   BIGINT,
    UNIQUE (vendor_id, challenge_id),
    CONSTRAINT challenge_key_namespace
        CHECK (challenge_key = 'dis:v1:challenge:' || vendor_id || ':' || challenge_id),
    CONSTRAINT challenge_id_format CHECK (challenge_id ~ '^[0-9a-f]{32}$'),
    -- Must equal CHALLENGE_TTL_SECS in src/main.rs (server-enforced window).
    CONSTRAINT challenge_ttl CHECK (expires_at - issued_at = 299)
);

CREATE INDEX IF NOT EXISTS challenges_expires_at_idx ON challenges (expires_at);

CREATE TABLE IF NOT EXISTS revocations (
    key_id     TEXT PRIMARY KEY,
    wallet_id  TEXT NOT NULL,
    revoked_at BIGINT NOT NULL,
    reason     TEXT
);

CREATE TABLE IF NOT EXISTS verified_sessions (
    id            BIGSERIAL PRIMARY KEY,
    wallet_id     TEXT NOT NULL,
    vendor_id     TEXT NOT NULL,
    resource_id   TEXT NOT NULL,
    action        TEXT NOT NULL,
    challenge_key TEXT NOT NULL UNIQUE,  -- second replay barrier: one grant per challenge
    verified_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
