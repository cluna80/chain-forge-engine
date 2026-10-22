-- DIS-I11: Durable, atomic delegation usage counter.
--
-- delegation_id is the SHA-256 of canonical_delegation_body (see dis-core).
-- The row is created on first use; used_count is incremented atomically
-- inside a SELECT FOR UPDATE transaction so concurrent requests cannot
-- both increment past max_uses.
CREATE TABLE IF NOT EXISTS delegation_usage (
    delegation_id  BYTEA   PRIMARY KEY,
    max_uses       INTEGER NOT NULL CHECK (max_uses > 0),
    used_count     INTEGER NOT NULL DEFAULT 0 CHECK (used_count >= 0)
);
