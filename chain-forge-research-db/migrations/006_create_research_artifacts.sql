-- Migration 006: research_artifacts
--
-- Stores supporting artifacts attached to experiment results or findings.
-- Examples: output hash arrays, timing histograms, partial collision data,
-- serialised proof trees, or any binary blob the research protocol generates.
--
-- Artifact content is stored by reference (content_hash + storage_uri).
-- Actual blob storage may be local filesystem, IPFS, or S3 depending on
-- deployment.  The URI is resolved by the QDE artifact layer (Change Set G).
--
-- This table is append-only: artifacts are never deleted, only superseded
-- by new versions (new rows with a supersedes_artifact_id reference).

CREATE TABLE IF NOT EXISTS research_artifacts (
    -- UUID primary key
    artifact_id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Parent result (NULL for objective-level artifacts)
    result_id           UUID
        REFERENCES experiment_results (result_id) ON DELETE SET NULL,

    -- Parent finding (NULL for result-level artifacts)
    finding_id          UUID
        REFERENCES research_findings (finding_id) ON DELETE SET NULL,

    -- MIME-like type descriptor
    -- Examples: 'application/octet-stream', 'application/json',
    --           'application/x-hash-collision', 'text/plain'
    artifact_type       TEXT        NOT NULL,

    -- Human-readable label
    label               TEXT        NOT NULL,

    -- Content hash (hex of SHA-256 over the artifact bytes) — integrity check
    content_hash        TEXT        NOT NULL,

    -- Size in bytes
    size_bytes          BIGINT      NOT NULL CHECK (size_bytes >= 0),

    -- Where the artifact can be retrieved (local path, IPFS CID, S3 URI, etc.)
    storage_uri         TEXT        NOT NULL,

    -- Optional back-reference if this artifact supersedes an earlier version
    supersedes_artifact_id  UUID
        REFERENCES research_artifacts (artifact_id) ON DELETE SET NULL,

    -- Timestamps
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_research_artifacts_result
    ON research_artifacts (result_id)
    WHERE result_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_research_artifacts_finding
    ON research_artifacts (finding_id)
    WHERE finding_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_research_artifacts_content_hash
    ON research_artifacts (content_hash);
