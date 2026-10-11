-- Migration 009: Research intelligence reports
--
-- Persists the output of AnalysisEngine::generate_report() so callers can
-- retrieve the last-computed report without re-running analysis on every
-- request.  One row per objective; a re-analysis upserts in place.

CREATE TABLE IF NOT EXISTS research_intelligence_reports (
    report_id       UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    objective_id    TEXT        NOT NULL UNIQUE
                                REFERENCES research_objectives(objective_id)
                                ON DELETE CASCADE,
    report_body     JSONB       NOT NULL,
    generated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    schema_version  INTEGER     NOT NULL DEFAULT 1
);

-- Fast lookup by objective (report_id PK + unique constraint already covers
-- point lookups; this index supports range scans ordered by recency).
CREATE INDEX IF NOT EXISTS idx_intelligence_reports_generated
    ON research_intelligence_reports (objective_id, generated_at DESC);
