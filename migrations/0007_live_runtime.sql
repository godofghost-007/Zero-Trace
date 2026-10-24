-- Durable live-engine state.
--
-- The live engine keeps a narrow projection of Recon, Intel, Guard, readiness,
-- and scheduler state. These tables are intentionally separate from the
-- canonical production repositories so the SQLite demo path can remain a
-- zero-dependency fallback. The live engine uses the same PostgreSQL database
-- as the BFF when DATABASE_URL is configured.

CREATE TABLE IF NOT EXISTS live_scopes (
    scope_id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    targets JSONB NOT NULL,
    environment TEXT NOT NULL,
    approved BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at TIMESTAMPTZ NOT NULL,
    profiles JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT live_scopes_environment_check
        CHECK (environment IN ('synthetic', 'isolated_lab'))
);

CREATE TABLE IF NOT EXISTS live_scans (
    scan_id TEXT PRIMARY KEY,
    run_id TEXT,
    scope_id TEXT NOT NULL REFERENCES live_scopes(scope_id) ON DELETE CASCADE,
    target TEXT NOT NULL,
    profile_id TEXT NOT NULL,
    state TEXT NOT NULL,
    warnings JSONB NOT NULL DEFAULT '[]'::jsonb,
    assets JSONB NOT NULL DEFAULT '[]'::jsonb,
    services JSONB NOT NULL DEFAULT '[]'::jsonb,
    tls_findings JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT live_scans_state_check
        CHECK (state IN (
            'queued', 'running', 'completed', 'partial',
            'cancelled', 'timed_out', 'failed'
        ))
);

CREATE INDEX IF NOT EXISTS live_scans_scope_idx
    ON live_scans (scope_id, created_at);

CREATE TABLE IF NOT EXISTS live_intel_facts (
    cve_id TEXT PRIMARY KEY,
    payload JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS live_intel_meta (
    key TEXT PRIMARY KEY,
    payload JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS live_findings (
    finding_id TEXT PRIMARY KEY,
    payload JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS live_uncertain_matches (
    match_id TEXT PRIMARY KEY,
    payload JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS live_guard_events (
    event_id BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    blocked BOOLEAN NOT NULL,
    reason TEXT,
    pii_blocked BOOLEAN NOT NULL
);

CREATE INDEX IF NOT EXISTS live_guard_events_created_idx
    ON live_guard_events (created_at);

CREATE TABLE IF NOT EXISTS live_readiness_snapshots (
    snapshot_id BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    payload JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS live_intel_schedule (
    source TEXT PRIMARY KEY,
    last_started TIMESTAMPTZ,
    last_completed TIMESTAMPTZ,
    last_state TEXT NOT NULL DEFAULT 'never',
    last_error TEXT,
    last_fact_count INTEGER NOT NULL DEFAULT 0,
    runs INTEGER NOT NULL DEFAULT 0,
    CONSTRAINT live_intel_schedule_source_check
        CHECK (source IN ('nvd', 'epss', 'kev'))
);
