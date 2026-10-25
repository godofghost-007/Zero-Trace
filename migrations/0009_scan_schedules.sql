-- Pre-approved, bounded scan schedules.
--
-- A schedule only references an existing live_scope. The engine revalidates
-- the scope, target policy, profile level, and DNS authorization on every run.
-- These rows do not grant new authorization.

CREATE TABLE IF NOT EXISTS live_scan_schedules (
    schedule_id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    scope_id TEXT NOT NULL REFERENCES live_scopes(scope_id) ON DELETE CASCADE,
    target TEXT NOT NULL,
    profile_id TEXT NOT NULL,
    interval_seconds INTEGER NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    next_run_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    authorization_id TEXT,
    last_run_at TIMESTAMPTZ,
    last_scan_id TEXT,
    last_state TEXT,
    last_error TEXT,
    runs INTEGER NOT NULL DEFAULT 0,
    CONSTRAINT live_scan_schedules_interval_check
        CHECK (interval_seconds BETWEEN 300 AND 604800),
    CONSTRAINT live_scan_schedules_runs_check CHECK (runs >= 0)
);

CREATE INDEX IF NOT EXISTS live_scan_schedules_due_idx
    ON live_scan_schedules (enabled, next_run_at);
