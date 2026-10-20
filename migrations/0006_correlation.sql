CREATE TABLE IF NOT EXISTS intel_uncertain_matches (
    uncertain_id UUID PRIMARY KEY,
    scope_id UUID NOT NULL REFERENCES recon_scopes(scope_id),
    asset_id UUID NOT NULL,
    service_id UUID NOT NULL,
    cve_id VARCHAR(32) NOT NULL,
    reason VARCHAR(64) NOT NULL,
    evidence JSONB NOT NULL,
    freshness VARCHAR(16) NOT NULL,
    source_revision VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (scope_id, service_id, cve_id, reason, source_revision)
);

CREATE INDEX IF NOT EXISTS intel_uncertain_matches_scope_idx
    ON intel_uncertain_matches (scope_id, created_at, uncertain_id);
