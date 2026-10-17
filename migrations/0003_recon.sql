CREATE TABLE IF NOT EXISTS recon_scopes (
    scope_id UUID PRIMARY KEY,
    owner_id VARCHAR(255) NOT NULL,
    environment VARCHAR(32) NOT NULL,
    approved BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at TIMESTAMPTZ NOT NULL,
    targets JSONB NOT NULL,
    profiles JSONB NOT NULL,
    CONSTRAINT recon_scopes_environment_check
        CHECK (environment IN ('synthetic', 'isolated_lab'))
);

CREATE TABLE IF NOT EXISTS recon_runs (
    run_id UUID PRIMARY KEY,
    scope_id UUID NOT NULL REFERENCES recon_scopes(scope_id),
    target VARCHAR(255) NOT NULL,
    profile_id VARCHAR(128) NOT NULL,
    state VARCHAR(32) NOT NULL,
    warnings JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    CONSTRAINT recon_runs_state_check
        CHECK (state IN (
            'queued', 'running', 'completed', 'partial',
            'cancelled', 'timed_out', 'failed'
        ))
);

CREATE UNIQUE INDEX IF NOT EXISTS recon_runs_scope_target_profile
    ON recon_runs (scope_id, target, profile_id, created_at);

CREATE TABLE IF NOT EXISTS recon_assets (
    asset_id UUID PRIMARY KEY,
    scope_id UUID NOT NULL REFERENCES recon_scopes(scope_id),
    canonical_identifier VARCHAR(255) NOT NULL,
    asset_kind VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'active',
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (scope_id, canonical_identifier)
);

CREATE TABLE IF NOT EXISTS recon_services (
    service_id UUID PRIMARY KEY,
    asset_id UUID NOT NULL REFERENCES recon_assets(asset_id),
    protocol VARCHAR(16) NOT NULL,
    port INTEGER NOT NULL,
    product VARCHAR(255),
    version VARCHAR(255),
    tls_status VARCHAR(32),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT recon_services_port_check CHECK (port BETWEEN 1 AND 65535),
    UNIQUE (asset_id, protocol, port)
);

CREATE TABLE IF NOT EXISTS recon_observations (
    observation_id UUID PRIMARY KEY,
    run_id UUID NOT NULL REFERENCES recon_runs(run_id),
    asset_id UUID REFERENCES recon_assets(asset_id),
    service_id UUID REFERENCES recon_services(service_id),
    source VARCHAR(128) NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    evidence JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS recon_idempotency (
    idempotency_key VARCHAR(255) PRIMARY KEY,
    request_hash CHAR(64) NOT NULL,
    run_id UUID NOT NULL REFERENCES recon_runs(run_id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS recon_idempotency_key_unique
    ON recon_idempotency (idempotency_key);
