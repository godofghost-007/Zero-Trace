-- BFF operational tables.
--
-- Local development may create these tables through SQLAlchemy, but a
-- production deployment runs with AUTO_CREATE_SCHEMA=false. This migration is
-- the authoritative PostgreSQL schema for the Flask BFF and is safe to apply
-- after an earlier local create_all() because every object is guarded.

CREATE TABLE IF NOT EXISTS user_accounts (
    id VARCHAR(96) NOT NULL,
    tenant_id VARCHAR(64) NOT NULL,
    email VARCHAR(254) NOT NULL,
    password_hash VARCHAR(512) NOT NULL,
    role VARCHAR(16) NOT NULL,
    active BOOLEAN NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_login_at TIMESTAMP WITH TIME ZONE,
    password_changed_at TIMESTAMP WITH TIME ZONE,
    failed_login_count INTEGER NOT NULL,
    locked_until TIMESTAMP WITH TIME ZONE,
    mfa_enabled BOOLEAN NOT NULL,
    mfa_secret VARCHAR(512),
    mfa_pending_secret VARCHAR(512),
    PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS auth_sessions (
    id VARCHAR(96) NOT NULL,
    token_hash VARCHAR(64) NOT NULL,
    user_id VARCHAR(96) NOT NULL,
    tenant_id VARCHAR(64) NOT NULL,
    csrf_token VARCHAR(128) NOT NULL,
    auth_method VARCHAR(32) NOT NULL,
    mfa_verified BOOLEAN NOT NULL,
    ip_address VARCHAR(64),
    user_agent VARCHAR(512),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_seen_at TIMESTAMP WITH TIME ZONE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked_at TIMESTAMP WITH TIME ZONE,
    PRIMARY KEY (id),
    FOREIGN KEY (user_id) REFERENCES user_accounts (id)
);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id VARCHAR(96) NOT NULL,
    token_hash VARCHAR(64) NOT NULL,
    user_id VARCHAR(96) NOT NULL,
    tenant_id VARCHAR(64) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used_at TIMESTAMP WITH TIME ZONE,
    PRIMARY KEY (id),
    FOREIGN KEY (user_id) REFERENCES user_accounts (id)
);

CREATE TABLE IF NOT EXISTS oidc_identities (
    id VARCHAR(96) NOT NULL,
    issuer VARCHAR(512) NOT NULL,
    subject VARCHAR(255) NOT NULL,
    user_id VARCHAR(96) NOT NULL,
    tenant_id VARCHAR(64) NOT NULL,
    email VARCHAR(254),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    PRIMARY KEY (id),
    CONSTRAINT oidc_identity_issuer_subject UNIQUE (issuer, subject),
    FOREIGN KEY (user_id) REFERENCES user_accounts (id)
);

CREATE TABLE IF NOT EXISTS auth_audit_events (
    id VARCHAR(96) NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    outcome VARCHAR(32) NOT NULL,
    user_id VARCHAR(96),
    tenant_id VARCHAR(64),
    ip_address VARCHAR(64),
    user_agent VARCHAR(512),
    detail VARCHAR(512),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS demo_scenario (
    id VARCHAR(32) NOT NULL,
    stage INTEGER NOT NULL,
    correlation_id VARCHAR(96) NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS assets (
    id VARCHAR(96) NOT NULL,
    hostname VARCHAR(253) NOT NULL,
    scope_id VARCHAR(96) NOT NULL,
    environment VARCHAR(64) NOT NULL,
    services JSON NOT NULL,
    provenance VARCHAR(128) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    PRIMARY KEY (id),
    UNIQUE (hostname)
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id VARCHAR(96) NOT NULL,
    identifier VARCHAR(64) NOT NULL,
    title VARCHAR(256) NOT NULL,
    cvss FLOAT NOT NULL,
    epss FLOAT NOT NULL,
    confidence VARCHAR(128) NOT NULL,
    cpe VARCHAR(256) NOT NULL,
    synthetic BOOLEAN NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    PRIMARY KEY (id),
    UNIQUE (identifier)
);

CREATE TABLE IF NOT EXISTS scan_runs (
    id VARCHAR(96) NOT NULL,
    scope_id VARCHAR(96) NOT NULL,
    status VARCHAR(32) NOT NULL,
    partial BOOLEAN NOT NULL,
    warnings JSON NOT NULL,
    started_at TIMESTAMP WITH TIME ZONE NOT NULL,
    completed_at TIMESTAMP WITH TIME ZONE NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS service_vulnerabilities (
    id VARCHAR(96) NOT NULL,
    asset_id VARCHAR(96) NOT NULL,
    finding_id VARCHAR(96) NOT NULL,
    match_method VARCHAR(64) NOT NULL,
    confidence VARCHAR(128) NOT NULL,
    evidence JSON NOT NULL,
    review_state VARCHAR(32) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    PRIMARY KEY (id),
    FOREIGN KEY (asset_id) REFERENCES assets (id),
    FOREIGN KEY (finding_id) REFERENCES vulnerabilities (id)
);

CREATE TABLE IF NOT EXISTS patch_proposals (
    id VARCHAR(96) NOT NULL,
    finding_id VARCHAR(96) NOT NULL,
    status VARCHAR(32) NOT NULL,
    review_required BOOLEAN NOT NULL,
    execution_allowed BOOLEAN NOT NULL,
    due_window_hours INTEGER NOT NULL,
    safe_next_action VARCHAR(512) NOT NULL,
    synthetic BOOLEAN NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    PRIMARY KEY (id),
    FOREIGN KEY (finding_id) REFERENCES vulnerabilities (id)
);

CREATE TABLE IF NOT EXISTS guard_events (
    id VARCHAR(96) NOT NULL,
    action VARCHAR(64) NOT NULL,
    outcome VARCHAR(32) NOT NULL,
    asset_id VARCHAR(96) NOT NULL,
    finding_id VARCHAR(96) NOT NULL,
    correlation_id VARCHAR(96) NOT NULL,
    audit_sequence INTEGER NOT NULL,
    audit_hash VARCHAR(64) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS score_snapshots (
    id VARCHAR(96) NOT NULL,
    stage INTEGER NOT NULL,
    score FLOAT,
    aei FLOAT,
    vui FLOAT,
    aiet FLOAT,
    components JSON NOT NULL,
    formula_version VARCHAR(32) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS demo_event_outbox (
    id VARCHAR(96) NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    entity_type VARCHAR(64) NOT NULL,
    entity_id VARCHAR(96) NOT NULL,
    source VARCHAR(64) NOT NULL,
    correlation_id VARCHAR(96) NOT NULL,
    schema_version INTEGER NOT NULL,
    payload JSON NOT NULL,
    occurred_at TIMESTAMP WITH TIME ZONE NOT NULL,
    status VARCHAR(16) NOT NULL,
    attempts INTEGER NOT NULL,
    redis_entry_id VARCHAR(96),
    last_error VARCHAR(512),
    published_at TIMESTAMP WITH TIME ZONE,
    PRIMARY KEY (id)
);

CREATE UNIQUE INDEX IF NOT EXISTS ix_user_accounts_email
    ON user_accounts (email);
CREATE INDEX IF NOT EXISTS ix_user_accounts_tenant_id
    ON user_accounts (tenant_id);
CREATE UNIQUE INDEX IF NOT EXISTS ix_auth_sessions_token_hash
    ON auth_sessions (token_hash);
CREATE INDEX IF NOT EXISTS ix_auth_sessions_tenant_id
    ON auth_sessions (tenant_id);
CREATE INDEX IF NOT EXISTS ix_auth_sessions_user_id
    ON auth_sessions (user_id);
CREATE INDEX IF NOT EXISTS ix_password_reset_tokens_user_id
    ON password_reset_tokens (user_id);
CREATE INDEX IF NOT EXISTS ix_password_reset_tokens_tenant_id
    ON password_reset_tokens (tenant_id);
CREATE UNIQUE INDEX IF NOT EXISTS ix_password_reset_tokens_token_hash
    ON password_reset_tokens (token_hash);
CREATE INDEX IF NOT EXISTS ix_oidc_identities_user_id
    ON oidc_identities (user_id);
CREATE INDEX IF NOT EXISTS ix_oidc_identities_tenant_id
    ON oidc_identities (tenant_id);
CREATE INDEX IF NOT EXISTS ix_auth_audit_events_event_type
    ON auth_audit_events (event_type);
CREATE INDEX IF NOT EXISTS ix_auth_audit_events_outcome
    ON auth_audit_events (outcome);
CREATE INDEX IF NOT EXISTS ix_auth_audit_events_user_id
    ON auth_audit_events (user_id);
CREATE INDEX IF NOT EXISTS ix_auth_audit_events_tenant_id
    ON auth_audit_events (tenant_id);
CREATE INDEX IF NOT EXISTS ix_demo_event_outbox_status
    ON demo_event_outbox (status);
CREATE INDEX IF NOT EXISTS ix_demo_event_outbox_correlation_id
    ON demo_event_outbox (correlation_id);
CREATE INDEX IF NOT EXISTS ix_demo_event_outbox_event_type
    ON demo_event_outbox (event_type);
