CREATE TABLE IF NOT EXISTS intel_vulnerability_facts (
    fact_id UUID PRIMARY KEY,
    cve_id VARCHAR(32) NOT NULL,
    source VARCHAR(64) NOT NULL,
    source_record_id VARCHAR(255) NOT NULL,
    source_revision VARCHAR(255) NOT NULL,
    summary TEXT NOT NULL,
    cpe_names JSONB NOT NULL,
    cvss_score DOUBLE PRECISION,
    epss_score DOUBLE PRECISION,
    kev BOOLEAN,
    published_at TIMESTAMPTZ,
    modified_at TIMESTAMPTZ,
    retrieved_at TIMESTAMPTZ NOT NULL,
    schema_version INTEGER NOT NULL,
    payload_digest CHAR(64) NOT NULL,
    UNIQUE (source, source_record_id, source_revision)
);

CREATE TABLE IF NOT EXISTS intel_findings (
    finding_id UUID PRIMARY KEY,
    scope_id UUID NOT NULL,
    asset_id UUID NOT NULL,
    service_id UUID NOT NULL,
    cve_id VARCHAR(32) NOT NULL,
    match_method VARCHAR(64) NOT NULL,
    confidence DOUBLE PRECISION NOT NULL,
    evidence JSONB NOT NULL,
    freshness VARCHAR(16) NOT NULL,
    priority_score DOUBLE PRECISION NOT NULL,
    priority_inputs JSONB NOT NULL,
    formula_version VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'active',
    source_revision VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (scope_id, service_id, cve_id, source_revision)
);

ALTER TABLE intel_vulnerability_facts
    ADD COLUMN IF NOT EXISTS epss_score_date DATE,
    ADD COLUMN IF NOT EXISTS kev_due_date DATE;

CREATE TABLE IF NOT EXISTS intel_ingestions (
    ingestion_id UUID PRIMARY KEY,
    source VARCHAR(64) NOT NULL,
    state VARCHAR(32) NOT NULL,
    source_checkpoint VARCHAR(255),
    retrieved_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    error_code VARCHAR(64),
    quarantined_count INTEGER NOT NULL DEFAULT 0,
    last_known_good_at TIMESTAMPTZ,
    UNIQUE (source, source_checkpoint)
);

CREATE TABLE IF NOT EXISTS intel_feed_quarantine (
    quarantine_id UUID PRIMARY KEY,
    ingestion_id UUID NOT NULL REFERENCES intel_ingestions(ingestion_id),
    source VARCHAR(64) NOT NULL,
    source_record_id VARCHAR(255),
    reason VARCHAR(255) NOT NULL,
    payload_digest CHAR(64),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS intel_feed_checkpoints (
    source VARCHAR(64) PRIMARY KEY,
    next_start_index INTEGER NOT NULL DEFAULT 0,
    modified_since TIMESTAMPTZ,
    etag VARCHAR(512),
    last_modified VARCHAR(255),
    last_success_at TIMESTAMPTZ,
    last_good_digest CHAR(64)
);
