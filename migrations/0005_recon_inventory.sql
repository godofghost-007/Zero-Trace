CREATE TABLE IF NOT EXISTS recon_inventory_deltas (
    delta_id UUID PRIMARY KEY,
    run_id UUID NOT NULL REFERENCES recon_runs(run_id),
    scope_id UUID NOT NULL REFERENCES recon_scopes(scope_id),
    added_assets JSONB NOT NULL DEFAULT '[]'::jsonb,
    removed_assets JSONB NOT NULL DEFAULT '[]'::jsonb,
    added_services JSONB NOT NULL DEFAULT '[]'::jsonb,
    removed_services JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (run_id)
);
