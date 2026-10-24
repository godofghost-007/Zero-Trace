-- Identity hardening for the Flask BFF.
--
-- The BFF can create its tables through SQLAlchemy for a fresh local demo, but
-- an existing PostgreSQL deployment needs an explicit, reversible migration.
-- The ALTER statements are guarded so this migration can run before the BFF has
-- created its tables (for example in an engine-only database).

DO $$
BEGIN
    IF to_regclass('public.user_accounts') IS NOT NULL THEN
        ALTER TABLE user_accounts
            ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMPTZ;
        ALTER TABLE user_accounts
            ADD COLUMN IF NOT EXISTS failed_login_count INTEGER NOT NULL DEFAULT 0;
        ALTER TABLE user_accounts
            ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ;
        ALTER TABLE user_accounts
            ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE;
        ALTER TABLE user_accounts
            ADD COLUMN IF NOT EXISTS mfa_secret VARCHAR(512);
        ALTER TABLE user_accounts
            ADD COLUMN IF NOT EXISTS mfa_pending_secret VARCHAR(512);
    END IF;

    IF to_regclass('public.auth_sessions') IS NOT NULL THEN
        ALTER TABLE auth_sessions
            ADD COLUMN IF NOT EXISTS auth_method VARCHAR(32) NOT NULL DEFAULT 'password';
        ALTER TABLE auth_sessions
            ADD COLUMN IF NOT EXISTS mfa_verified BOOLEAN NOT NULL DEFAULT TRUE;
        ALTER TABLE auth_sessions
            ADD COLUMN IF NOT EXISTS ip_address VARCHAR(64);
        ALTER TABLE auth_sessions
            ADD COLUMN IF NOT EXISTS user_agent VARCHAR(512);
    END IF;
END $$;

DO $$
BEGIN
    IF to_regclass('public.user_accounts') IS NOT NULL THEN
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id VARCHAR(96) PRIMARY KEY,
            token_hash VARCHAR(64) NOT NULL UNIQUE,
            user_id VARCHAR(96) NOT NULL REFERENCES user_accounts(id),
            tenant_id VARCHAR(64) NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMPTZ NOT NULL,
            used_at TIMESTAMPTZ
        );

        CREATE INDEX IF NOT EXISTS password_reset_tokens_user_idx
            ON password_reset_tokens (user_id, created_at);

        CREATE TABLE IF NOT EXISTS oidc_identities (
            id VARCHAR(96) PRIMARY KEY,
            issuer VARCHAR(512) NOT NULL,
            subject VARCHAR(255) NOT NULL,
            user_id VARCHAR(96) NOT NULL REFERENCES user_accounts(id),
            tenant_id VARCHAR(64) NOT NULL,
            email VARCHAR(254),
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            CONSTRAINT oidc_identity_issuer_subject UNIQUE (issuer, subject)
        );

        CREATE INDEX IF NOT EXISTS oidc_identities_user_idx
            ON oidc_identities (user_id);

        CREATE TABLE IF NOT EXISTS auth_audit_events (
            id VARCHAR(96) PRIMARY KEY,
            event_type VARCHAR(64) NOT NULL,
            outcome VARCHAR(32) NOT NULL,
            user_id VARCHAR(96),
            tenant_id VARCHAR(64),
            ip_address VARCHAR(64),
            user_agent VARCHAR(512),
            detail VARCHAR(512),
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS auth_audit_events_created_idx
            ON auth_audit_events (created_at);
        CREATE INDEX IF NOT EXISTS auth_audit_events_user_idx
            ON auth_audit_events (user_id, created_at);
    END IF;
END $$;
