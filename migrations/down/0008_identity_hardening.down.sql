DROP TABLE IF EXISTS auth_audit_events;
DROP TABLE IF EXISTS oidc_identities;
DROP TABLE IF EXISTS password_reset_tokens;

DO $$
BEGIN
    IF to_regclass('public.auth_sessions') IS NOT NULL THEN
        ALTER TABLE auth_sessions DROP COLUMN IF EXISTS user_agent;
        ALTER TABLE auth_sessions DROP COLUMN IF EXISTS ip_address;
        ALTER TABLE auth_sessions DROP COLUMN IF EXISTS mfa_verified;
        ALTER TABLE auth_sessions DROP COLUMN IF EXISTS auth_method;
    END IF;
    IF to_regclass('public.user_accounts') IS NOT NULL THEN
        ALTER TABLE user_accounts DROP COLUMN IF EXISTS mfa_pending_secret;
        ALTER TABLE user_accounts DROP COLUMN IF EXISTS mfa_secret;
        ALTER TABLE user_accounts DROP COLUMN IF EXISTS mfa_enabled;
        ALTER TABLE user_accounts DROP COLUMN IF EXISTS locked_until;
        ALTER TABLE user_accounts DROP COLUMN IF EXISTS failed_login_count;
        ALTER TABLE user_accounts DROP COLUMN IF EXISTS password_changed_at;
    END IF;
END $$;
