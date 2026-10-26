-- Roll back the BFF operational schema.
--
-- Drop child tables before their parents so foreign keys do not block the
-- rollback. The engine's own tables are intentionally untouched.

DROP TABLE IF EXISTS service_vulnerabilities;
DROP TABLE IF EXISTS patch_proposals;
DROP TABLE IF EXISTS guard_events;
DROP TABLE IF EXISTS score_snapshots;
DROP TABLE IF EXISTS scan_runs;
DROP TABLE IF EXISTS assets;
DROP TABLE IF EXISTS vulnerabilities;
DROP TABLE IF EXISTS demo_event_outbox;
DROP TABLE IF EXISTS demo_scenario;
DROP TABLE IF EXISTS auth_audit_events;
DROP TABLE IF EXISTS oidc_identities;
DROP TABLE IF EXISTS password_reset_tokens;
DROP TABLE IF EXISTS auth_sessions;
DROP TABLE IF EXISTS user_accounts;
