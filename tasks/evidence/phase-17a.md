# Phase 17A evidence — durable live state and identity hardening

Date: 2026-10-25
Branch: `feature/phase-17-production-hardening`

## Implemented

- PostgreSQL live-engine store (`app/live_store_pg.py`) with pooled `psycopg`
  connections and JSONB-backed scopes, scans, Intel facts/findings/uncertain
  matches, Guard counters, readiness snapshots, and scheduler state.
- Migration `0007_live_runtime.sql` plus reversible down migration.
- Live engine selects PostgreSQL when `DATABASE_URL` is set and keeps SQLite as
  the zero-dependency demo fallback.
- Identity hardening:
  - TOTP MFA (RFC 6238) with Fernet-encrypted secrets.
  - Restricted `mfa_verified=false` sessions for MFA-enabled accounts.
  - One-time hashed password-reset tokens; reset revokes sessions.
  - Session inventory and per-session revocation.
  - Database-backed failed-login counter and lockout.
  - Optional OIDC via Authlib, linked by `(issuer, subject)`; auto-provisioning
    is off by default.
  - Auth audit events.
  - Production startup validation for unsafe secrets, SQLite, schema
    auto-creation, demo mode, insecure cookies, missing MFA key, and incomplete
    OIDC configuration.
- Migration `0008_identity_hardening.sql` plus reversible down migration.
- `docs/AUTH-MATRIX.md`, `docs/decisions/ADR-010-open-source-self-hosted-ai-slots.md`,
  and `docs/decisions/ADR-011-identity-hardening.md`.

## Verification

```text
py -3.13 -m pytest -q
225 passed, 1 warning

frontend\.venv\Scripts\python.exe -m pytest backend\tests -q
32 passed

ZEROTRACE_TEST_DATABASE_URL=postgresql://... py -3.13 -m pytest -q
225 passed, 1 warning
```

PostgreSQL tests create disposable databases, apply migrations `0001`–`0008`,
exercise the live store, exercise the live engine with PostgreSQL storage, and
roll back `0008` and `0007` before reapplying.

## Known gaps

- SAML is not implemented. OIDC is implemented but was not exercised against a
  live identity provider in this phase.
- Email delivery for password-reset tokens is deployment-specific; the token is
  returned once to the admin for out-of-band delivery.
- Tenant-wide MFA enforcement is not implemented; enrollment is per account.
- OIDC auto-provisioning must remain disabled unless the operator explicitly
  wants it.
- The production BFF schema is bootstrapped with `flask init-schema` before
  `AUTO_CREATE_SCHEMA=false`; this is documented in `deploy/README.md`.
