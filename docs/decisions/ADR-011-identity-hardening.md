# ADR-011: Database-backed identity hardening for the self-hosted BFF

- Status: Accepted
- Date: 2026-10-25
- Related: `docs/AUTH-MATRIX.md`, `migrations/0008_identity_hardening.sql`

## Context

The BFF already used opaque sessions, CSRF tokens, role checks, and a bootstrap
admin. It did not have a second factor, a password-reset path, session
inventory, OIDC, database-backed lockout, or a production startup check for
unsafe defaults. The local demo also used SQLite while production uses
PostgreSQL.

## Decision

1. Keep the existing opaque-cookie session model and add `auth_method`,
   `mfa_verified`, `ip_address`, and `user_agent` metadata.
2. Add TOTP MFA (RFC 6238). Encrypt TOTP secrets at rest with Fernet. The
   production configuration requires an explicit `ZEROTRACE_MFA_ENCRYPTION_KEY`;
   the local demo may derive a key from `SECRET_KEY`.
3. A password-only login for an MFA-enabled account creates a restricted
   session. It can only read its own session, verify MFA, or log out.
4. Add one-time, hashed, short-lived password-reset tokens. Reset revokes all
   sessions. Admin-issued tokens are returned once and must be delivered out of
   band; email delivery is a deployment integration, not a v1 requirement.
5. Add OIDC as an optional identity provider using Authlib. Link identities by
   `(issuer, subject)`. Auto-provisioning is disabled by default. SAML is not
   implemented in v1; operators that require SAML should front the app with an
   IdP/proxy that provides OIDC.
6. Add a database-backed failed-login counter and lockout window. The in-process
   rate limiter remains as a cheap first line of defense.
7. Add `auth_audit_events` for login, MFA, password, session, and OIDC events.
8. Production startup fails closed when the secret key, PostgreSQL URL, secure
   cookies, schema auto-creation, demo mode, MFA key, or OIDC credentials are
   unsafe.
9. SQLite compatibility migrations add the new columns in place for existing
   local databases. PostgreSQL deployments use the versioned migration.

## Consequences

- The local demo keeps working without external services.
- Production must set `ZEROTRACE_ENV=production`, a strong `FLASK_SECRET_KEY`,
  `ZEROTRACE_COOKIE_SECURE=true`, `AUTO_CREATE_SCHEMA=false`, `DEMO_MODE=false`,
  and a valid MFA key.
- Operators must decide whether to require MFA per account; v1 supports
  per-account enrollment but does not enforce a tenant-wide policy.
- SAML users need an OIDC bridge or a future ADR.

## Rejected alternatives

- **Store TOTP secrets in plaintext:** rejected; database read would expose a
  second factor.
- **Use an in-memory-only lockout:** rejected for multi-worker production
  deployments.
- **Send reset links from the app in v1:** rejected because email deliverability
  and provider credentials are deployment-specific; the token path is usable
  now and can be wired to email later.
- **Implement SAML from scratch:** rejected for v1; OIDC covers the common
  self-hosted IdP path with less protocol risk.
