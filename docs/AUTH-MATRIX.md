# ZeroTrace Authorization Matrix

This matrix is the contract enforced by `frontend/backend/auth.py` and
`_required_role_for`. It applies to the self-hosted v1 deployment.

## Roles

| Role | Purpose |
|---|---|
| `viewer` | Read dashboards, inventory, Intel, Guard status, and readiness. |
| `operator` | Run authorized scans, ingest feeds, inspect Guard traffic, and create remediation proposals. |
| `admin` | Manage users, identity settings, engine configuration, and destructive account actions. |

Roles are ordered `viewer < operator < admin`. A higher role includes the
lower-role permissions.

## Actions

| Action | Viewer | Operator | Admin | Notes |
|---|---:|---:|---:|---|
| Read health/readiness | yes | yes | yes | Public liveness/readiness only. |
| Read dashboard and inventory | yes | yes | yes | Authenticated and MFA-complete. |
| Create a scan scope | no | yes | yes | Explicit `authorized: true` acknowledgement is still required. |
| Submit a scan | no | yes | yes | High/Deep also require DNS TXT authorization. |
| Cancel a scan | no | yes | yes | Only scans in the caller's tenant/scope. |
| Ingest Intel feeds | no | yes | yes | Allowlisted endpoints only. |
| Inspect Guard events | yes | yes | yes | Read-only status and counters. |
| Submit Guard inspection | no | yes | yes | Bounded inspection only; no automatic remediation. |
| Send chat through Guard | no | yes | yes | BFF adds the Guard credential; no client-supplied upstream or streaming. |
| Read or mutate another user's scopes/scans | no | no | no | The BFF forwards the authenticated subject and role to the loopback engine, so owner checks are per user, not a shared service identity. |
| Create remediation proposal | no | yes | yes | Proposal remains review-required and non-executing. |
| Manage users/roles | no | no | yes | Tenant-scoped; last active admin is protected. |
| Issue password reset token | no | no | yes | Token is returned once; deliver out of band. |
| Reset another user's MFA | no | no | yes | Revokes that user's sessions. |
| Change own password | yes | yes | yes | Revokes the user's other sessions. |
| Enroll/verify own MFA | yes | yes | yes | Enrollment requires an authenticated, MFA-complete session. |
| List/revoke own sessions | yes | yes | yes | A user cannot revoke another user's session here. |
| Configure engine URL/key | no | no | yes | Engine URL remains loopback-only. |
| Change tenant identity provider | no | no | yes | OIDC configuration is environment-managed. |

## Authentication requirements

1. Passwords are at least 12 characters and hashed with Werkzeug's current
   password hash.
2. Login failures are rate-limited in-process and locked in the database after
   the configured threshold.
3. A session is an opaque cookie; only its SHA-256 digest is stored.
4. State-changing requests require a per-session CSRF token and an allowed
   `Origin`.
5. MFA uses TOTP (RFC 6238) with a ±1 step window. Secrets are encrypted at
   rest with Fernet.
6. A password-only session for an MFA-enabled account is marked
   `mfa_verified=false` and can only read `/auth/session`, verify MFA, or log
   out.
7. OIDC identities are linked by `(issuer, subject)`; email matching is only a
   first-link convenience. Auto-provisioning is off by default.
8. Password reset tokens are one-time, hashed at rest, short-lived, and revoke
   all existing sessions when used.
9. The last active admin in a tenant cannot be disabled or demoted.
10. Production startup fails if the secret key, PostgreSQL URL, secure cookies,
    MFA encryption key, OIDC credentials, an enabled Guard proxy
    credential/loopback URL, or a metrics token for enabled metrics are
    unsafe/missing.
