# Phase 4 Evidence — Auth and Platform Security

- **Decision:** PASS
- **Commit / diff:** Working tree diff; no commit was requested
- **Environment:** Windows 11, Python 3.13.5, Docker Engine 29.4.3,
  Compose v5.1.3, Python 3.13.5
- **Reviewer:** User approval in this session
- **Date:** 2026-10-17

## Scope

Phase 4 adds dependency-free security primitives and response-boundary
controls while preserving the Phase 0–3 application behavior. No real
credentials, customer data, production data, external targets, or database
migrations were used.

## Required criteria and evidence

| Criterion | Status | Evidence | Notes |
|---|---|---|---|
| Unauthenticated and role-negative behavior | PASS | `test_missing_principal_is_unauthenticated`, `test_viewer_cannot_perform_operator_action`, and `test_admin_can_perform_operator_action` passed | Missing identity returns 401; insufficient role returns 403 |
| Password handling | PASS | `test_password_hash_is_salted_and_verifiable` passed | Uses scrypt with per-password random salt; plaintext is not returned |
| API-key handling | PASS | `test_api_key_verification_uses_secret_digest` passed | Uses HMAC-SHA256 digest with environment-loaded secret; plaintext key is not stored in digest |
| Secret loading | PASS | `test_weak_auth_secret_is_rejected` passed | Auth and session secrets require at least 32 bytes |
| CSRF protection | PASS | `test_csrf_token_is_bound_to_session_and_secret` passed | HMAC token is bound to both session ID and secret |
| Secure session cookie contract | PASS | `test_session_cookie_is_secure_and_bounded` passed | HttpOnly, Secure, SameSite=Lax, 8-hour default |
| Security headers | PASS | Unit test passed; live `/health` returned CSP `default-src 'self'`, `nosniff`, and `DENY` framing headers | Headers are applied by the existing HTTP server boundary |
| Request-size limit | PASS | `test_request_size_is_rejected_before_body_is_read` passed | Oversized Content-Length is rejected before stream consumption |
| Audit-file handling | PASS with platform note | `test_audit_file_is_owner_only` passed | Symlinks/non-regular paths are rejected; POSIX mode is 0600. Windows does not expose POSIX mode bits, so deployment ACL verification remains required |
| Private service networking | PASS | Compose config validation returned `core=0 full=0 dev=0`; PostgreSQL remains bound to `127.0.0.1` | No network exposure change was introduced |
| Secret hygiene | PASS | `git diff --check` passed; focused scan found no non-empty auth/session secret assignments outside `.env.example` | `.env.example` contains blank placeholders only |
| Full repository tests | PASS | `py -m unittest discover -s tests -v` passed all 27 tests | Includes Phase 0–3 regression coverage |
| Python sources compile | PASS | `py -m compileall -q app scripts` completed successfully |  |

## Implementation notes

- [app/security.py](../../app/security.py) is intentionally isolated from
  persistence and route wiring; Phase 5 or a later identity integration must
  provide canonical user/session/API-key state.
- [app/__main__.py](../../app/__main__.py) now adds security headers to all
  responses while retaining the existing `/health`, `/ready`, and query-string
  behavior.
- No migration file was modified.
- No new dependency was added; password hashing uses Python's standard
  library `hashlib.scrypt`.

## Exceptions and unresolved risks

- Persistent user accounts, session storage, API-key rotation/revocation, and
  bearer-token issuance are not implemented in this phase.
- On Windows, POSIX file-mode bits do not represent the effective ACL. A
  deployment-specific ACL check is required before using audit files in a
  Windows production deployment.
- The current foundation HTTP server does not yet expose protected API routes;
  the authorization primitives are tested independently and must be wired into
  every protected route when those routes are implemented.

## Decision

- [x] Phase 4 implementation criteria have reproducible evidence.
- [x] Human has reviewed and signed the Phase 4 gate.
- [x] Phase 5 is authorized.

**Human signoff:** User approved Phase 4 signoff and Phase 5 transition in this
session on 2026-10-17. The Windows ACL verification limitation is accepted as
an explicit deployment follow-up.
