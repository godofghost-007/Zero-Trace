# ADR-007: ZeroTrace Dashboard UI/UX (Phase 13)

## Status
Superseded by [ADR-008](ADR-008-dashboard-delivery-correction.md). The
standalone `app/dashboard/` HTTP server described below was never committed and
is not part of the current repository.

## Date
2026-10-18

## Context

ZeroTrace Phases 0-12 established the three-module cyber-defense platform:
Recon (attack surface discovery), Intel (vulnerability intelligence), and
Guard (LLM security middleware), with a unified Operational Readiness Score.
There was no web UI for operators to view Recon assets, Intel findings, Guard
events, or readiness scores in a single pane of glass.

Phase 13 requires a complete dashboard UI/UX built on Open Design principles,
connecting to the existing backend APIs (Recon, Intel, Guard) via a dedicated
HTTP dashboard server.

## Decision

Build a standalone dashboard HTTP server (`app/dashboard/server.py`) using
Python's `http.server` module, serving a single-page web UI
(`app/dashboard/static/`) with Open Design CSS custom properties and vanilla
JavaScript. The dashboard aggregates data from the backend API endpoints and
exposes its own API routes under `/api/v1/dashboard/`.

### Dashboard API Routes

| Route | Method | Backend Source | Fallback on Error |
|-------|--------|----------------|-------------------|
| `/api/v1/dashboard/health` | GET | N/A | `{"status": "healthy"}` |
| `/health` | GET | N/A | `{"status": "healthy"}` |
| `/api/v1/dashboard/ready` | GET | N/A | `{"status": "ready"}` |
| `/api/v1/dashboard/assets` | GET | `/api/v1/assets` | `{"items": [], "total": 0}` |
| `/api/v1/dashboard/findings` | GET | `/api/v1/findings` | `{"items": [], "total": 0}` |
| `/api/v1/dashboard/readiness` | GET | `/api/v1/intel/readiness` | `{"score": null, ...}` |
| `/api/v1/dashboard/guard-events` | GET | `/api/v1/uncertain-matches` | `{"items": [], "total": 0}` |

### Authentication

API key authentication via HMAC-SHA256 digest comparison, matching the
backend's `AuthorizationError` / `require_role` pattern from `app/security.py`.
Requests without a valid `X-API-Key` header receive `401 Unauthorized`.

### Security Headers

All responses include:
- `Content-Security-Policy: default-src 'self'; img-src 'self' data:;`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: no-referrer`
- `Cache-Control: no-store`

### Fail-Closed Behavior

When the backend API is unreachable, each dashboard endpoint returns an
empty/default response rather than propagating the error. The frontend
gracefully displays empty states. Authentication failures always return 401.

### Frontend

Single-page application (`index.html` + `app.js` + `design-tokens.css` +
`components.css`) using vanilla JavaScript with `fetch()` and the
`X-API-Key` authentication header. Auto-refreshes every 30 seconds.

## Alternatives Considered

### Embed dashboard in the main FastAPI backend
Rejected — would require modifying the FastAPI composition and coupling the
dashboard lifecycle with the main API server. A standalone `http.server`
instance on port 8766 keeps concerns separate.

### Use a frontend framework (React/Vue)
Rejected — adds build tooling and dependency overhead. Vanilla JavaScript
with Open Design CSS meets the requirements without a build step.

### Serve dashboard from the same port as the backend (8765)
Rejected — port 8765 is used by the main API server. The dashboard runs on
port 8766 to avoid conflicts.

## Consequences

- Dashboard server runs independently on port 8766
- Dashboard communicates only with local API routes (no external targets)
- All dashboard endpoints are authenticated via HMAC-SHA256 API key
- Backend unavailability degrades gracefully to empty/default responses
- Security headers applied on all dashboard responses
- No new Python dependencies beyond the standard library

## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Dashboard server port conflicts with other services | Medium | Configurable port via `run_dashboard_server()` |
| Backend API changes break dashboard data format | Low | Fallback to empty data; normalize backend response keys |
| API key digest mismatch between dashboard and backend | Medium | Same HMAC-SHA256 secret and algorithm as backend |

## Open Questions

None.
