# Browser E2E and accessibility tests

These tests exercise the built React UI through the Flask BFF and a live local
engine. They are deterministic and do not scan public targets.

## Scope

- Password login, invalid credentials, and TOTP enrollment/challenge.
- Deterministic Recon -> Intel -> Guard demo flow.
- Scope creation and a synthetic inventory scan against `lab.example.test`.
- Engine-outage handling and disabled scope creation.
- axe WCAG 2.0 A/AA checks for the login screen and operator console.
- Chromium, Firefox, and WebKit through `ZEROTRACE_E2E_BROWSERS`.

The scan coverage uses the synthetic adapter only. A multi-profile Nmap/Subfinder
scan is intentionally not part of this suite because it depends on host binaries
and live network behavior; that path remains covered by the engine integration
tests and the deployment acceptance steps.

## Run locally

```powershell
cd frontend
pnpm exec playwright install chromium firefox webkit
pnpm build
pnpm test:e2e
```

Set `ZEROTRACE_E2E_BROWSERS=chromium,firefox,webkit` to exercise every project.
The runner creates a temporary SQLite data directory and starts both the engine
and BFF on loopback ports. It never reuses an existing server.

## CI

The `Browser E2E and accessibility` job installs Python and frontend
dependencies, builds the UI, installs all three browsers, runs the suite, and
uploads Playwright evidence from `frontend/.e2e-results` when present.

## Credentials

The suite creates its own E2E-only bootstrap account and MFA user inside a
disposable database. Do not reuse these credentials outside the test harness.
