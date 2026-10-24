# Phase 17F evidence — CI and release metadata (partial)

Date: 2026-10-25

## Implemented

- `.github/workflows/ci.yml`:
  - engine tests with a disposable PostgreSQL service;
  - BFF identity tests;
  - frontend typecheck, tests, and production build;
  - BFF and engine container builds.
- `.github/workflows/codeql.yml` for Python and JavaScript/TypeScript.
- Apache-2.0 `LICENSE`, `NOTICE`, package metadata, and frontend package license.
- Critical-error lint gate (`E9,F63,F7,F82`) because the repository has a large
  pre-existing style backlog.
- Production configuration validation fails closed before the app starts.

## Verification

```text
py -3.13 -m pytest -q
225 passed, 1 warning

frontend\.venv\Scripts\python.exe -m pytest backend\tests -q
32 passed

pnpm check
pnpm test
6 frontend tests passed

docker build -f Dockerfile.engine -t zerotrace-engine:ci .
docker build -t zerotrace-bff:ci frontend
```

## Known gaps

- No SBOM, dependency-audit gate, load test, or restore drill in CI yet.
- Branch protection, signed releases, changelog/semver automation, and staged
  rollout are pending.
- CodeQL has not run in GitHub Actions yet; the workflow is committed for the
  first CI run.
- The full Phase 18 release gate and human signoff are still required.
