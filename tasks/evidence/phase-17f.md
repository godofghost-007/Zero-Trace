# Phase 17F evidence - CI, supply chain, and release engineering

Date: 2026-10-25

## Implemented

- `.github/workflows/ci.yml`:
  - engine tests with a disposable PostgreSQL service;
  - BFF identity tests;
  - frontend typecheck, tests, and production build;
  - runtime security and load smoke;
  - dependency audit (`pip-audit`) for the engine and BFF environments;
  - Python CycloneDX SBOM artifacts;
  - BFF, engine, and custom Caddy container builds with image SBOMs.
- `.github/workflows/codeql.yml` for Python and JavaScript/TypeScript.
- `.github/workflows/release.yml` for tag builds:
  - pushes immutable BFF, engine, and Caddy images to GHCR;
  - signs them with cosign keyless signing;
  - attaches build-provenance attestations;
  - generates image SBOMs and a GitHub release.
- `.github/rulesets/main.json` and `docs/BRANCH-PROTECTION.md` for the main
  branch rules and required checks.
- `.github/pull_request_template.md` with safety, verification, and evidence
  checks.
- Apache-2.0 `LICENSE`, `NOTICE`, package metadata, and frontend package license.
- `docs/RELEASE-PROCESS.md` for semver, staged rollout, expand/contract
  migrations, rollback, and the honest limits of the current evidence.

## Verification

```text
py -3.13 -m pytest -q
265 passed

frontend\.venv\Scripts\python.exe -m pytest backend/tests -q
61 passed

pnpm check
pnpm test
6 frontend tests passed

pnpm build
# production build completed
```

```text
py -3.13 -m pip_audit
# No known vulnerabilities found

py -3.13 -m pip_audit -r frontend\requirements.txt
# No known vulnerabilities found
```

The dependency audit forced upgrades to `cryptography>=50,<51`, Flask 3.1.3,
and pytest 9.0.3. The root and BFF environments were re-audited after the
upgrade.

```text
py -3.13 -m scripts.generate_sbom --output tasks/evidence/sbom-python.json
# 69 components

frontend\.venv\Scripts\python.exe -m scripts.generate_sbom \
  --requirements frontend/requirements.txt \
  --output tasks/evidence/sbom-frontend.json
# 9 components on Windows (gunicorn is excluded by its platform marker)
```

```text
py -3.13 -m scripts.security_smoke
# passed=true
```

```text
frontend\.venv\Scripts\python.exe -m scripts.load_test \
  --requests 100 --concurrency 10 --fail
# 200/200 200s, p95 92.69 ms, passed=true
```

```text
py -3.13 -m scripts.run_migrations
py -3.13 -m scripts.run_migrations --rollback
# 0009 and 0008 rolled back; latest version 0007
```

Evidence: `tasks/evidence/migration-rollback.json`.

## Known gaps

- No git remote is configured, so CI, CodeQL, branch protection, and the release
  workflow have not run in GitHub Actions.
- No signed release has been published.
- No production VPS or Supabase deployment has been performed.
- The release workflow uses GHCR and cosign keyless signing but has not been
  exercised on a real tag.
- The custom Caddy image includes a pinned third-party rate-limit module; it was
  built and validated locally, not in CI or production.
- The load test is an embedded Flask/SQLite smoke test, not a Gunicorn/
  PostgreSQL/TLS capacity test.
- There is no browser E2E suite for login, scope creation, multi-profile scans,
  KEV sync, Guard inspection, and failure states.
- The Phase 18 release gate and human signoff are still required.
