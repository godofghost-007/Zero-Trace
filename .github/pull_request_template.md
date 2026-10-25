# Pull request

## What changed

<!-- One paragraph. Link the phase/task if applicable. -->

## Security and safety

- [ ] No new target-scanning capability outside an approved, unexpired scope.
- [ ] High/Deep scans still require `isolated_lab` plus verified DNS TXT.
- [ ] No provider key, session token, or backup key is exposed to the browser.
- [ ] Engine URLs remain loopback-only.
- [ ] New user input is validated and encoded at the boundary.
- [ ] No `@ts-ignore`, `# noqa`, skipped test, or lowered threshold was added
      without a written reason.

## Verification

- [ ] `pytest -q`
- [ ] `cd frontend && python -m pytest backend/tests -q`
- [ ] `python -m scripts.security_smoke`
- [ ] `python -m scripts.load_test --requests 100 --concurrency 10 --fail`
- [ ] `python -m scripts.evaluate_guard`
- [ ] Container or Compose configuration validated if deployment changed.

## Evidence and docs

- [ ] Updated `tasks/todo.md` and the relevant evidence file.
- [ ] Updated `docs/PRODUCTION-READINESS.md` if the scorecard changed.
- [ ] Added an ADR for a durable architecture decision.
- [ ] Called out anything that is not production-ready instead of implying it is.
