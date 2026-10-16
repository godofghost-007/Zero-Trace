# Constraints

Last reviewed: 2026-10-17 · Status: **draft v0.1 — defaults applied, awaiting the owner's confirmation on the four questions at the bottom**

This is ZeroTrace's written quality bar. Read it before writing code. **Do not weaken it to make a change pass.**

Two sources of numbers appear below:
- `[source]` — comes from the ZeroTrace v2.0 project documentation. It is an acceptance criterion inherited from the spec, not a measured fact.
- `[default]` — a sane default chosen because there was no number yet. Replace it with a real one when you have one.

---

## Floor (always enforced, no setup required)

Passes on the current codebase. Checked by reading the diff.

- No new suppression comments: `# type: ignore`, `# noqa`, `# pragma: no cover`, `@pytest.mark.skip` without a reason in the commit message
- No unimplemented stubs: `raise NotImplementedError`, `pass  # TODO`, empty `except: pass` that swallows a failure
- No skipped or deleted tests without a reason in the commit message
- No secrets in source (keys, tokens, passwords, connection strings with credentials)
- No `shell=True` with interpolated input; no raw SQL string building
- **This file does not get weakened to make a change pass**

---

## Enforced with numbers

`Checked by` names the command that produces the verdict. A dimension with a number and no command is an aspiration, not a constraint.

| Dimension | Rule | Checked by | Runs at | Active from |
|---|---|---|---|---|
| Types | Zero mypy errors on changed modules | `mypy app` | task end | Phase 2 |
| Lint | Zero ruff errors | `ruff check .` | every edit | Phase 2 |
| Format | No format drift | `ruff format --check .` | every edit | Phase 2 |
| Secrets | No secrets in source | `gitleaks detect --redact --no-banner` | every edit | Phase 2 |
| Coverage | Changed lines ≥ **80%** `[default]` | `pytest --cov --cov-report=lcov` + `git diff` | task end | Phase 3 |
| Security: code | No high findings | `semgrep scan --config p/python --config p/owasp-top-ten` | task end, SHIP | Phase 3 |
| Security: deps | Nothing at high or above | `python -m pip_audit` (or `osv-scanner scan source -r .`) | SHIP | Phase 2 |
| Architecture | Module boundaries hold | `lint-imports` (import-linter contract) | task end | Phase 3 |
| Score engine | Deterministic, monotone, bounded `[source]` | `pytest tests/test_score_properties.py` | task end | Phase 6 |
| Audit chain | Tamper detection works | `pytest tests/test_audit_chain.py` | task end | Phase 5 |
| Guard overhead | ≤ **50 ms** added on a 500 ms baseline `[source]` | `pytest tests/bench/test_guard_latency.py` | SHIP | Phase 5 |
| Guard regex | ≤ **5 ms** per prompt `[source]` | same harness | SHIP | Phase 5 |
| Guard ONNX | ≤ **20 ms** per prompt `[source]` | same harness | SHIP | Phase 5 |
| Rate limiter | ≤ **10 of 100** requests in 10 s processed `[source]` | `pytest tests/test_rate_limit.py` | task end | Phase 5 |
| Jailbreak catch | Regex ≥ **60%**, ONNX ≥ **85%**, combined ≥ **92%** `[source]` | `pytest -m eval` on pinned JailbreakBench set | SHIP | Phase 5 |
| False positives | ≤ **5%** on 500 legitimate prompts `[source]` | `pytest -m eval` on pinned ShareGPT set | SHIP | Phase 5 |
| PII recall / FP | Recall ≥ **90%**, clean-file redaction ≤ **10%** `[source]` | `pytest -m eval` on seeded fixtures | SHIP | Phase 6 |
| Recall / precision | Subdomain ≥ **90%** / ≥ **95%** `[source]` | `pytest -m eval` on labelled domain set | SHIP | Phase 3 |
| Scanner parity | Nmap parity **100%**, S3 FP ≤ 5%, FN ≤ 10%, TLS expiry **100%** `[source]` | `pytest -m eval` | SHIP | Phase 3 |
| Patch ranking | Top-20 vs KEV overlap ≥ **60%** `[source]` | `pytest -m eval` | SHIP | Phase 4 |
| CPE match | ≥ **90%** correct, 48 h NVD completeness ≥ **99%** `[source]` | `pytest -m eval` | SHIP | Phase 4 |
| Compose validity | Config parses, profiles resolve | `docker compose config` | SHIP | Phase 8 |

**Not covered on purpose:** accessibility, LCP/CLS and bundle budgets. ZeroTrace has no public marketing page; the dashboard is a local server-rendered UI. Adding those dimensions would create checks that cannot run, which is worse than having none.

---

## Measured, not yet enforced (ratchets)

Record today's value. Every check compares against the recorded value, not an aspiration. When a number improves, update it; when it drops, that is the finding.

| Metric | Today | Direction | First measured |
|---|---|---|---|
| Host physical RAM total | 19.77 GB | must not change (hardware) | 2026-10-17 |
| Free physical RAM, LM Studio loaded | **1.08 GB** | must stay ≥ 2 GB with stack running | 2026-10-17 |
| `llama-server` resident memory, 4B @ 32K | **4.66 GB** | must not grow | 2026-10-17 |
| Total stack footprint (target ≈ 9 GB `[source]`) | not yet measurable (no stack) | must not exceed 9 GB | pending |
| Cold start to all services healthy | not yet measurable | must not grow | pending |
| Effective generation throughput | see `scripts/bench-results.json` | must not fall | 2026-10-17 |
| Project test coverage | 0% (no tests yet) | must not fall | pending |
| Dependency count (direct) | 0 | must not grow without a reason | pending |

Ratchets change in a PR that explains the movement. A ratchet that silently drops is a finding, not a detail.

---

## Exceptions

| ID | Rule | Path | Reason | Owner | Expires |
|---|---|---|---|---|---|
| — | *(none)* | | | | |

An exception needs an owner and an expiry. Entries older than 90 days without a re-justification are removed.

---

## Where each check runs

| Phase | Command | What runs | Budget |
|---|---|---|---|
| BUILD (after an edit) | `scripts/check-fast.ps1` *(to be created)* | ruff, format, secrets; changed files only | under 5 s |
| VERIFY (task end) | `scripts/check-task.ps1` *(to be created)* | the fast set + mypy + tests with coverage on changed lines | under 90 s `[default]` |
| REVIEW | manual diff read | the floor, the guard checks below | minutes |
| SHIP | `scripts/check-full.ps1` *(to be created)* | everything above + semgrep + pip-audit + eval markers | unlimited |

**Hardware reality note:** this machine has 2 physical cores. A full `mypy` + `pytest` run may exceed the 90 s budget, so the VERIFY stage must be diff-scoped; full runs belong to SHIP. If VERIFY regularly overruns, the fix is scoping, not deleting the check.

---

## Guarding the bar (watch these in every diff)

The agent writes both the code and most of the checks, so at review time look for the five cheap routes to green:

1. **A threshold moved** — compare `CONSTRAINTS.md` against its state at the branch point.
2. **A test got easier** — a `.skip` added, a test file deleted, assertions removed from a test that stayed.
3. **A checker got silenced** — the four that matter most here: `istanbul ignore` / `# pragma: no cover` (drops code from coverage), `nosemgrep` and `gitleaks:allow` (switch off the security dimension).
4. **Work is unfinished** — a stub that raises, an empty `except` turning a failure into silence, a `TODO` where the implementation should be.
5. **An exception appeared** — a new row in the Exceptions table nobody discussed.

Tightening the bar should be silent. Loosening it should be loud.

---

## The four questions (please confirm or override)

Defaults were applied above. Answering "fine" keeps them.

1. **Beyond the floor, which dimensions?**
   Default: **coverage + security**, plus the `[source]` performance and detection gates because your spec already states them.
   Not proposed: accessibility, web-vitals, bundle size (no public page to measure).
2. **When a check fails mid-task: block or warn?**
   Default: **block on the floor, warn on the rest for the first two weeks.**
3. **Numbers in mind, or measure and hold?**
   Default: **measure and hold** — the ratchet table above.
4. **Slowest check tolerated at task end?**
   Default: **90 seconds**, unlimited in SHIP.

Two of these numbers cannot be met by this laptop and are worth knowing now: the 90 s VERIFY budget and the ≤50 ms Guard overhead both need diff-scoping and careful fixture sizing to hold on 2 cores. They stay as written until measured evidence says otherwise.
