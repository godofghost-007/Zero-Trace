# skilladdy.md — ZeroTrace skill index

> **Purpose:** the single list of agent skills needed to build ZeroTrace, which of them to load at each step, and how much context each one costs.
> **Compiled:** 2026-10-17 · **Sources:** `C:\Users\aniru\.agents\skills` (Addy Osmani pack, 26 skills) · your own `SKILL.md` (`github-gem-seeker`) · ZeroTrace wiki pages 02–10.
> **Companions:** `AGENTS.md` (always-on project rules) and `CONSTRAINTS.md` (the written quality bar). Keep skill files for *workflows*; keep permanent rules in those two files.

---

## TL;DR

- **27 skills apply** to this project (26 installed + your `github-gem-seeker`).
- You can **never load them all**: together they are roughly **105,000 tokens**. Your 4B model runs a **32,768-token** window. Loading all of them is physically impossible.
- **Load 2–3 at a time**, matched to the current phase (tables in section 3).
- **Six behaviors belong always-on** — distill them into `AGENTS.md` so they never cost a skill load:
  `using-agent-skills` (surface assumptions, stop on confusion) · `constraint-driven-development` (never lower the bar) · `incremental-implementation` (thin slices) · `git-workflow-and-versioning` (commit before/after every slice) · `source-driven-development` (verify against official docs) · `code-review-and-quality` (review the diff before it lands).
- **Highest-leverage for ZeroTrace**, in order: `security-and-hardening` → `test-driven-development` → `performance-optimization` → `constraint-driven-development` → `api-and-interface-design` → `observability-and-instrumentation`.
- **One gap to fill:** nothing in the pack covers ML/ONNX/XGBoost evaluation. Use `find-skills` + `github-gem-seeker` (section 5).

---

## 1. Where the skills live and how to load them

| Item | Value |
|---|---|
| Installed pack | `C:\Users\aniru\.agents\skills\<skill-name>\SKILL.md` (26 skills) |
| Your own skill | `...\Compile ZeroTrace project wiki and implementation strategies\SKILL.md` → name `github-gem-seeker` (**not installed** yet; see section 6) |
| How to invoke | Ask in plain language: *"use the security-and-hardening skill on this diff"*, or let the agent load it via its skill tool when the trigger in the description matches |
| Loading cost | the whole `SKILL.md` enters the context window |

**Load rules for your laptop (2-core i3, 32K context on the 4B):**

1. **Max 3 skills at once** on the 4B; **max 2** on the 9B when a large file is also in context.
2. Never load two *large* skills (≥16 KB) together with a big source file.
3. Start a **fresh session per phase** (table in section 3) instead of carrying old skill text forward.
4. Prefer the **trigger** over willpower: skills fire by description match, so phrase the work in the skill's own vocabulary ("set up constraints", "review this diff", "something broke").

---

## 2. Verdict: every skill, and whether ZeroTrace needs it

### Tier A — always-on behaviors (write into `AGENTS.md`, don't load as files)

| Skill | Size | Why it is always-on here |
|---|---|---|
| `using-agent-skills` | 10.2 KB | meta-skill: routes every task, enforces "surface assumptions / stop on confusion" |
| `context-engineering` | 15.1 KB | you are context-starved; rules files + session hygiene decide output quality |
| `constraint-driven-development` | 20.5 KB | 9 GB budget, ≤50 ms Guard overhead, no auto-applied patches — this is the contract |
| `incremental-implementation` | 9.4 KB | a 2-core CPU cannot land features in one shot |
| `git-workflow-and-versioning` | 13.8 KB | ZeroTrace is **not a git repo yet** — no rollback path exists today |
| `source-driven-development` | 9.8 KB | wiki rule #3: separate source facts from decisions; verify FastAPI/Postgres/ONNX APIs |

### Tier B — load per phase (section 3)

| Skill | Size | ZeroTrace use |
|---|---|---|
| `spec-driven-development` | 12.8 KB | turn wiki pages into per-module specs with acceptance checks |
| `planning-and-task-breakdown` | 10.3 KB | order the module work; estimate the 9 GB envelope |
| `interview-me` | 14.7 KB | closes the 5 "Open decisions" in `04 ZeroTrace architecture.md` |
| `idea-refine` | 9.0 KB | only if scope is reopened (core-vs-full profile, GLM/Qwen choice) |
| `test-driven-development` | 16.3 KB | score fixture **73 not 71**, CPE matching, hash-chain verify, eval matrix |
| `debugging-and-error-recovery` | 10.7 KB | WSL2/Docker/postgres-on-2-cores failures |
| `code-review-and-quality` | 20.5 KB | review every diff; catches small-model sloppiness |
| `code-simplification` | 13.2 KB | small models write verbose code; RAM and reviewability both suffer |
| `doubt-driven-development` | 16.3 KB | security-sensitive: hash chain, auth, SSRF, fail-open policy |
| `documentation-and-adrs` | 10.7 KB | record formula version, discrepancies, upstream license decisions |
| `observability-and-instrumentation` | 13.6 KB | DEGRADED health states, GuardEvent metadata, audit, eval evidence |
| `performance-optimization` | 16.3 KB | the 9 GB goal, ≤50 ms proxy overhead, ≤10-min scan, DB query cost |
| `shipping-and-launch` | 11.2 KB | profiles, backups+restore test, rollback, pre-launch checklist |
| `ci-cd-and-automation` | 11.1 KB | quality gates for tests/lint (deferred until Phase 8) |

### Tier C — load per module

| Skill | Size | Module |
|---|---|---|
| `api-and-interface-design` | 14.5 KB | FastAPI control API, Guard `/v1` contract, adapter interfaces, event schema |
| `security-and-hardening` | 17.1 KB | **the product itself**: auth/RBAC, key hashes, secrets, SSRF allowlists, PII, dependency audit |
| `frontend-ui-engineering` | 11.4 KB | Flask + HTMX + Alpine dashboard |
| `browser-testing-with-devtools` | 14.2 KB | dashboard UI tests — **blocked**: needs the chrome-devtools MCP server, which is not configured |
| `deprecation-and-migration` | 12.3 KB | Alembic expand/contract migrations; swapping upstreams (LiteLLM → own proxy) |
| `find-skills` | 5.3 KB | install the missing ML/Docker/Postgres skills (section 5) |
| `github-gem-seeker` (yours) | 4.1 KB | Approach B reuse: Subfinder, Nmap, NVD/EPSS, Optimum ONNX, LiteLLM, xgboost |

**Nothing in the pack is useless here.** The only *conditionally* relevant ones are `browser-testing-with-devtools` (needs MCP), `idea-refine` and `interview-me` (Phase 0/1 only), and `find-skills` (occasional).

---

## 3. Load set per phase

| Phase | Goal | Load (2–3) | Deliverable / evidence |
|---|---|---|---|
| **0. Constraints & evidence** | make the budget real | `constraint-driven-development` · `source-driven-development` · `context-engineering` | `CONSTRAINTS.md` (9 GB cap, latency/eval gates), `MEASURED.md` (hardware, tok/s, LM Studio config) |
| **1. Spec & tasks** | turn the wiki into buildable specs | `spec-driven-development` · `planning-and-task-breakdown` · `interview-me` | module specs + ordered `TASKS.md`; 5 open decisions closed |
| **2. Repo & git safety** | rollback exists | `git-workflow-and-versioning` · `incremental-implementation` | `git init`, `.gitignore` (exclude models/ONNX/weights), `README.md`, first vertical slice |
| **3. Recon** | passive discovery → normalized findings | `api-and-interface-design` · `test-driven-development` · `security-and-hardening` | `SubdomainProvider`/`PortScanner` adapters with fakes, authorization allowlist, golden fixtures |
| **4. Intel** | feeds → ranking → proposals | `test-driven-development` · `performance-optimization` · `github-gem-seeker` | NVD/EPSS ingest + CPE matcher tests, `Scorer` interface, patch proposals stuck in `proposed` |
| **5. Guard** | OpenAI-compatible protection | `security-and-hardening` · `observability-and-instrumentation` · `test-driven-development` | `/v1/chat/completions`, regex→ONNX→PII pipeline, SHA-256 chain, DEGRADED states, limiter tests |
| **6. Score & evaluation** | the number is reproducible | `test-driven-development` · `observability-and-instrumentation` · `performance-optimization` | formula v1 with the corrected **73** fixture; eval matrix run with recorded evidence |
| **7. Dashboard** | operator view | `frontend-ui-engineering` · `api-and-interface-design` · (+ `browser-testing-with-devtools` when MCP exists) | inventory, findings, patch queue, Guard events, score with components and coverage |
| **8. Ship & operate** | repeatable deployment | `shipping-and-launch` · `code-review-and-quality` · `ci-cd-and-automation` | `core`/`full`/`dev` profiles, backup+restore test, rollback plan, pre-launch checklist |

**Cross-cutting (call on demand, any phase):** `debugging-and-error-recovery` (something broke) · `doubt-driven-development` (irreversible or security-critical change) · `code-review-and-quality` (before merge) · `code-simplification` (diff got ugly) · `documentation-and-adrs` (a decision was made) · `find-skills` / `idea-refine`.

---

## 4. Module × skill matrix

| ZeroTrace area | Primary skills | Supporting |
|---|---|---|
| Recon worker | `api-and-interface-design`, `test-driven-development`, `security-and-hardening` | `performance-optimization`, `observability-and-instrumentation` |
| Intel worker (NVD/EPSS/CPE/XGBoost) | `test-driven-development`, `performance-optimization` | `github-gem-seeker`, `source-driven-development` |
| Guard middleware | `security-and-hardening`, `observability-and-instrumentation` | `test-driven-development`, `performance-optimization`, `doubt-driven-development` |
| Score engine | `test-driven-development`, `observability-and-instrumentation` | `performance-optimization`, `documentation-and-adrs` |
| Control API | `api-and-interface-design` | `security-and-hardening`, `observability-and-instrumentation` |
| Dashboard (Flask+HTMX+Alpine) | `frontend-ui-engineering` | `api-and-interface-design`, `browser-testing-with-devtools` (blocked) |
| Postgres/Alembic/events | `deprecation-and-migration` | `api-and-interface-design`, `test-driven-development` |
| Compose, profiles, 9 GB envelope | `performance-optimization`, `constraint-driven-development` | `ci-cd-and-automation`, `shipping-and-launch` |
| Eval matrix & evidence | `test-driven-development`, `observability-and-instrumentation` | `performance-optimization`, `documentation-and-adrs` |

---

## 5. Gap analysis — what the pack does **not** cover

| Need in ZeroTrace | Covered by? | Fix |
|---|---|---|
| ONNX export, tokenizer pinning, threshold calibration | partly (`source-driven-development` cites the Optimum docs) | `npx skills find onnx` / `npx skills find model evaluation` |
| XGBoost feature/model versioning | partly | `npx skills find machine learning python` |
| Docker Compose authoring/debugging | not covered | `npx skills find docker compose` |
| PostgreSQL schema/migration depth | partly (`deprecation-and-migration` = expand/contract) | `npx skills find postgres` |
| FastAPI-specific patterns | partly (`api-and-interface-design`) | `npx skills find fastapi` |

Commands (from the `find-skills` skill):

```bash
npx skills find "machine learning evaluation"
npx skills add <package>
npx skills check
npx skills update
```

These need network access — do it deliberately, not mid-build.

---

## 6. Context cost reference (why you load 2–3, not 27)

Rough cost = KB × ~290 tokens. Measured against your 32,768-token 4B window:

| Skill | KB | ≈ tokens |
|---|---:|---:|
| `code-review-and-quality` | 20.5 | ~5,900 |
| `constraint-driven-development` | 20.5 | ~5,900 |
| `security-and-hardening` | 17.1 | ~5,000 |
| `doubt-driven-development` | 16.3 | ~4,700 |
| `performance-optimization` | 16.3 | ~4,700 |
| `test-driven-development` | 16.3 | ~4,700 |
| `context-engineering` | 15.1 | ~4,400 |
| `interview-me` | 14.7 | ~4,300 |
| `api-and-interface-design` | 14.5 | ~4,200 |
| `browser-testing-with-devtools` | 14.2 | ~4,100 |
| `git-workflow-and-versioning` | 13.8 | ~4,000 |
| `observability-and-instrumentation` | 13.6 | ~3,900 |
| `code-simplification` | 13.2 | ~3,800 |
| `spec-driven-development` | 12.8 | ~3,700 |
| `deprecation-and-migration` | 12.3 | ~3,600 |
| `frontend-ui-engineering` | 11.4 | ~3,300 |
| `ci-cd-and-automation` | 11.1 | ~3,200 |
| `shipping-and-launch` | 11.2 | ~3,200 |
| `debugging-and-error-recovery` | 10.7 | ~3,100 |
| `documentation-and-adrs` | 10.7 | ~3,100 |
| `planning-and-task-breakdown` | 10.3 | ~3,000 |
| `using-agent-skills` | 10.2 | ~3,000 |
| `source-driven-development` | 9.8 | ~2,800 |
| `idea-refine` | 9.0 | ~2,600 |
| `incremental-implementation` | 9.4 | ~2,700 |
| `find-skills` | 5.3 | ~1,500 |
| `github-gem-seeker` | 4.1 | ~1,200 |
| **Total** | **~369** | **~105,000** |

> 105,000 tokens of skills vs a 32,768-token window: **the index is the point.** Load three, work, start fresh.

---

## 7. Full path list (copy-paste ready)

```
C:\Users\aniru\.agents\skills\api-and-interface-design\SKILL.md
C:\Users\aniru\.agents\skills\browser-testing-with-devtools\SKILL.md
C:\Users\aniru\.agents\skills\ci-cd-and-automation\SKILL.md
C:\Users\aniru\.agents\skills\code-review-and-quality\SKILL.md
C:\Users\aniru\.agents\skills\code-simplification\SKILL.md
C:\Users\aniru\.agents\skills\constraint-driven-development\SKILL.md
C:\Users\aniru\.agents\skills\context-engineering\SKILL.md
C:\Users\aniru\.agents\skills\debugging-and-error-recovery\SKILL.md
C:\Users\aniru\.agents\skills\deprecation-and-migration\SKILL.md
C:\Users\aniru\.agents\skills\documentation-and-adrs\SKILL.md
C:\Users\aniru\.agents\skills\doubt-driven-development\SKILL.md
C:\Users\aniru\.agents\skills\find-skills\SKILL.md
C:\Users\aniru\.agents\skills\frontend-ui-engineering\SKILL.md
C:\Users\aniru\.agents\skills\git-workflow-and-versioning\SKILL.md
C:\Users\aniru\.agents\skills\idea-refine\SKILL.md
C:\Users\aniru\.agents\skills\incremental-implementation\SKILL.md
C:\Users\aniru\.agents\skills\interview-me\SKILL.md
C:\Users\aniru\.agents\skills\observability-and-instrumentation\SKILL.md
C:\Users\aniru\.agents\skills\performance-optimization\SKILL.md
C:\Users\aniru\.agents\skills\planning-and-task-breakdown\SKILL.md
C:\Users\aniru\.agents\skills\security-and-hardening\SKILL.md
C:\Users\aniru\.agents\skills\shipping-and-launch\SKILL.md
C:\Users\aniru\.agents\skills\source-driven-development\SKILL.md
C:\Users\aniru\.agents\skills\spec-driven-development\SKILL.md
C:\Users\aniru\.agents\skills\test-driven-development\SKILL.md
C:\Users\aniru\.agents\skills\using-agent-skills\SKILL.md
```

**Your own skill (not installed):**
```
C:\Users\aniru\OneDrive\Desktop\ZeroTrace\Compile ZeroTrace project wiki and implementation strategies\SKILL.md
```
To make it usable from OpenCode, copy it to `C:\Users\aniru\.agents\skills\github-gem-seeker\SKILL.md`.

---

## 8. Skill → project artifact map (what each skill produces here)

| Skill | Artifact it produces in ZeroTrace |
|---|---|
| `constraint-driven-development` | `CONSTRAINTS.md` — 9 GB cap, ≤50 ms overhead, ≥92% catch target, no auto-apply |
| `context-engineering` | `AGENTS.md` + session hygiene rules |
| `spec-driven-development` | one spec per module (Recon/Intel/Guard/Score/Dashboard) |
| `planning-and-task-breakdown` | ordered task list gated by the eval matrix |
| `test-driven-development` | the 73-score fixture, CPE matcher tests, hash-chain tests |
| `api-and-interface-design` | adapter interfaces + OpenAPI schema + event contract |
| `security-and-hardening` | auth/RBAC, key hashing, secret handling, SSRF/PII controls, dependency audit |
| `observability-and-instrumentation` | `/health`, `/ready`, DEGRADED states, audit metadata, eval evidence |
| `performance-optimization` | measured 9 GB / cold-start / latency evidence per profile |
| `frontend-ui-engineering` | dashboard pages with score components + coverage |
| `deprecation-and-migration` | Alembic revisions; upstream swap plan |
| `documentation-and-adrs` | ADRs for the 5 open decisions + discrepancy log |
| `shipping-and-launch` | pre-launch checklist, backup/restore test, rollback |
| `github-gem-seeker` | reuse decisions with licenses pinned (Subfinder, Nmap, LiteLLM, Optimum) |
