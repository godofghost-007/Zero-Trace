# AGENTS.md — ZeroTrace

Project rules for any agent working in this repository. Read this file first, every session.

## 1. Hard scope rule (location)

**Repository root: `E:\zerotrace-demo`. This is the only place project work happens.**

- All project code, tests, fixtures, config, docs and scripts live under `E:\zerotrace-demo`. Never create, edit or run project files outside it — not on the Desktop, not in OneDrive, not in `%TEMP%`.
- **Do not transfer or relocate assets.** Model weights (`C:\Users\aniru\.lmstudio\models`), Docker/WSL2 images and volumes, pip/npm caches and the LM Studio install stay where they are. They are runtime assets, not project files.
- `E:\zerotrace-demo\ZeroTrace\` holds the **source documentation** (wiki pages, PDFs). Treat it as reference; do not scatter build artifacts into it.
- `C:\Users\aniru\OneDrive\Desktop\ZeroTrace` is a **read-only archive**. Never edit it.
- Temporary scratch work goes to `C:\Users\aniru\AppData\Local\Temp\opencode`.

## 2. Read order (context is the scarce resource)

1. `AGENTS.md` (this file)
2. `skilladdy.md` — which skills apply, and what not to load
3. `CONSTRAINTS.md` — the written quality bar
4. `ZeroTrace\02 ZeroTrace — compiled project wiki.md` — the wiki index
5. **Only** the specific module page needed for the task

Never read the raw PDFs or `01 …p1-26.txt` unless auditing a source claim. Never paste whole doc pages into context when a summary will do.

## 3. Always-on behaviors

**Read `CONSTRAINTS.md` before writing code. Do not weaken it to make a change pass.**

These six apply to every task without being loaded as skill files:

| Behavior | Rule |
|---|---|
| Surface assumptions | State assumptions before non-trivial work: *"Correct me now or I proceed."* |
| Stop on confusion | Conflicting spec or unclear requirement → stop, name it, ask. Never guess silently. |
| Never lower the bar | Don't add `@ts-ignore`/`# type: ignore`/skips, don't delete or weaken tests, don't stub and claim done. |
| Thin slices | One small verifiable change at a time, committed on its own. |
| Verify against sources | Check official docs (FastAPI, SQLAlchemy, ONNX Runtime, LM Studio) before coding against memory. |
| Review the diff | Read every change before it lands; small models produce plausible-looking wrong code. |

## 4. Non-negotiables (from the project source)

- **Patch proposals are never auto-applied.** Default state is `proposed`; human review plus isolated validation required. Generated scripts are never executed against a real target.
- **Scans only on explicitly authorized scope.** Allowlist, bounded concurrency, timeouts, safe Nmap profiles, no arbitrary-argument scan endpoints.
- **Never persist raw prompts/responses by default.** Guard audit stores hashes, lengths, outcomes and endpoint IDs.
- **Failures must be visible.** A missing ONNX model, stale feed or unavailable upstream reports `DEGRADED` — never an apparently healthy result.
- **The score equation is authoritative:** `Score = clamp(100 − (0.40×AEI + 0.40×VUI + 0.20×AIET), 0, 100)`. The source's `71` fixture is wrong; the correct value is **73**.
- **Readiness states change only with implementation or test evidence.** Never mark something done because it was described.

## 5. Machine and runtime facts

| Item | Value |
|---|---|
| CPU / RAM / GPU | Intel i3-1005G1, 2 cores / 20 GB / Intel UHD only |
| Free disk | E: ~96 GB, C: ~15 GB free |
| Inference | LM Studio, OpenAI-compatible, **port 1235** |
| Speed reality | ~8–12 tok/s (4B, Phi-4) · ~3–5 tok/s (9B) |
| Context | 32,768 on the 4B, KV cache Q8_0, parallel 1 |
| Concurrency | Only **one model loaded at a time** (JIT unload on switch) |

Budget target from the source: **~9 GB total footprint**. Treat it as a benchmark, not a proven number.

## 6. Model routing

| Model (OpenCode ref) | Use for |
|---|---|
| `lmstudio/qwen3.5-4b` | **default driver** — tool calling, file edits, routine work |
| `lmstudio/qwen/qwen3.5-9b` | coding sessions, **only with the Docker stack stopped** |
| `lmstudio/phi-4-mini-reasoning` | reasoning/Q&A only — **tools are disabled**, it cannot edit files |

Never run the 9B and the Docker stack at the same time. Thinking mode stays **off** for the 4B driver.

## 7. Skill loading rules

- Load **2–3 skills at most**; all 27 skills total ~105,000 tokens against a 32,768-token window.
- Start a **fresh session per phase** rather than carrying old skill text forward.
- Load set per phase is in `skilladdy.md`. Follow it.
- Don't load a skill file to get a behavior listed in section 3 — those are already here for free.

## 8. Git rules

- Commit **after every verified slice**; one logical change per commit.
- Never commit: `.env`, model weights (`*.gguf`, `*.onnx`), audit databases, `data/`, virtualenvs, secrets, API keys.
- Never rewrite history on a branch that has been pushed.

## 9. Definition of done

A task is done when:
1. The acceptance check exists and was run.
2. The evidence (test output, measurement, command) is recorded — not asserted from memory.
3. The diff was reviewed for weakened tests, suppressions or stubs.
4. `CONSTRAINTS.md` thresholds still hold; if a threshold had to move, it was agreed, not edited quietly.
