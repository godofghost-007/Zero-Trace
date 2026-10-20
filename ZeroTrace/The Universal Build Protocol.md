# The Universal Build Protocol

[← Master index](index.md) · Related: [CPU Runtimes & Models](models-and-runtimes.md) · [Agent Frameworks & Harnesses](agent-frameworks.md) · [Tool Arsenal](github-gems.md)

## Goal

Move from a description to a working, reviewable app, script, or automation while minimizing context, dependencies, memory pressure, and unreviewed changes. **Selected default for this project:** GitHub Copilot Pro in VS Code, using a small, project-local selection of Addy Osmani's agent-skills. This is a hosted/hybrid workflow; project context may leave the machine. Use local Ollama/llama.cpp only when the task needs offline/private inference or another specific local capability. Never silently send code or prompts to an external model.

## Phase 0 — Establish constraints

Record:

- Operating system and shell.
- CPU model and available RAM.
- GPU, VRAM and driver/runtime if present.
- Free disk space and whether model downloads are acceptable.
- Local-only, hybrid, or cloud mode; privacy and external network restrictions.
- Desired artifact, acceptance criteria, test command, and threat/safety boundaries.
- Copilot AI-credit budget and whether project source/context may be processed by a hosted service.

Set a resource budget with headroom for the operating system, editor, inference runtime, model weights, context cache, harness, and build/test process. Do not accept the source's estimated budget as measured evidence.

## Phase 1 — Define a small build target

Turn the request into:

1. **Outcome:** one sentence describing what will exist when done.
2. **Scope:** permitted files/features and explicit non-goals.
3. **Acceptance checks:** observable behavior and test/verification commands.
4. **Constraints:** language, framework, dependencies, offline/network behavior, security.
5. **Milestones:** thin vertical slices, each independently runnable/testable.

Prefer a minimal `README.md`, `AGENTS.md`/project rule file, and short `PLAN.md` over a large permanent prompt pack. Keep authoritative instructions concise.

## Phase 2 — Inspect only relevant context

- Check Git status and project tree before edits.
- Identify entry points, interfaces, tests, dependency manifest and directly related modules.
- Use `rg`, IDE symbol search, or targeted file reads before creating a repository bundle.
- Use Repomix only when a harness cannot obtain adequate repository context itself. Include narrow globs and honor ignore rules; exclude secrets, generated files, vendored dependencies and binaries.
- For external documentation, fetch only authorized public pages needed for the task. For local PDFs/office files, use an appropriate parser only when required; validate extracted tables and diagrams.

Do not send an entire repository or reference archive into every turn. Pass a concise summary, relevant interface definitions, and only the files required for the next change.

## Phase 3 — Prepare the chosen inference path

For the selected Copilot workflow, update VS Code and the Copilot extension, confirm the desired account/plan, install only the chosen skills under `.github/skills/`, and add concise repository rules to `.github/copilot-instructions.md`. Confirm skills are discovered in Copilot Chat, then use one bounded task to test the workflow. Watch the GitHub AI-credit usage view; disable or cap additional spend if a hard budget is required.

Only for tasks that need local inference: select one compatible model artifact and record its exact ID, quantization, source/license and chat template; start with one runtime (Ollama for low-friction API access, or llama.cpp for low-level control); use modest context and single-request concurrency; verify the expected model, GPU placement, system RAM, VRAM, and thermals. Reduce context/model size or use a smaller supported model if resource pressure or latency is high.

The supplied source's sample model IDs and command flags may be stale or not published exactly as written. Resolve the current installed model name with the runtime's list/tag output. Check the harness's current provider syntax instead of assuming API aliases are interchangeable.

## Phase 4 — Build one vertical slice

For each slice:

1. Ask the harness for a short plan and proposed file list.
2. Confirm the plan stays within scope; request one small behavior or module at a time.
3. Permit only relevant file edits and necessary commands. Keep auto-approval disabled during evaluation.
4. Ask for tests alongside the change where practical.
5. Run the targeted test, formatter, type checker, and static checks locally.
6. Give only the relevant failure and traceback back to the model; request a minimal fix.
7. Review the entire diff for unrelated changes, insecure defaults, placeholder code, secrets, destructive commands, and dependency creep.
8. Commit after the change passes its checks; document unresolved issues and next step.

A useful task prompt format:

```text
Goal: <one observable behavior>
Allowed files: <small exact list or folder>
Constraints: <interfaces, style, safety, dependency limits>
Acceptance: <commands and expected outcomes>
Return: edit only the scoped files; summarize changed files and test results.
Do not: expand scope, add dependencies, or execute destructive commands.
```

## Phase 5 — Verify integrated behavior

- Run unit tests for touched code first, then the relevant integration tests, then the full suite.
- Test normal input, boundary input, malformed input, and expected failure behavior.
- For automation, use dry-run mode and synthetic fixtures before live side effects.
- Verify network and file-system behavior, secrets handling, authentication, and cleanup.
- Re-run setup from a clean environment or container when reproducibility matters.
- Record versions, commands, model/runtime settings, dataset fixtures, and results.

## Phase 6 — Package and operate

- Provide README setup/run/stop instructions, prerequisites, configuration, and troubleshooting.
- Pin important dependencies and model artifacts; note licenses.
- Record whether each AI workflow is hosted or local, what repository context can be transmitted, and the Copilot AI-credit/spend controls used.
- Keep local data/model directories explicit and exclude secrets from Git.
- If containerizing, avoid unnecessary base images/services; account for image layers and GPU passthrough needs.
- Expose logs and health checks; make resource limits and network access explicit.
- Document whether code/data stay local or leave the machine.

## Fallback and troubleshooting

| Symptom | Likely dimensions | First response |
|---|---|---|
| Very slow first token | Large prompt, cold model load, CPU/GPU offload, storage or memory pressure | Reduce context/input, warm-start once, verify GPU placement, inspect swap and I/O |
| Generation is slow throughout | CPU throughput, thermal throttling, insufficient GPU/VRAM, large model | Reduce model size/quantization burden or output length; benchmark after thermal stabilization |
| OOM or swapping | Model + cache + harness + editor + tests exceed available memory | Stop parallel requests; reduce context/model; close unrelated processes; avoid containers if not required |
| Agent repeats or calls tools incorrectly | Unsupported/weak tool-call behavior, overly broad task, bad API/template/context | Test one tool, shorten task, verify model template and provider settings; fall back to manual harness edits |
| Irrelevant multi-file edits | Context too broad or scope unclear | Restore via Git; narrow files and acceptance criteria; request a plan first |
| Context bundle exposes secrets | Bad globs/ignore rules | Stop, remove bundle, rotate exposed credentials if applicable, add exclusions and inspect next bundle |
| Test repair loop grows | Flaky tests, contradictory instructions, or change too broad | Stop the loop, inspect root cause, revert and split into smaller changes |

## Benchmark and readiness record

For each local workflow, record:

```text
Hardware / OS:
Runtime + version:
Model artifact + quantization + license:
Harness + version:
Context / concurrency:
Task and repository commit:
Cold-start time:
Median TTFT / decode speed (if measured):
Peak system RAM / swap:
Peak GPU VRAM / placement:
Tests / static checks:
Manual repairs / unrelated edits:
Privacy and network checks:
```

Call the workflow **ready for routine use** only after a clean run completes the selected task, local validation passes, changes are reviewable, resource use stays within the measured budget, and no unapproved external data transfer occurred. A one-off successful generation is not a readiness gate.
