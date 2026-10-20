# ZeroTrace Development Loop

## Purpose and guarantee boundary

This is the required project workflow for Copilot-assisted changes. **“Without any break” cannot be guaranteed by an LLM instruction.** A model may miss a rule, misunderstand context, or report an unrun check as complete. Prevent unsafe merges with automated tests/checks and protected branches. Keep a human responsible for approvals and high-risk decisions.

## Repository state to maintain

- `docs/`: approved project specifications and architecture decisions; link each task to these.
- `tasks/plan.md`: approved plan for the current initiative; never replace an unfinished unrelated plan.
- `tasks/todo.md`: ordered tasks, acceptance checks, verification, and status. Use one tracker only.
- `tasks/evidence/phase-NN.md`: completed phase exit evidence using `templates/PHASE_EXIT.md`.
- `.github/copilot-instructions.md` and `.github/skills/`: standing rules and scoped capabilities.

Use the actual repository's existing conventions if these paths already have authoritative alternatives; record the mapping once.

## One task, one loop

### 0. Orient and protect state

Read repository instructions, this loop, relevant phase gate, approved spec/ADR, active task, and relevant source/tests. Run `git status --short`; preserve pre-existing changes. Do not explore/load unrelated files or raw dumps unnecessarily.

### 1. Declare the task contract

Before edits, write a brief in the chat/task record:

```text
Phase / task ID:
Goal (one behavior/outcome):
Allowed files:
Out of scope:
Acceptance criteria (observable):
Verification commands (existing repo commands):
Risk class: low / medium / high
Human decisions or permissions required:
```

Task should normally affect 1–5 files and one subsystem. Split larger tasks. If it changes architecture/API/schema/events/security/CI/dependencies/data retention, pause for a decision before implementation.

### 2. Spec gate (when needed)

For new capabilities, ambiguous requirements, multi-file behavior, or architectural choices: use `/spec` or `/spec-driven-development`. Clarify assumptions, actors, flow, errors, data handling, security, limits, acceptance criteria, and non-goals. Save the spec, list open questions, and stop for explicit human approval. No code in the same turn as first spec approval request.

### 3. Plan gate

After spec approval, use `/plan` or `/planning-and-task-breakdown`. Read-only inspect existing patterns, map dependencies, identify risks, split into vertical verifiable tasks, specify commands and human checkpoints. Save/refresh plan and task list without overwriting unrelated unchecked work. Stop for human approval.

### 4. Implement one approved task

Use `/build` or the `incremental-implementation` skill plus `test-driven-development`:

1. Recheck task and clean/understood diff state.
2. Write a focused failing test first for behavior (RED); show it fails for the expected reason.
3. Implement the smallest code change (GREEN); avoid unrelated refactors and dependencies.
4. Run focused tests. Refactor only if useful and in scope; rerun affected tests.
5. Run relevant lint/type/build checks. For DB/event/security work, run targeted integration/negative tests.
6. Inspect the full diff and ensure no secrets, unrelated files, dangerous commands, unbounded behavior, or silent success-shaped failures.
7. Update task state with exact evidence. Commit only when asked/authorized; otherwise leave changes for review.

If a test/check fails, do not proceed to another task. Diagnose from the actual failure, make a minimal fix, and rerun. If environment/dependency/service is unavailable, mark BLOCKED, state what is missing, and do not report passing.

### 5. Verify and review gate

Use `/verify`, then `/review` or `code-review-and-quality`. Verify acceptance and tests; review correctness, simplicity, architecture, security, performance, data handling, and dependency/license effects. Classify findings as blocker/required/optional. Address blockers and rerun relevant checks. Summarize changed files, exact commands and outcomes, known gaps, and risk.

### 6. Human review and integration

Human reviews the whole diff and evidence. Merge only when required CI checks pass and branch protection review is satisfied. Copilot cloud-agent output is an ordinary proposal, not trusted code. Never let Copilot silently merge or deploy.

### 7. Phase exit gate

When all tasks for a roadmap phase are complete, use `/phase-exit`. Fill the phase record with evidence for each criterion. Mark each criterion PASS, FAIL, or BLOCKED. A human reviews/signs the gate. Never begin dependent phase work while a gate is unresolved; independent documentation may proceed only if explicitly marked non-blocking.

## Escalation: stop and ask

Pause before any action that materially changes user intent, production access, scan scope, data exposure, authentication/security policy, database compatibility, event durability, spend, public publishing, deployment, or deletion. Also pause when acceptance criteria conflict, authorization is unclear, test evidence is missing, an old plan has unchecked unrelated tasks, or repository changes cannot be safely preserved.

## Evidence standard

Evidence means recorded command plus actual exit status/output, test name/count, environment, and commit/diff reference where relevant. “Looks good,” model narrative, generated screenshots without context, and a test command not run are not evidence. Update `docs/PHASE_GATES.md` only from the matching phase evidence record.

## Daily start and end

**Start:** read index/routing and current task; inspect Git status; identify last verified checkpoint. **End:** run checks after the last edit; update task/evidence; summarize what changed, checks run, blockers, and next single task. Do not leave a claim of completion unsupported by a reproducible check.
