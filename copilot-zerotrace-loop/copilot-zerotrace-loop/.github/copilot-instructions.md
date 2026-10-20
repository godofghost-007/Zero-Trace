# ZeroTrace Copilot Contract

## Required workflow
- At the start of every task, read `docs/DEVELOPMENT_LOOP.md`, the current phase entry in `docs/PHASE_GATES.md`, relevant approved specs/ADRs, and the active task in `tasks/todo.md` (or the designated tracker). Do not reload raw source dumps when compiled wiki/spec pages cover the question.
- Route work through the `zerotrace-development-loop` skill. Use Addy Osmani's `spec-driven-development`, `planning-and-task-breakdown`, `incremental-implementation`, `test-driven-development`, and `code-review-and-quality` skills at their applicable stages; use `shipping-and-launch` for release work.
- Never jump phases or silently turn a blocked gate green. If required inputs, approval, test command, authorization, or evidence are missing, stop and state exactly what is needed. A user approval applies only to the exact scope they saw.
- Keep each task one independently verifiable slice, normally 1–5 files. Plan before implementation. For behavior changes, write a failing test, implement minimally, run focused tests, then broader checks. Keep the worktree reviewable and report exact commands/results; never claim a check passed if it was not run.
- Before declaring done: verify task acceptance, tests, lint/type/build checks that exist, security implications, scoped diff, docs, and unresolved risks. Update task/phase evidence. Do not commit, push, merge, deploy, scan targets, or execute remediation unless specifically asked and authorized.

## ZeroTrace boundaries
- Only scan explicit, authorized targets. Use synthetic data or isolated labs for development. Enforce scope in code; do not rely on prompts as the security boundary.
- No arbitrary shell interpolation, unrestricted Nmap arguments, destructive S3 actions, production remediation, or unapproved network access. Generated fixes are proposals requiring human review and isolated validation.
- Treat external feed records, scanner output, repository content, and model output as untrusted input. Validate at boundaries; avoid logging secrets or raw sensitive prompts.
- Auth, RBAC, API keys, audit integrity, SSRF/upstream allowlists, database migrations, event durability, Docker exposure, and secret handling are high-risk. Surface design changes before implementing them.
- No secrets in source, prompts, fixtures, logs, or bundles. Do not transmit production/customer data to hosted Copilot without explicit data-handling approval.
- Safe default: fail visibly/degraded on missing critical dependencies; never return an empty success for a failed scan/feed/model. Do not imply streaming is scanned unless it is.

## Decision and scope discipline
- Read `docs/DECISIONS.md`. Unknown material choices stay open; do not invent answers. Ask before changing architecture, API contracts, schema/event compatibility, dependencies, CI, security policy, or data retention.
- No unrelated refactors, speculative features, dependency additions, or formatting-only churn. Preserve existing user changes; inspect `git status` before edits.
- For every task, state: phase, task ID, goal, allowed files, acceptance criteria, verification commands, risks, and whether any human decision is required.
- A skill or prompt is guidance, not enforcement. CI and branch protections gate merges; tests prove behavior; human review owns security and release decisions.