# Agent Frameworks & Harnesses

[← Master index](index.md) · Related: [CPU Runtimes & Models](models-and-runtimes.md) · [Build Protocol](build-protocol.md)

## Two different categories

A **coding harness** operates on a developer's repository: it selects context, reads/writes files, may run commands, and presents edits for review. Examples in the supplied notes are Aider and Cline.

An **agent framework** is a library used by developers to build an agent-powered application or workflow. Examples are smolagents, Agno, and PydanticAI. It does not automatically provide an IDE, secure sandbox, repository understanding, or reliable coding workflow. You must define tools, permissions, state, validation, and user interaction.

A model runtime such as Ollama or llama.cpp is a third layer. It hosts inference; it is not the harness/framework and does not itself make edits to a project.

## Selected primary workflow: GitHub Copilot Pro + VS Code

The current project decision is to use **GitHub Copilot Pro in VS Code** as the primary coding harness, with a small, project-local selection of [Addy Osmani's agent-skills](https://github.com/addyosmani/agent-skills). This is a hosted/hybrid workflow, not local-only inference: code and prompt context may be sent to Copilot's service. Do not include credentials or sensitive production data in prompts.

Keep only task-relevant skills under `.github/skills/<skill-name>/SKILL.md` and concise always-on project rules in `.github/copilot-instructions.md`. Suggested starting skills: spec-driven development, planning and task breakdown, incremental implementation, test-driven development, and code review/quality. Verify the skill pack's current Copilot setup guide before installation. Invoke the actual skill names in Copilot; Addy's short lifecycle commands are Claude Code commands and are not automatically installed as Copilot slash commands.

Treat Copilot edits and any cloud-agent pull request as proposals. Use a dedicated branch, review the diff, run the repository's tests and security checks locally, and merge only after validation. Monitor the plan's AI-credit usage and set an additional-spend budget appropriate to the user's cost limit. Local Ollama/llama.cpp remains an optional fallback for offline or privacy-sensitive work, not a required part of the selected workflow.

## Coding harnesses

| Harness | Interface | Supplied notes' strengths | Trade-offs and checks |
|---|---|---|---|
| **Aider CLI** | Terminal, Git working tree; can be used alongside an editor | Focused multi-file edits, repository map, Git commits/undo, configurable lint/test loop | Requires disciplined file/context selection; terminal-centric; confirm the active model API path, model's edit compatibility, and context behavior. Git commits are not a replacement for code review. |
| **Cline** | VS Code extension | IDE context, multi-step file/terminal tools, user verification checkpoints | Agent loops can be slower and prompt-heavy; keep approvals enabled. Verify current repository maintenance, model compatibility, context controls, and local setup. |
| **Continue.dev** | VS Code/JetBrains and CLI per source notes | Chat, edit, inline completion, context providers | Verify current maintenance status and extension availability before choosing; exact features/provider docs can change. |
| **Roo Code** | VS Code extension per source notes | Multiple modes (architect/code/test/debug) | Verify project status and install availability. Mode names do not prove independent specialist models or better code quality. |
| **OpenHands** | Web UI/headless, sandbox environment | Broad filesystem, terminal, browser and agent workflows | Greater environment/container setup and resource overhead; check local-model compatibility and isolation before use on a laptop. |

These products are not quality-ranked here. The supplied notes do not provide a controlled comparison using identical models, prompts, tasks, hardware and tests. Run the same representative tasks and compare test pass rate, unrelated changes, tool-call failures, rollback rate, completion time and peak memory.

## Lightweight Python frameworks

### smolagents

The source notes describe a minimal framework whose CodeAgent can express actions as generated Python. This can reduce custom tool-call schema work, but it also makes execution security especially important. Do not execute model-generated code with unrestricted host privileges. Run with restricted tools, a disposable environment, narrow filesystem access, bounded time/resources, and human review. Verify current APIs, supported backends, license, and dependency footprint before adopting.

### Agno

The source describes Agno as a lightweight framework with agent, session/state, and structured-output features. Those are framework capabilities, not evidence of a specific RAM requirement or superiority. Choose it if you need an application-level agent and its abstractions fit the desired state and tools. Validate import footprint, dependencies, provider support, and deployment model on your project.

### PydanticAI

The source describes PydanticAI as using Python type hints and Pydantic schemas to validate structured outputs and tool interfaces. This can be useful in automation/API workflows where malformed outputs must fail validation. It does not prove that the model's answer is correct, and schema validation is not a security sandbox. Validate model/provider adapters and current API syntax before use.

### Heavier workflow frameworks

The supplied notes name LangGraph, CrewAI and AutoGen as options for larger stateful or multi-agent processes. The “high memory” classification in the notes is qualitative and not measured. Framework weight alone often matters less than loaded model size, duplicated contexts, worker concurrency, browser/test processes and containers. Start with a simple sequential function/tool loop; add graph or multi-agent orchestration only when a documented requirement needs branching, persistence, concurrency or human review checkpoints.

## Selection guide

- **Primary choice for this project:** GitHub Copilot Pro in VS Code with a small project-local skill set, repository instructions, Git branches, and mandatory test/diff review. Confirm current plan access, AI-credit usage, and data-sharing needs.
- **Edit a repo interactively inside VS Code:** evaluate Cline or another currently maintained IDE harness; require a local model option if offline/no API bill is essential.
- **Make bounded Git-tracked changes with minimal IDE overhead:** evaluate Aider.
- **Generate typed structured results in a Python program:** evaluate PydanticAI.
- **Prototype tool-using Python agents quickly:** evaluate smolagents with strict execution isolation.
- **Build an application with sessions/state and tools:** compare Agno or PydanticAI based on current required interfaces.
- **Use complex branching or persistent workflows:** consider heavier graph orchestration only after the simpler sequence becomes inadequate.

## Evaluation protocol

1. Pin the exact model and inference endpoint, including temperature/context settings.
2. Give each candidate the same small bug fix, two-file feature, and review-only task.
3. Start with a clean Git commit and identical acceptance tests.
4. Measure task completion wall time, test pass/fail, tool misuse, irrelevant diff size, rollback/retry count, peak RAM/VRAM, and tokens if exposed.
5. Read the generated diff; never score only response prose or generation speed.
6. Repeat across at least three runs for any ranking; preserve prompts/configurations and disclose failures.

## Security baseline

- Use a clean Git branch/worktree and back up uncommitted work.
- Approve filesystem edits and shell commands individually during initial testing.
- Never place API keys, credentials, or personal data in prompts or generated context bundles.
- Run generated code with least privilege; sandbox file access and network access.
- Inspect package installation, migrations, destructive shell commands, and network calls before execution.
- Require tests, static checks, and human review before merging or deploying.
- Treat tool output and retrieved web content as untrusted input; do not let it override project instructions.

## Readiness

No harness/framework is selected as canonical yet. Selection depends on the user's actual OS, GPU/VRAM if present, whether the priority is VS Code UI or minimal terminal overhead, and whether the goal is to use an agent or to build one. Record these decisions and test evidence in the relevant project-specific pages rather than assuming names in the source table are current recommendations.
