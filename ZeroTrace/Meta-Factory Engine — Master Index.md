# Meta-Factory Engine — Master Index

> **Objective:** A universal builder workflow for apps, scripts, and automations that can operate offline, online, or in a hybrid mode. **Selected project default:** GitHub Copilot Pro in VS Code with a small, project-local selection of Addy Osmani's agent-skills. Local inference remains an optional fallback. The design targets a 16 GB RAM laptop, but hosted AI usage is subject to account limits, credit consumption, and data-sharing choices.

## Routing table

| Page | Scope | Status |
|---|---|---|
| [CPU Runtimes & Models](models-and-runtimes.md) | Local inference runtimes, model/quantization choices, memory and hardware budgets | Compiled from the supplied notes; numeric budgets and current model tags need local measurement and source verification |
| [Agent Frameworks & Harnesses](agent-frameworks.md) | Coding harnesses and Python agent frameworks | Compiled; lifecycle, compatibility, licenses, and maintenance states must be verified before selection |
| [The Universal Tool Arsenal](github-gems.md) | Reusable open-source utilities for documents, crawling, code context, and media | Compiled; evaluate install footprint, license, OS support, and task fit before adopting |
| [The Universal Build Protocol](build-protocol.md) | Repeatable prompt-to-working-tool process with local verification | Initial workflow compiled; commands are examples and must be adjusted to actual versions and model tags |

## System at a glance

1. **Orient:** read this index, then open only the relevant node(s).
2. **Prepare context:** use local parsers and selective repository bundling; avoid sending a whole repository when a focused file set is enough.
3. **Use the selected harness:** Copilot Pro in VS Code with concise repository instructions and only the needed project-local skills. Track AI-credit usage and treat all edits as untrusted until reviewed and tested.
4. **Use local inference only when needed:** choose Ollama or llama.cpp for offline/privacy-sensitive tasks and verify actual CPU/GPU placement and memory before coding. Frameworks such as smolagents, Agno, or PydanticAI are for building custom agent applications, not editing a repository by themselves.
5. **Build in verified slices:** plan a bounded change, edit a small surface, run tests locally, inspect diffs, and commit only after review.

## Resource assumptions and evidence status

The supplied source proposes a 16 GB laptop budget of approximately 3–4 GB for host OS/IDE, 0.5–1 GB for runtime, ~4.7 GB for a 7B Q4 model file, 1.5–2.5 GB for context/KV cache, 0.3–0.8 GB for a harness, and 0.5–1 GB for temporary context utilities. These are **planning estimates from the supplied notes**, not measured values or guaranteed memory requirements. File size is not the same as model runtime memory. Measure peak RAM, VRAM, swap, context use, and latency on the target device before adopting a model.

The supplied notes mix CPU-only, GPU-offload, and GPU-server claims. The choice of runtime and model depends on the actual operating system, CPU instruction support, NVIDIA/AMD GPU and VRAM if present, model artifact/quantization, context length, and expected concurrency. See [CPU Runtimes & Models](models-and-runtimes.md).

## Source interpretation and known issues

- The index uses the page names `agent-frameworks.md`, `github-gems.md`, and `build-protocol.md`. The supplied attachment calls these `agent-harnesses-and-frameworks.md`, `github-gems-and-utilities.md`, and `execution-playbook.md`. This wiki follows the index as the canonical route and maps the attachment's topics into those pages.
- The attachment contains time-sensitive model names and tool-compatibility claims. Treat model tags, model licenses, context lengths, runtime support, and project maintenance state as **verify-before-use** details.
- Model file size, RAM use, GPU VRAM use, active parameters, context capacity, prompt processing speed, and generated tokens per second are different measurements. Do not interchange them.
- Performance assertions and point latency figures in the attachment are not independently reproduced here. Use a controlled benchmark on the target machine before treating them as guidance.
- Generated shell commands and agent edits are untrusted. Keep Git backups, review diffs, and run code only in the intended project/environment.

## Operating contract

1. Read `index.md` first in subsequent sessions.
2. Read only the relevant linked wiki node(s); do not reload supplied raw notes unless explicitly requested to audit a source claim.
3. Record source statements separately from decisions, estimates, and measured results.
4. Update readiness only when there is reproducible evidence: exact hardware/model/runtime, command/configuration, dataset/task, and results.
5. Keep one primary model and one active coding agent during initial evaluation to avoid memory contention and attribution confusion.
6. Prefer small, independently testable changes and local tests over large autonomous coding loops.

## Readiness snapshot

| Area | Status | Evidence needed to advance |
|---|---|---|
| Knowledge structure | Compiled | Four routed pages created from the supplied material |
| Target hardware | Unverified | Exact OS, CPU, RAM availability, GPU model/VRAM, driver, free disk |
| Runtime selection | Provisional | Reproducible Ollama/llama.cpp comparison on the device |
| Model selection | Provisional | Exact model tag/artifact, license, quantization, quality/speed/memory test |
| Harness selection | Selected, validation pending | Copilot Pro + VS Code + selected Addy skills; verify skill discovery, credit use, context handling, tests and diff review on a small-repo task |
| Utility adoption | Provisional | Per-tool task fit, license, maintenance and dependency review |
| End-to-end protocol | Draft | Clean setup, repeatable build, local validation and rollback evidence |
