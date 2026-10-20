# ZeroTrace Copilot Development Loop Kit

A repo-ready workflow for **GitHub Copilot Pro in VS Code** plus a small selection of [Addy Osmani's agent-skills](https://github.com/addyosmani/agent-skills), adapted to the supplied ZeroTrace 19-phase roadmap.

## Important limitation

No prompt, skill, or `copilot-instructions.md` can guarantee that an AI agent follows every instruction in every turn. This kit makes the path repeatable. Tests, CI, version control, branch protection, and human review provide actual gates. Keep agent approvals enabled; never permit unattended production scanning, deployment, or remediation.

## Install

1. Start from a clean Git branch/commit. The notes name `E:\zerotrace-demo`; confirm the actual repository root before copying.
2. Copy this kit's contents into the repo root, merging rather than overwriting existing `.github` files. Review conflicts first.
3. Install these upstream skills in the project/workspace scope when prompted:

   ```powershell
   npx skills add addyosmani/agent-skills --skill spec-driven-development
   npx skills add addyosmani/agent-skills --skill planning-and-task-breakdown
   npx skills add addyosmani/agent-skills --skill incremental-implementation
   npx skills add addyosmani/agent-skills --skill test-driven-development
   npx skills add addyosmani/agent-skills --skill code-review-and-quality
   npx skills add addyosmani/agent-skills --skill shipping-and-launch
   ```

   Confirm `.github/skills/<skill-name>/SKILL.md` exists for each, plus the bundled `zerotrace-development-loop` skill. The upstream skills provide detailed methods; the bundled skill routes phases and project-specific stop/go conditions.
4. Open the repo in current VS Code and Copilot Chat. Run `/skills`, confirm discovery, then reload if needed.
5. Read `docs/DEVELOPMENT_LOOP.md`. Begin at Phase 0 only. Do not implement a later phase until prior exit evidence is recorded and reviewed.
6. Commit the kit after inspection. Later configure GitHub branch protection to require CI checks and human approval; Markdown alone cannot enforce GitHub settings.

## Files

- `.github/copilot-instructions.md`: concise always-on contract.
- `.github/skills/zerotrace-development-loop/SKILL.md`: project-specific phase router and safety rules.
- `.github/prompts/*.prompt.md`: slash entry points for spec, plan, build, verify, review, resume, release.
- `docs/DEVELOPMENT_LOOP.md`: lifecycle, task loop, evidence and escalation.
- `docs/PHASE_GATES.md`: exit checks for phases 0–18.
- `docs/DECISIONS.md`: architecture decisions to close before dependent code.
- `templates/WORK_ITEM.md`, `templates/PHASE_EXIT.md`: reusable task and signoff records.

## ZeroTrace safety

Use synthetic fixtures or an authorized isolated lab until scan scope is approved. Never execute generated remediation against production automatically. Do not put credentials, customer prompts, private vulnerability details, or production data into Copilot context unless data handling is explicitly reviewed.

## First prompt

```text
Use the zerotrace-development-loop and spec-driven-development skills. We are at Phase 0 only. Inspect the repository and report what exists, what is missing, and conflicts with docs/DEVELOPMENT_LOOP.md. Do not edit application code, install dependencies, run scanners, access external targets, or change GitHub settings. Propose the smallest Phase 0 checklist and wait for my approval.
```