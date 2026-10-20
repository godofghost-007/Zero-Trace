---
name: build
description: Implement only the next approved ZeroTrace task, test-first and in scope.
---
Use `zerotrace-development-loop`, `incremental-implementation`, and `test-driven-development`. Read approved plan/task and relevant files; check Git status. If task is not approved, exceeds scope, or depends on an open decision, stop. State phase, task ID, allowed files, acceptance and commands. Implement only this task. For behavior changes show RED then GREEN; run focused checks after each slice. Do not commit/push/merge/deploy. Update task status only with actual evidence; report exact changed files, commands/results, risks and next task.