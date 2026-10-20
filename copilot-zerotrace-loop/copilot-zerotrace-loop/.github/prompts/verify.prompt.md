---
name: verify
description: Verify one ZeroTrace change against its acceptance criteria and phase gate.
---
Use `zerotrace-development-loop` and `test-driven-development`. Do not edit code initially. Compare diff with task/spec, run exact focused tests and applicable broader tests/lint/type/build/security checks. Include exit codes and actual outcomes. Check boundary/failure cases, authorization, secrets, network behavior, migrations/events as relevant. Mark each criterion PASS/FAIL/BLOCKED. Never claim unrun checks passed. If failure is found, report it; fix only if requested or within the already approved task, then rerun.