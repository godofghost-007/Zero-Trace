---
name: review
description: Review a ZeroTrace diff before merge for correctness, design, security, and performance.
---
Use `code-review-and-quality` and `zerotrace-development-loop`. Read the approved task/spec first, then inspect the full diff and tests. Review correctness, simplicity/readability, architecture, security, performance; for ZeroTrace also verify scan scope, shell invocation, SSRF, secrets/PII, auth/RBAC, audit, failure/degraded behavior, migrations/events and authorization. Report only actionable findings, severity, file/line, consequence and proposed fix. Do not rubber-stamp. Do not merge or claim production safety.