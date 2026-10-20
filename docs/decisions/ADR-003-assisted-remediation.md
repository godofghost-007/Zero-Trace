# ADR-003: Assisted Remediation — Proposals Never Execute Automatically

## Status
Accepted

## Date
2026-10-17

## Context

Phase 10 adds assisted remediation: given a confirmed vulnerability finding,
ZeroTrace can generate a remediation proposal (patch, config change, or
version pin) for an operator to review. The wiki Phase 10 specification is
explicit:

- Generate Bash, Ansible, or Terraform proposals only when appropriate
- Include bounded CVE and environment facts
- Never include secrets in prompts
- Validate output schemas
- Reject disallowed or privilege-escalating operations
- Run syntax and static checks
- Test in isolated disposable fixtures
- Attach provenance, model version, prompt version, and SHA-256 digest
- Require human approval
- Record rollback notes
- Re-scan after approved remediation

The critical security constraint: **ZeroTrace never runs a proposed fix
against any target.** Execution is entirely manual and out of scope for this
module.

## Decision

Create `app/remediation.py` with the following security-enforced design:

1. **RemediationProposal** — frozen dataclass carrying proposal_id, finding_id,
   CVE ID, fix_type (allowlisted: patch/config/version_pin), proposed_fix,
   target_environment, scrubbed environment_facts, prompt_version,
   model_version, SHA-256 digest, created_at, status, human_approval_required,
   approved_by, approved_at, rejection_reason, rollback_notes.

2. **ProposalGenerator** — generates proposals but never executes them. An
   optional `execute_fn` is accepted but never invoked. Scans proposed_fix for
   unsafe patterns (rm -rf, chmod 777, chown, curl | bash, etc.) and rejects
   them at generation time. Scrubs secret-like keys from environment_facts.
   Computes SHA-256 digest over canonical JSON of all proposal content.

3. **ProposalValidator** — validates proposals before queuing. Checks for
   unsafe operations, protected system file references (/etc/shadow, /etc/
   passwd, /etc/sudoers), chmod usage, leaked secrets in environment facts,
   and valid SHA-256 digest.

4. **RemediationQueue** — tracks proposals through PROPOSED → APPROVED /
   REJECTED lifecycle. Approve and reject require `approver_role="admin"`;
   any other role raises `PermissionError`. No execution path exists.

5. **Module-level functions** — `generate_proposal`, `validate_proposal`,
   `queue_proposal`, `approve_proposal`, `reject_proposal` backed by shared
   default instances.

## Alternatives Considered

### Automatic execution on approval
Explicitly prohibited by the wiki Phase 10 checkpoint: "No generated fix
executes automatically against production." Rejected.

### Storing raw environment facts including secrets
Violates the security constraint "Never include secrets in prompts" and the
security-and-hardening rule "Never log sensitive data." Rejected — secrets are
scrubbed before storage.

### Allowing operator role to approve
Would elevate non-admin users to authorize potentially destructive changes.
Rejected — only admin may approve or reject.

### Executing via an execute_fn callback
The generator accepts an `execute_fn` parameter but never calls it. This keeps
the interface open for future human-triggered execution while guaranteeing
ZeroTrace itself never runs fixes. The execution step remains entirely manual
and out of module scope.

## Consequences

- Remediation proposals are generated, validated, and queued but never
  executed by ZeroTrace.
- Privilege escalation patterns (rm -rf, chmod 777, chown, curl | bash, etc.)
  are rejected at both generation and validation time.
- Secrets are scrubbed from environment facts before storage.
- Every proposal carries a SHA-256 digest for integrity verification.
- Human approval by admin is mandatory; no role other than admin can approve
  or reject.
- 19 new tests pass; full suite is 141 tests, all green.
- No new dependencies; no network access; no external targets.