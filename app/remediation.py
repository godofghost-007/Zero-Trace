"""Phase 10 — Assisted Remediation and Auto-Fix Safety.

Generates safe remediation proposals without autonomous production changes.

Security constraints (enforced, not advisory):

- **No automatic execution.** Proposals are generated and queued; ZeroTrace
  never runs a proposed fix against any target.
- **Model output is untrusted input.** Every proposed fix is parsed,
  validated against a schema, and scanned for unsafe operations before it can
  be queued.
- **No secrets in prompts or proposals.** Environment facts are scrubbed of
  credential-like fields before being stored.
- **Privilege escalation and destructive operations are rejected.** chmod,
  chown, rm -rf, and similar patterns are blocked at validation time.
- **Human approval required.** Every proposal carries `human_approval_required`
  and must be explicitly approved by an admin before it can be reviewed.
- **Provenance and integrity.** Every proposal carries prompt version, model
  version, and a SHA-256 digest of its canonical content.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import hmac
import json
import re
from typing import Callable


class FixType(Enum):
    """Allowlisted remediation fix types."""

    PATCH = "patch"
    CONFIG = "config"
    VERSION_PIN = "version_pin"


class ProposalStatus(Enum):
    """Lifecycle states for a remediation proposal."""

    PROPOSED = "proposed"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTED = "executed"  # only set after human executes externally


# Patterns that indicate privilege escalation or destructive operations.
_UNSAFE_PATTERNS = [
    re.compile(r"\brm\s+-rf\b", re.IGNORECASE),
    re.compile(r"\bchmod\s+777\b", re.IGNORECASE),
    re.compile(r"\bchmod\s+-R\s+777\b", re.IGNORECASE),
    re.compile(r"\bchown\s+", re.IGNORECASE),
    re.compile(r"\bsudo\s+rm\b", re.IGNORECASE),
    re.compile(r"\bmkfs\b", re.IGNORECASE),
    re.compile(r"\bdd\s+if=", re.IGNORECASE),
    re.compile(r">\s*/etc/", re.IGNORECASE),
    re.compile(r"\bcurl\s+.*\|\s*bash\b", re.IGNORECASE),
    re.compile(r"\bwget\s+.*\|\s*sh\b", re.IGNORECASE),
]

# Secret-like keys that must never be stored in environment_facts.
_SECRET_KEYS = {
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "private_key",
    "credentials",
    "pwd",
}

_MAX_PROPOSAL_BYTES = 64 * 1024

# Only admin role may approve or reject remediation proposals.
_APPROVER_ROLES = {"admin"}


def _scrub_secrets(facts: dict[str, object]) -> dict[str, object]:
    """Remove secret-like keys from environment facts."""
    return {
        key: value
        for key, value in facts.items()
        if key.lower() not in _SECRET_KEYS
    }


def _canonical_bytes(
    *,
    finding_id: str,
    cve_id: str,
    fix_type: FixType,
    proposed_fix: str,
    target_environment: str,
    environment_facts: dict[str, object],
    prompt_version: str,
    model_version: str,
    created_at: datetime,
) -> bytes:
    """Canonical byte representation for digest computation."""
    payload = {
        "finding_id": finding_id,
        "cve_id": cve_id,
        "fix_type": fix_type.value,
        "proposed_fix": proposed_fix,
        "target_environment": target_environment,
        "environment_facts": environment_facts,
        "prompt_version": prompt_version,
        "model_version": model_version,
        "created_at": created_at.isoformat(),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _compute_digest(
    *,
    finding_id: str,
    cve_id: str,
    fix_type: FixType,
    proposed_fix: str,
    target_environment: str,
    environment_facts: dict[str, object],
    prompt_version: str,
    model_version: str,
    created_at: datetime,
) -> str:
    return hashlib.sha256(
        _canonical_bytes(
            finding_id=finding_id,
            cve_id=cve_id,
            fix_type=fix_type,
            proposed_fix=proposed_fix,
            target_environment=target_environment,
            environment_facts=environment_facts,
            prompt_version=prompt_version,
            model_version=model_version,
            created_at=created_at,
        )
    ).hexdigest()


def _scan_unsafe(text: str) -> list[str]:
    """Return a list of unsafe-pattern violations found in the fix text."""
    violations: list[str] = []
    for pattern in _UNSAFE_PATTERNS:
        if pattern.search(text):
            violations.append(pattern.pattern)
    return violations


@dataclass(frozen=True)
class RemediationProposal:
    """A reviewed, non-executed remediation proposal."""

    proposal_id: str
    finding_id: str
    cve_id: str
    fix_type: FixType
    proposed_fix: str
    target_environment: str
    environment_facts: dict[str, object]
    prompt_version: str
    model_version: str
    sha256_digest: str
    created_at: datetime
    status: ProposalStatus = ProposalStatus.PROPOSED
    human_approval_required: bool = True
    approved_by: str | None = None
    approved_at: datetime | None = None
    rejection_reason: str | None = None
    rollback_notes: str | None = None

    def __post_init__(self) -> None:
        if not self.proposal_id:
            raise ValueError("proposal ID is required")
        if not self.finding_id:
            raise ValueError("finding ID is required")
        if not self.cve_id:
            raise ValueError("CVE ID is required")
        if not self.proposed_fix or len(self.proposed_fix) > _MAX_PROPOSAL_BYTES:
            raise ValueError("proposed fix is required and must be bounded")
        if not self.target_environment:
            raise ValueError("target environment is required")
        if not self.prompt_version or not self.model_version:
            raise ValueError("prompt and model versions are required")
        if len(self.sha256_digest) != 64:
            raise ValueError("SHA-256 digest must be 64 hex characters")
        try:
            int(self.sha256_digest, 16)
        except ValueError as error:
            raise ValueError("SHA-256 digest must be hexadecimal") from error


@dataclass(frozen=True)
class ProposalGenerator:
    """Generates remediation proposals. Never executes them."""

    execute_fn: Callable[[str], None] | None = None

    def generate(
        self,
        *,
        finding_id: str,
        cve_id: str,
        fix_type: FixType,
        proposed_fix: str,
        target_environment: str,
        environment_facts: dict[str, object],
        prompt_version: str,
        model_version: str,
    ) -> RemediationProposal:
        """Build a proposal and record its SHA-256 digest.

        The ``execute_fn`` (if provided) is never called here; execution is an
        explicit, human-gated step outside this module.
        """
        if not finding_id or not cve_id:
            raise ValueError("finding ID and CVE ID are required")
        if not proposed_fix:
            raise ValueError("proposed fix is required")

        created_at = datetime.now(timezone.utc)
        safe_facts = _scrub_secrets(dict(environment_facts))

        unsafe = _scan_unsafe(proposed_fix)
        if unsafe:
            raise ValueError(
                "proposed fix contains unsafe operations: " + ", ".join(unsafe)
            )

        digest = _compute_digest(
            finding_id=finding_id,
            cve_id=cve_id,
            fix_type=fix_type,
            proposed_fix=proposed_fix,
            target_environment=target_environment,
            environment_facts=safe_facts,
            prompt_version=prompt_version,
            model_version=model_version,
            created_at=created_at,
        )
        return RemediationProposal(
            proposal_id=digest[:16],
            finding_id=finding_id,
            cve_id=cve_id,
            fix_type=fix_type,
            proposed_fix=proposed_fix,
            target_environment=target_environment,
            environment_facts=safe_facts,
            prompt_version=prompt_version,
            model_version=model_version,
            sha256_digest=digest,
            created_at=created_at,
        )


@dataclass(frozen=True)
class ProposalValidator:
    """Validates a proposal before it can be queued."""

    def validate(self, proposal: RemediationProposal) -> list[str]:
        """Return a list of validation errors, empty when the proposal is safe."""
        errors: list[str] = []

        if proposal.status != ProposalStatus.PROPOSED:
            errors.append("proposal must be in PROPOSED state to be validated")

        unsafe = _scan_unsafe(proposal.proposed_fix)
        if unsafe:
            errors.append(
                "proposed fix contains unsafe operations: " + ", ".join(unsafe)
            )

        # Reject fixes that reference system-critical paths outside app scope.
        if re.search(r"/etc/(shadow|passwd|sudoers)", proposal.proposed_fix):
            errors.append("proposed fix references protected system files")

        if re.search(r"\bchmod\b", proposal.proposed_fix, re.IGNORECASE):
            errors.append("proposed fix uses chmod (privilege escalation risk)")

        # Check environment facts for leaked secrets.
        for key in proposal.environment_facts:
            if key.lower() in _SECRET_KEYS:
                errors.append(f"environment fact '{key}' may contain a secret")

        if len(proposal.sha256_digest) != 64:
            errors.append("proposal is missing a valid SHA-256 digest")
        else:
            expected_digest = _compute_digest(
                finding_id=proposal.finding_id,
                cve_id=proposal.cve_id,
                fix_type=proposal.fix_type,
                proposed_fix=proposal.proposed_fix,
                target_environment=proposal.target_environment,
                environment_facts=proposal.environment_facts,
                prompt_version=proposal.prompt_version,
                model_version=proposal.model_version,
                created_at=proposal.created_at,
            )
            if not hmac.compare_digest(expected_digest, proposal.sha256_digest):
                errors.append("proposal digest does not match its content")

        return errors


@dataclass
class RemediationQueue:
    """Tracks proposals through their lifecycle. No automatic execution."""

    def __init__(self) -> None:
        self._proposals: dict[str, RemediationProposal] = {}

    def add(self, proposal: RemediationProposal) -> str:
        if proposal.proposal_id in self._proposals:
            raise ValueError("proposal already queued")
        self._proposals[proposal.proposal_id] = proposal
        return proposal.proposal_id

    def get(self, proposal_id: str) -> RemediationProposal | None:
        return self._proposals.get(proposal_id)

    def approve(self, proposal_id: str, approver: str, approver_role: str) -> None:
        if not approver:
            raise ValueError("approver is required")
        if approver_role not in _APPROVER_ROLES:
            raise PermissionError(
                f"role '{approver_role}' may not approve remediation proposals"
            )
        proposal = self._proposals.get(proposal_id)
        if proposal is None:
            raise ValueError("proposal not found")
        if proposal.status != ProposalStatus.PROPOSED:
            raise ValueError("only PROPOSED proposals can be approved")
        updated = RemediationProposal(
            proposal_id=proposal.proposal_id,
            finding_id=proposal.finding_id,
            cve_id=proposal.cve_id,
            fix_type=proposal.fix_type,
            proposed_fix=proposal.proposed_fix,
            target_environment=proposal.target_environment,
            environment_facts=proposal.environment_facts,
            prompt_version=proposal.prompt_version,
            model_version=proposal.model_version,
            sha256_digest=proposal.sha256_digest,
            created_at=proposal.created_at,
            status=ProposalStatus.APPROVED,
            human_approval_required=False,
            approved_by=approver,
            approved_at=datetime.now(timezone.utc),
        )
        self._proposals[proposal_id] = updated

    def reject(
        self, proposal_id: str, approver: str, approver_role: str, reason: str
    ) -> None:
        if not approver:
            raise ValueError("approver is required")
        if approver_role not in _APPROVER_ROLES:
            raise PermissionError(
                f"role '{approver_role}' may not reject remediation proposals"
            )
        if not reason:
            raise ValueError("rejection reason is required")
        proposal = self._proposals.get(proposal_id)
        if proposal is None:
            raise ValueError("proposal not found")
        if proposal.status != ProposalStatus.PROPOSED:
            raise ValueError("only PROPOSED proposals can be rejected")
        updated = RemediationProposal(
            proposal_id=proposal.proposal_id,
            finding_id=proposal.finding_id,
            cve_id=proposal.cve_id,
            fix_type=proposal.fix_type,
            proposed_fix=proposal.proposed_fix,
            target_environment=proposal.target_environment,
            environment_facts=proposal.environment_facts,
            prompt_version=proposal.prompt_version,
            model_version=proposal.model_version,
            sha256_digest=proposal.sha256_digest,
            created_at=proposal.created_at,
            status=ProposalStatus.REJECTED,
            human_approval_required=False,
            approved_by=None,
            approved_at=None,
            rejection_reason=reason,
        )
        self._proposals[proposal_id] = updated


# Module-level convenience functions backed by a shared default queue.
_default_queue = RemediationQueue()
_default_generator = ProposalGenerator()
_default_validator = ProposalValidator()


def generate_proposal(
    *,
    finding_id: str,
    cve_id: str,
    fix_type: FixType,
    proposed_fix: str,
    target_environment: str,
    environment_facts: dict[str, object],
    prompt_version: str,
    model_version: str,
) -> RemediationProposal:
    return _default_generator.generate(
        finding_id=finding_id,
        cve_id=cve_id,
        fix_type=fix_type,
        proposed_fix=proposed_fix,
        target_environment=target_environment,
        environment_facts=environment_facts,
        prompt_version=prompt_version,
        model_version=model_version,
    )


def validate_proposal(proposal: RemediationProposal) -> list[str]:
    return _default_validator.validate(proposal)


def queue_proposal(proposal: RemediationProposal) -> str:
    errors = _default_validator.validate(proposal)
    if errors:
        raise ValueError("proposal failed validation: " + "; ".join(errors))
    return _default_queue.add(proposal)


def approve_proposal(
    proposal_id: str, approver: str, approver_role: str
) -> None:
    _default_queue.approve(proposal_id, approver, approver_role)


def reject_proposal(
    proposal_id: str, approver: str, approver_role: str, reason: str
) -> None:
    _default_queue.reject(proposal_id, approver, approver_role, reason)