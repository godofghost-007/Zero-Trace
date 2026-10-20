import unittest
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from app.remediation import (
    FixType,
    ProposalStatus,
    RemediationProposal,
    ProposalGenerator,
    ProposalValidator,
    RemediationQueue,
    generate_proposal,
    validate_proposal,
    queue_proposal,
    approve_proposal,
    reject_proposal,
)


class FixTypeTests(unittest.TestCase):
    def test_fix_types_are_allowlisted(self) -> None:
        self.assertEqual(FixType.PATCH.value, "patch")
        self.assertEqual(FixType.CONFIG.value, "config")
        self.assertEqual(FixType.VERSION_PIN.value, "version_pin")

    def test_fix_type_from_string_rejects_unknown(self) -> None:
        with self.assertRaises(ValueError):
            FixType("rm_rf")


class RemediationProposalTests(unittest.TestCase):
    def test_proposal_requires_provenance_and_digest(self) -> None:
        now = datetime(2024, 1, 1, tzinfo=timezone.utc)
        proposal = RemediationProposal(
            proposal_id=str(uuid4()),
            finding_id="finding-1",
            cve_id="CVE-2024-1234",
            fix_type=FixType.PATCH,
            proposed_fix="sudo apt update && sudo apt install -y libssl3",
            target_environment="linux",
            environment_facts={"os": "ubuntu", "package": "libssl3"},
            prompt_version="prompt-v1",
            model_version="model-v1",
            sha256_digest="a" * 64,
            created_at=now,
        )
        self.assertEqual(proposal.status, ProposalStatus.PROPOSED)
        self.assertTrue(proposal.human_approval_required)
        self.assertEqual(len(proposal.sha256_digest), 64)

    def test_proposal_rejects_empty_digest(self) -> None:
        with self.assertRaises(ValueError):
            RemediationProposal(
                proposal_id=str(uuid4()),
                finding_id="finding-1",
                cve_id="CVE-2024-1234",
                fix_type=FixType.PATCH,
                proposed_fix="fix",
                target_environment="linux",
                environment_facts={},
                prompt_version="prompt-v1",
                model_version="model-v1",
                sha256_digest="",
                created_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
            )

    def test_proposal_rejects_invalid_digest_length(self) -> None:
        with self.assertRaises(ValueError):
            RemediationProposal(
                proposal_id=str(uuid4()),
                finding_id="finding-1",
                cve_id="CVE-2024-1234",
                fix_type=FixType.PATCH,
                proposed_fix="fix",
                target_environment="linux",
                environment_facts={},
                prompt_version="prompt-v1",
                model_version="model-v1",
                sha256_digest="short",
                created_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
            )


class ProposalGeneratorTests(unittest.TestCase):
    def test_generate_proposal_never_executes(self) -> None:
        called = []

        def fake_execute(command: str) -> None:
            called.append(command)

        generator = ProposalGenerator(execute_fn=fake_execute)
        proposal = generator.generate(
            finding_id="finding-1",
            cve_id="CVE-2024-1234",
            fix_type=FixType.PATCH,
            proposed_fix="apt install -y openssl",
            target_environment="linux",
            environment_facts={"os": "ubuntu"},
            prompt_version="prompt-v1",
            model_version="model-v1",
        )

        self.assertIsNotNone(proposal)
        self.assertEqual(proposal.status, ProposalStatus.PROPOSED)
        self.assertEqual(called, [])  # no execution

    def test_generate_proposal_attaches_sha256_digest(self) -> None:
        generator = ProposalGenerator()
        proposal = generator.generate(
            finding_id="finding-1",
            cve_id="CVE-2024-1234",
            fix_type=FixType.PATCH,
            proposed_fix="apt install -y openssl",
            target_environment="linux",
            environment_facts={"os": "ubuntu"},
            prompt_version="prompt-v1",
            model_version="model-v1",
        )
        self.assertEqual(len(proposal.sha256_digest), 64)
        self.assertTrue(all(c in "0123456789abcdef" for c in proposal.sha256_digest))

    def test_generate_proposal_excludes_secrets(self) -> None:
        generator = ProposalGenerator()
        proposal = generator.generate(
            finding_id="finding-1",
            cve_id="CVE-2024-1234",
            fix_type=FixType.CONFIG,
            proposed_fix="apt install -y openssl",
            target_environment="linux",
            environment_facts={"os": "ubuntu", "password": "secret123"},
            prompt_version="prompt-v1",
            model_version="model-v1",
        )
        self.assertNotIn("secret123", proposal.proposed_fix)
        self.assertNotIn("password", str(proposal.environment_facts))

    def test_generate_proposal_rejects_privilege_escalation(self) -> None:
        generator = ProposalGenerator()
        with self.assertRaises(ValueError):
            generator.generate(
                finding_id="finding-1",
                cve_id="CVE-2024-1234",
                fix_type=FixType.PATCH,
                target_environment="linux",
                environment_facts={"os": "ubuntu"},
                prompt_version="prompt-v1",
                model_version="model-v1",
                proposed_fix="chmod 777 /etc/passwd",
            )


class ProposalValidatorTests(unittest.TestCase):
    def test_validator_accepts_safe_proposal(self) -> None:
        now = datetime(2024, 1, 1, tzinfo=timezone.utc)
        proposal = RemediationProposal(
            proposal_id=str(uuid4()),
            finding_id="finding-1",
            cve_id="CVE-2024-1234",
            fix_type=FixType.PATCH,
            proposed_fix="apt install -y openssl",
            target_environment="linux",
            environment_facts={"os": "ubuntu"},
            prompt_version="prompt-v1",
            model_version="model-v1",
            sha256_digest="a" * 64,
            created_at=now,
        )
        errors = ProposalValidator().validate(proposal)
        self.assertEqual(errors, [])

    def test_validator_rejects_privilege_escalation(self) -> None:
        now = datetime(2024, 1, 1, tzinfo=timezone.utc)
        proposal = RemediationProposal(
            proposal_id=str(uuid4()),
            finding_id="finding-1",
            cve_id="CVE-2024-1234",
            fix_type=FixType.PATCH,
            proposed_fix="chmod 777 /etc/shadow",
            target_environment="linux",
            environment_facts={"os": "ubuntu"},
            prompt_version="prompt-v1",
            model_version="model-v1",
            sha256_digest="a" * 64,
            created_at=now,
        )
        errors = ProposalValidator().validate(proposal)
        self.assertGreater(len(errors), 0)
        self.assertTrue(any("privilege" in e.lower() for e in errors))

    def test_validator_rejects_destructive_operations(self) -> None:
        now = datetime(2024, 1, 1, tzinfo=timezone.utc)
        proposal = RemediationProposal(
            proposal_id=str(uuid4()),
            finding_id="finding-1",
            cve_id="CVE-2024-1234",
            fix_type=FixType.PATCH,
            proposed_fix="rm -rf /",
            target_environment="linux",
            environment_facts={"os": "ubuntu"},
            prompt_version="prompt-v1",
            model_version="model-v1",
            sha256_digest="a" * 64,
            created_at=now,
        )
        errors = ProposalValidator().validate(proposal)
        self.assertGreater(len(errors), 0)
        self.assertTrue(any("unsafe" in e.lower() for e in errors))


class RemediationQueueTests(unittest.TestCase):
    def test_queue_stores_proposal_in_proposed_state(self) -> None:
        queue = RemediationQueue()
        now = datetime(2024, 1, 1, tzinfo=timezone.utc)
        proposal = RemediationProposal(
            proposal_id=str(uuid4()),
            finding_id="finding-1",
            cve_id="CVE-2024-1234",
            fix_type=FixType.PATCH,
            proposed_fix="apt install -y openssl",
            target_environment="linux",
            environment_facts={"os": "ubuntu"},
            prompt_version="prompt-v1",
            model_version="model-v1",
            sha256_digest="a" * 64,
            created_at=now,
        )
        queue.add(proposal)
        stored = queue.get(proposal.proposal_id)
        self.assertIsNotNone(stored)
        self.assertEqual(stored.status, ProposalStatus.PROPOSED)

    def test_approve_requires_human_action(self) -> None:
        queue = RemediationQueue()
        now = datetime(2024, 1, 1, tzinfo=timezone.utc)
        proposal = RemediationProposal(
            proposal_id=str(uuid4()),
            finding_id="finding-1",
            cve_id="CVE-2024-1234",
            fix_type=FixType.PATCH,
            proposed_fix="apt install -y openssl",
            target_environment="linux",
            environment_facts={"os": "ubuntu"},
            prompt_version="prompt-v1",
            model_version="model-v1",
            sha256_digest="a" * 64,
            created_at=now,
        )
        queue.add(proposal)
        # Approval without admin role should fail
        with self.assertRaises(PermissionError):
            queue.approve(proposal.proposal_id, approver="viewer-1", approver_role="viewer")

    def test_approve_sets_approved_status(self) -> None:
        queue = RemediationQueue()
        now = datetime(2024, 1, 1, tzinfo=timezone.utc)
        proposal = RemediationProposal(
            proposal_id=str(uuid4()),
            finding_id="finding-1",
            cve_id="CVE-2024-1234",
            fix_type=FixType.PATCH,
            proposed_fix="apt install -y openssl",
            target_environment="linux",
            environment_facts={"os": "ubuntu"},
            prompt_version="prompt-v1",
            model_version="model-v1",
            sha256_digest="a" * 64,
            created_at=now,
        )
        queue.add(proposal)
        queue.approve(proposal.proposal_id, approver="admin-1", approver_role="admin")
        stored = queue.get(proposal.proposal_id)
        self.assertEqual(stored.status, ProposalStatus.APPROVED)
        self.assertEqual(stored.approved_by, "admin-1")

    def test_reject_sets_rejected_status(self) -> None:
        queue = RemediationQueue()
        now = datetime(2024, 1, 1, tzinfo=timezone.utc)
        proposal = RemediationProposal(
            proposal_id=str(uuid4()),
            finding_id="finding-1",
            cve_id="CVE-2024-1234",
            fix_type=FixType.PATCH,
            proposed_fix="apt install -y openssl",
            target_environment="linux",
            environment_facts={"os": "ubuntu"},
            prompt_version="prompt-v1",
            model_version="model-v1",
            sha256_digest="a" * 64,
            created_at=now,
        )
        queue.add(proposal)
        queue.reject(
            proposal.proposal_id, approver="admin-1", approver_role="admin", reason="unsafe"
        )
        stored = queue.get(proposal.proposal_id)
        self.assertEqual(stored.status, ProposalStatus.REJECTED)
        self.assertEqual(stored.rejection_reason, "unsafe")


class ModuleFunctionTests(unittest.TestCase):
    def test_generate_proposal_returns_proposal(self) -> None:
        proposal = generate_proposal(
            finding_id="finding-1",
            cve_id="CVE-2024-1234",
            fix_type=FixType.PATCH,
            proposed_fix="apt install -y openssl",
            target_environment="linux",
            environment_facts={"os": "ubuntu"},
            prompt_version="prompt-v1",
            model_version="model-v1",
        )
        self.assertIsNotNone(proposal)
        self.assertEqual(proposal.status, ProposalStatus.PROPOSED)

    def test_validate_proposal_returns_errors(self) -> None:
        now = datetime(2024, 1, 1, tzinfo=timezone.utc)
        proposal = RemediationProposal(
            proposal_id=str(uuid4()),
            finding_id="finding-1",
            cve_id="CVE-2024-1234",
            fix_type=FixType.PATCH,
            proposed_fix="rm -rf /",
            target_environment="linux",
            environment_facts={"os": "ubuntu"},
            prompt_version="prompt-v1",
            model_version="model-v1",
            sha256_digest="a" * 64,
            created_at=now,
        )
        errors = validate_proposal(proposal)
        self.assertGreater(len(errors), 0)

    def test_queue_proposal_stores_and_returns(self) -> None:
        now = datetime(2024, 1, 1, tzinfo=timezone.utc)
        proposal = RemediationProposal(
            proposal_id=str(uuid4()),
            finding_id="finding-1",
            cve_id="CVE-2024-1234",
            fix_type=FixType.PATCH,
            proposed_fix="apt install -y openssl",
            target_environment="linux",
            environment_facts={"os": "ubuntu"},
            prompt_version="prompt-v1",
            model_version="model-v1",
            sha256_digest="a" * 64,
            created_at=now,
        )
        pid = queue_proposal(proposal)
        self.assertEqual(pid, proposal.proposal_id)


if __name__ == "__main__":
    unittest.main()