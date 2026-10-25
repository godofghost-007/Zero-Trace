import unittest

from scripts.run_migrations import migration_files, migration_statements


class MigrationTests(unittest.TestCase):
    def test_foundation_migration_is_idempotent(self) -> None:
        statements = migration_statements()
        sql = "\n".join(statements)

        self.assertIn("CREATE TABLE IF NOT EXISTS schema_migrations", sql)
        self.assertIn("CREATE TABLE IF NOT EXISTS event_outbox", sql)
        self.assertIn("CREATE UNIQUE INDEX IF NOT EXISTS", sql)

    def test_migrations_include_event_reliability_contract(self) -> None:
        versions = [path.stem for path in migration_files()]
        sql = "\n".join(migration_statements())

        self.assertEqual(
            versions,
            [
                "0001_foundation",
                "0002_event_reliability",
                "0003_recon",
                "0004_intel",
                "0005_recon_inventory",
                "0006_correlation",
                "0007_live_runtime",
                "0008_identity_hardening",
                "0009_scan_schedules",
            ],
        )
        self.assertIn("processed_events", sql)
        self.assertIn("dead_letter_reason", sql)
        self.assertIn("event_outbox_pending_idx", sql)
        self.assertIn("event_outbox_status_check", sql)

    def test_recon_migration_defines_canonical_state_and_idempotency(self) -> None:
        sql = "\n".join(migration_statements())

        for table in (
            "recon_scopes",
            "recon_runs",
            "recon_assets",
            "recon_services",
            "recon_observations",
            "recon_idempotency",
        ):
            self.assertIn(f"CREATE TABLE IF NOT EXISTS {table}", sql)
        self.assertIn("recon_runs_scope_target_profile", sql)
        self.assertIn("recon_idempotency_key_unique", sql)

    def test_intel_migration_defines_facts_and_findings(self) -> None:
        sql = "\n".join(migration_statements())

        self.assertIn("intel_vulnerability_facts", sql)
        self.assertIn("intel_findings", sql)
        self.assertIn("formula_version", sql)
        self.assertIn("intel_uncertain_matches", sql)

    def test_live_runtime_migration_defines_durable_engine_state(self) -> None:
        sql = "\n".join(migration_statements())

        for table in (
            "live_scopes",
            "live_scans",
            "live_intel_facts",
            "live_intel_meta",
            "live_findings",
            "live_uncertain_matches",
            "live_guard_events",
            "live_readiness_snapshots",
            "live_intel_schedule",
        ):
            self.assertIn(f"CREATE TABLE IF NOT EXISTS {table}", sql)
        self.assertIn("live_scans_state_check", sql)
        self.assertIn("live_intel_schedule_source_check", sql)

    def test_identity_migration_adds_mfa_and_session_metadata(self) -> None:
        sql = "\n".join(migration_statements())

        self.assertIn("password_reset_tokens", sql)
        self.assertIn("oidc_identities", sql)
        self.assertIn("auth_audit_events", sql)
        self.assertIn("mfa_enabled", sql)
        self.assertIn("mfa_verified", sql)
        self.assertIn("auth_method", sql)
