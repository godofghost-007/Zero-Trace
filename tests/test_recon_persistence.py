import unittest
from unittest.mock import MagicMock
from uuid import uuid4

from app.recon_pg import PostgresReconRepository


class ReconPersistenceTests(unittest.TestCase):
    def test_commit_results_uses_parameterized_queries_and_outbox_in_one_transaction(self) -> None:
        connection = MagicMock()
        connection.__enter__.return_value = connection
        repository = PostgresReconRepository(lambda: connection)

        repository.commit_results(
            run_id=str(uuid4()),
            scope_id="scope-lab",
            state="completed",
            assets=("lab.example.test",),
            services=(("lab.example.test", "tcp", 443, "https"),),
            warnings=(),
        )

        connection.__enter__.assert_called_once()
        connection.commit.assert_called_once()
        executed = [
            call.args[0]
            for call in connection.cursor.return_value.__enter__.return_value.execute.call_args_list
        ]
        self.assertTrue(any("INSERT INTO recon_assets" in statement for statement in executed))
        self.assertTrue(any("INSERT INTO event_outbox" in statement for statement in executed))
        self.assertTrue(all("%s" in statement or "UPDATE" in statement for statement in executed))

    def test_idempotency_key_reuse_with_changed_hash_is_rejected(self) -> None:
        connection = MagicMock()
        cursor = connection.cursor.return_value.__enter__.return_value
        cursor.fetchone.return_value = ("different-hash", "run-existing")
        repository = PostgresReconRepository(lambda: connection)

        with self.assertRaises(ValueError):
            repository.claim_idempotency("request-1", "new-hash")
