import unittest
from pathlib import Path


class Phase0BaselineTests(unittest.TestCase):
    def test_required_baseline_files_exist(self) -> None:
        root = Path(__file__).resolve().parents[1]
        required_files = (
            "README.md",
            ".gitignore",
            ".gitattributes",
            "AGENTS.md",
            "CONSTRAINTS.md",
            "MEASURED.md",
            ".env.example",
            "pyproject.toml",
            "compose.yaml",
            "tasks/plan.md",
            "tasks/todo.md",
            "docs/README.md",
        )

        missing = [path for path in required_files if not (root / path).is_file()]

        self.assertEqual(missing, [])
