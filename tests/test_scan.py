import tempfile
import unittest
from pathlib import Path

from vulnmind_ai import VulnMindAI


class VulnMindScanTests(unittest.TestCase):
    def test_scan_detects_eval(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            sample = temp_path / "sample.php"
            sample.write_text("<?php\n$user = $_GET['x'];\neval($user);\n", encoding="utf-8")

            agent = VulnMindAI()
            results = agent.run(temp_path)

            self.assertEqual(len(results), 1)
            self.assertEqual(results[0].severity, "HIGH")
            self.assertEqual(results[0].confidence, "HIGH")
            self.assertIn("eval", results[0].vulnerability.lower())


if __name__ == "__main__":
    unittest.main()
