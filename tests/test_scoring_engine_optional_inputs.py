import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scoring_engine import main


class ScoringEngineOptionalInputsTests(unittest.TestCase):
    def _write_json(self, path: Path, data: dict) -> None:
        path.write_text(json.dumps(data), encoding="utf-8")

    def test_main_accepts_missing_cloud_input(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            local_path = tmp_path / "local.json"
            rules_path = tmp_path / "rules.json"
            output_path = tmp_path / "out.json"

            self._write_json(local_path, {
                "risk": {"score": 60, "level": "medium"},
                "decision": {"recommended_action": "warn"},
                "change": {"affected_areas": ["Interface"], "destructive_operations": []},
                "reason": "test"
            })
            self._write_json(rules_path, {
                "rule_score": 40,
                "risk_level": "medium",
                "decision_hint": "warn",
                "findings": [],
                "affected_areas": []
            })

            with patch.object(sys, "argv", [
                "scoring_engine.py",
                "--local",
                str(local_path),
                "--rules",
                str(rules_path),
                "--output",
                str(output_path),
                "--no-notify",
            ]):
                exit_code = main()

            self.assertEqual(exit_code, 0)
            self.assertTrue(output_path.exists())
            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertIn("final_score", payload)

    def test_main_accepts_missing_local_input(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            cloud_path = tmp_path / "cloud.json"
            rules_path = tmp_path / "rules.json"
            output_path = tmp_path / "out.json"

            self._write_json(cloud_path, {
                "risk_score": 70,
                "risk_level": "high",
                "decision_recommendation": "manual_review",
                "risk_reason": "test",
                "changed_areas": ["Routing"],
                "affected_services": []
            })
            self._write_json(rules_path, {
                "rule_score": 40,
                "risk_level": "medium",
                "decision_hint": "warn",
                "findings": [],
                "affected_areas": []
            })

            with patch.object(sys, "argv", [
                "scoring_engine.py",
                "--cloud",
                str(cloud_path),
                "--rules",
                str(rules_path),
                "--output",
                str(output_path),
                "--no-notify",
            ]):
                exit_code = main()

            self.assertEqual(exit_code, 0)
            self.assertTrue(output_path.exists())
            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertIn("final_score", payload)


if __name__ == "__main__":
    unittest.main()
