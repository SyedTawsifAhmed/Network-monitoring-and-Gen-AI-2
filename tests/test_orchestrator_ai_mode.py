import sys
import unittest
from unittest.mock import patch

from orchestrator import parse_args


class OrchestratorAIModeTests(unittest.TestCase):
    def test_parse_args_defaults_to_both(self):
        with patch.object(sys, "argv", ["orchestrator.py"]):
            args = parse_args()

        self.assertEqual(args.ai_mode, "both")

    def test_parse_args_accepts_cloud_only(self):
        with patch.object(sys, "argv", ["orchestrator.py", "--ai-mode", "cloud"]):
            args = parse_args()

        self.assertEqual(args.ai_mode, "cloud")

    def test_parse_args_accepts_local_only(self):
        with patch.object(sys, "argv", ["orchestrator.py", "--ai-mode", "local"]):
            args = parse_args()

        self.assertEqual(args.ai_mode, "local")


if __name__ == "__main__":
    unittest.main()
