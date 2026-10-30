import json
import tempfile
import unittest
from pathlib import Path

from shortlist import assess, load_records


class ShortlistTests(unittest.TestCase):
    def test_github_asset_signals_are_not_confirmed_bugs(self):
        row = {"full_name": "sample/vault", "source_signal_score": 12,
               "asset_bearing_code_candidate": True,
               "fund_handling_surface_types": ["financial-entrypoint", "token-transfer"]}
        result = assess(row, "github")
        self.assertGreater(result["priority_score"], 0)
        self.assertFalse(result["confirmed_vulnerability"])
        self.assertEqual(result["category"], "source_only")

    def test_educational_source_deprioritized(self):
        base = {"full_name": "sample/vault", "source_signal_score": 12,
                "asset_bearing_code_candidate": True,
                "fund_handling_surface_types": ["financial-entrypoint", "token-transfer"]}
        classroom = dict(base, description="Scaffold tutorial challenge")
        self.assertLess(assess(classroom, "github")["priority_score"],
                        assess(base, "github")["priority_score"])

    def test_low_severity_only_scan_not_promoted_to_exploit(self):
        row = {"address": "0x" + "1"*40, "status": "screened",
               "findings": [{"check": "shadowing-local", "impact": "Low"}],
               "source_signal_score": 0}
        result = assess(row, "screened")
        self.assertEqual(result["priority_score"], 10)
        self.assertFalse(result["confirmed_vulnerability"])

    def test_verified_without_code_review_is_not_a_confirmed_bug(self):
        result = assess({"address": "0x" + "a"*40}, "verified")
        self.assertEqual(result["category"], "verified_onchain")
        self.assertFalse(result["confirmed_vulnerability"])

    def test_rejects_notebook_transcript_as_json(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "report.json"
            path.write_text("!python frontier.py github\n[]", encoding="utf-8")
            with self.assertRaises(json.JSONDecodeError):
                load_records(path)


if __name__ == "__main__":
    unittest.main()
