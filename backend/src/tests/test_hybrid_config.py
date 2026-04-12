import os
import sys
import unittest


ROOT = os.path.dirname(os.path.dirname(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from src.hybrid_config import DynamicConfig


class TestDynamicConfig(unittest.TestCase):
    def test_from_json_accepts_code_fences_and_coerces_types(self):
        payload = """```json
        {
          "ssh_high_risk_threshold": "28",
          "web_high_risk_threshold": null,
          "escalate_ips": ["1.2.3.4"],
          "rerun_engines": ["session"],
          "reasoning": "Lower SSH threshold due to spike.",
          "confidence": "0.9",
          "ignored_field": "should disappear"
        }
        ```"""

        cfg = DynamicConfig.from_json(payload)

        self.assertEqual(cfg.ssh_high_risk_threshold, 28.0)
        self.assertEqual(cfg.escalate_ips, ["1.2.3.4"])
        self.assertEqual(cfg.rerun_engines, ["session"])
        self.assertEqual(cfg.confidence, 0.9)
        self.assertFalse(hasattr(cfg, "ignored_field"))

    def test_plain_text_fallback_extracts_signal(self):
        text = (
            "Threat looks CRITICAL. Lower ssh threshold to 28 and rerun session. "
            "Escalate 8.8.8.8 because it is near block."
        )

        cfg = DynamicConfig.from_json(text)

        self.assertEqual(cfg.threat_level, "CRITICAL")
        self.assertEqual(cfg.ssh_high_risk_threshold, 28.0)
        self.assertIn("8.8.8.8", cfg.escalate_ips)
        self.assertIn("session", cfg.rerun_engines)
        self.assertEqual(cfg.issued_by, "orchestrator_agent_plaintext")

    def test_default_config_is_no_op(self):
        cfg = DynamicConfig.default()

        self.assertTrue(cfg.is_default())
        self.assertEqual(cfg.summary(), "no overrides (default pass)")


if __name__ == "__main__":
    unittest.main()
