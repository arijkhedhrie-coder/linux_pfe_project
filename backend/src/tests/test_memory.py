import os
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = os.path.dirname(os.path.dirname(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from src.agents import memory


class TestMemory(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.original_memory_file = memory.MEMORY_FILE
        memory.MEMORY_FILE = Path(self.tmpdir.name) / "long_term_memory.json"

    def tearDown(self):
        memory.MEMORY_FILE = self.original_memory_file
        self.tmpdir.cleanup()

    def test_sauvegarder_memoire_persists_threshold_history(self):
        snapshots = [
            {
                "pass": 1,
                "issued_by": "default",
                "ssh_high": 38,
                "web_high": 55,
                "ftp_high": 55,
                "threat_level": "NORMAL",
            },
            {
                "pass": 2,
                "issued_by": "orchestrator_agent",
                "ssh_high": 28,
                "web_high": 55,
                "ftp_high": 40,
                "threat_level": "CRITICAL",
            },
        ]

        memory.sauvegarder_memoire({
            "ips_suspectes": ["1.2.3.4"],
            "threshold_snapshots": snapshots,
            "nb_alarmes_pass1": 2,
            "nb_alarmes_final": 3,
            "pass2_ran": True,
            "agent_threat_level": "CRITICAL",
            "date": "20260404_120000",
        })

        stored = memory.charger_memoire()
        context = memory.get_contexte_historique()

        self.assertTrue(memory.MEMORY_FILE.exists())
        self.assertEqual(len(stored["sessions"]), 1)
        self.assertEqual(len(stored["threshold_history"]), 1)
        self.assertIn("1.2.3.4", stored["ips_suspectes"])
        self.assertIn("Threshold records : 1", context)
        self.assertIn("Pass 2 ran: True", context)


if __name__ == "__main__":
    unittest.main()
