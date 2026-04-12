import os
import sys
import unittest
from datetime import datetime, timedelta

import pandas as pd


# Ensure we can import modules from src/
ROOT = os.path.dirname(os.path.dirname(__file__))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from prediction_engine import run_prediction_engine


def _ts(base: datetime, minutes: int) -> pd.Timestamp:
    return pd.Timestamp(base + timedelta(minutes=minutes))


def _mk_ssh_failure(ts: pd.Timestamp, ip: str, username: str) -> dict:
    # Must satisfy:
    # - SSH_FAILURE_REGEX inside prediction_engine
    # - ml_engine.extract_username regex: user=<username>
    return {
        "timestamp": ts,
        "source_ip": ip,
        "Content": f"sshd: authentication failure; user={username} from {ip}",
        "type_event": "SSH_FAILED",
        "source_log": "auth.log",
    }


def _mk_kernel_panic(ts: pd.Timestamp) -> dict:
    return {
        "timestamp": ts,
        "source_ip": None,
        "Content": "kernel: kernel panic - not syncing: Fatal exception",
        "type_event": "KERNEL_SIGNAL",
        "source_log": "syslog",
    }


def _mk_ftp_retr(ts: pd.Timestamp, ip: str) -> dict:
    return {
        "timestamp": ts,
        "source_ip": ip,
        "Content": f"vsftpd: RETR /var/www/shell.php from {ip}",
        "type_event": "FTP_OTHER",
        "source_log": "ftp.log",
    }


def _mk_ftp_stor(ts: pd.Timestamp, ip: str) -> dict:
    return {
        "timestamp": ts,
        "source_ip": ip,
        "Content": f"vsftpd: STOR /tmp/upload.bin from {ip}",
        "type_event": "FTP_OTHER",
        "source_log": "ftp.log",
    }


class TestPredictionEngine(unittest.TestCase):
    def test_botnet_warmup(self):
        base = datetime(2026, 3, 9, 0, 0, 0)
        rows = []
        # Minutes 0..7 with rising unique IPs, but 1 failure per IP.
        # unique ips: 2,3,4,5,6,7,8,9 (last >= 5)
        for m in range(8):
            n_ips = 2 + m
            for i in range(n_ips):
                ip = f"1.2.3.{i+10}"
                rows.append(_mk_ssh_failure(_ts(base, m), ip, username=f"user{i%3}"))

        df_norm = pd.DataFrame(rows)
        out = run_prediction_engine(df_norm)
        self.assertIn("BOTNET_WARMUP", out["flags"])
        self.assertGreaterEqual(out["prediction_score"], 12)

    def test_spray_phase(self):
        base = datetime(2026, 3, 9, 1, 0, 0)
        rows = []
        # failures per minute low (<= 20), usernames per minute ramps hard on last minute.
        # First minutes have zero failures (so baseline median stays low).
        username_sets = [
            [],  # m=0
            [],  # m=1
            [f"u{i}" for i in range(2)],   # m=2
            [f"u{i}" for i in range(2)],   # m=3
            [f"u{i}" for i in range(2)],   # m=4
            [f"u{i}" for i in range(10)],  # m=5
            [f"u{i}" for i in range(10)],  # m=6
            [f"u{i}" for i in range(10)],  # m=7
        ]
        for m, users in enumerate(username_sets):
            if not users:
                # Add a benign log row so minute buckets exist,
                # but ensure it does NOT match the SSH failure regex.
                rows.append({
                    "timestamp": _ts(base, m),
                    "source_ip": None,
                    "Content": "sshd: session opened for user root",
                    "type_event": "SSH_OTHER",
                    "source_log": "auth.log",
                })
                continue  # no ssh failures this minute
            # 12 total failures per minute (kept low), distributed across the provided usernames.
            # This ensures unique usernames per minute can reach the expected SPRAY threshold.
            n_failures = 12
            for j in range(n_failures):
                ip = f"5.6.7.{m}{j}"
                username = users[j % len(users)]
                rows.append(_mk_ssh_failure(_ts(base, m), ip, username=username))

        df_norm = pd.DataFrame(rows)
        out = run_prediction_engine(df_norm)
        self.assertIn("SPRAY_PHASE", out["flags"])
        self.assertGreaterEqual(out["prediction_score"], 12)

    def test_crash_coming(self):
        base = datetime(2026, 3, 9, 2, 0, 0)
        rows = []
        # kernel error counts rising: 0,1,2,4,7,10 across 6..7 minutes.
        counts = [0, 1, 2, 4, 7, 10, 12, 15]
        for m, n in enumerate(counts):
            for _ in range(n):
                rows.append(_mk_kernel_panic(_ts(base, m)))

        df_norm = pd.DataFrame(rows)
        out = run_prediction_engine(df_norm)
        self.assertIn("CRASH_COMING", out["flags"])
        self.assertGreaterEqual(out["prediction_score"], 12)

    def test_data_exfil_start(self):
        base = datetime(2026, 3, 9, 3, 0, 0)
        rows = []
        ip = "9.9.9.9"
        # ftp events per minute: 2,2,2,2,2,8 (burst ratio high)
        # retr share: last minute mostly RETR
        ftp_counts = [2, 2, 2, 2, 2, 8, 8, 8]
        for m, total in enumerate(ftp_counts):
            if m < 5:
                # Keep balanced but retr dominant enough
                for i in range(total):
                    rows.append(_mk_ftp_retr(_ts(base, m), ip=f"10.0.0.{i+1}"))
            else:
                retr_n = max(2, int(total * 0.75))
                stor_n = total - retr_n
                for i in range(retr_n):
                    rows.append(_mk_ftp_retr(_ts(base, m), ip=f"10.0.1.{i+1}"))
                for i in range(stor_n):
                    rows.append(_mk_ftp_stor(_ts(base, m), ip=f"10.0.2.{i+1}"))

        df_norm = pd.DataFrame(rows)
        out = run_prediction_engine(df_norm)
        self.assertIn("DATA_EXFIL_START", out["flags"])
        self.assertGreaterEqual(out["prediction_score"], 12)


if __name__ == "__main__":
    unittest.main()

