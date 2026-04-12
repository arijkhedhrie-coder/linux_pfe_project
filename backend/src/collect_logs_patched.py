"""
collect_logs.py  — PATCHED v2
══════════════════════════════════════════════════════════════════
Script de collecte automatique des logs Linux → Upload vers Amazon S3.
À exécuter toutes les 4 heures via cron sur la VM Ubuntu.

PATCH APPLIQUÉ:
  - [FIX] timestamp par ligne = timestamp RÉEL extrait du contenu
    du log, pas l'heure de lancement du script.
    Avant : timestamp = NOW (identique pour toutes les lignes → inutile)
    Après : timestamp = heure réelle de l'événement dans le log
══════════════════════════════════════════════════════════════════
"""

import os
import re
import boto3
import datetime
import tempfile
import pandas as pd
from dotenv import load_dotenv
from pathlib import Path

load_dotenv()

AWS_ACCESS_KEY_ID     = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_REGION            = os.getenv("AWS_REGION", "us-east-1")
S3_BUCKET_NAME        = os.getenv("S3_BUCKET_NAME", "pfe-linux-logs-supervision")

LOG_FILES = {
    "auth":   "/var/log/auth.log",
    "apache": "/var/log/apache2/access.log",
    "syslog": "/var/log/syslog",
}

# First existing path is used (optional — skip if missing)
FTP_LOG_CANDIDATES = [
    "/var/log/vsftpd.log",
    "/var/log/proftpd/proftpd.log",
    "/var/log/pure-ftpd/pure-ftpd.log",
]

NOW       = datetime.datetime.now()
TIMESTAMP = NOW.strftime("%Y-%m-%d_%H-%M")
DATE_ONLY = NOW.strftime("%Y-%m-%d")


# ── Timestamp extraction helpers ──────────────────────────────────────────────

def _extract_ts_from_auth_line(line: str) -> str:
    """
    Extracts real timestamp from auth.log lines.
    Format: 2026-03-09T06:54:46.042517+00:00 ubuntu-server-lab sshd[...]: ...
    Falls back to legacy syslog format: Mar  9 06:54:46
    """
    # ISO8601 (journald format — Ubuntu 20.04+)
    m = re.search(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})', line)
    if m:
        return m.group(1)

    # Legacy syslog format: "Mar  9 06:54:46"
    m = re.search(r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', line)
    if m:
        try:
            ts = datetime.datetime.strptime(
                f"{m.group(1)} {NOW.year}", '%b %d %H:%M:%S %Y'
            )
            return ts.strftime('%Y-%m-%d %H:%M:%S')
        except ValueError:
            pass

    # Fallback: use script launch time (better than wrong time, still usable)
    return NOW.strftime("%Y-%m-%d %H:%M:%S")


def _extract_ts_from_apache_line(line: str) -> str:
    """
    Extracts real timestamp from Apache access.log lines.
    Format: 192.168.56.103 - - [09/Mar/2026:07:13:57 +0000] "GET ..."
    """
    m = re.search(r'\[(\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2})', line)
    if m:
        try:
            ts = datetime.datetime.strptime(m.group(1), '%d/%b/%Y:%H:%M:%S')
            return ts.strftime('%Y-%m-%d %H:%M:%S')
        except ValueError:
            pass
    return NOW.strftime("%Y-%m-%d %H:%M:%S")


def _extract_ts_from_syslog_line(line: str) -> str:
    """ISO8601, else legacy 'Mar  9 06:54:46' prefix (same as auth)."""
    m = re.search(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})', line)
    if m:
        return m.group(1)
    m = re.search(r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', line)
    if m:
        try:
            ts = datetime.datetime.strptime(
                f"{m.group(1)} {NOW.year}", '%b %d %H:%M:%S %Y'
            )
            return ts.strftime('%Y-%m-%d %H:%M:%S')
        except ValueError:
            pass
    return NOW.strftime("%Y-%m-%d %H:%M:%S")


_KERNEL_SNIP = re.compile(
    r'kernel:|Out of memory|oom-killer|Killed process|I/O error|EXT4-fs error|'
    r'kernel panic|segfault|Call Trace',
    re.I,
)


# ── File reader ───────────────────────────────────────────────────────────────

def lire_log(chemin_fichier: str) -> list:
    path = Path(chemin_fichier)
    if not path.exists():
        print(f"  [WARN] Fichier non trouvé : {chemin_fichier}")
        return []
    with open(path, "r", errors="ignore") as f:
        lignes = f.readlines()
    print(f"  [OK] {chemin_fichier} → {len(lignes)} lignes lues")
    return lignes


# ── Dataset builder (PATCHED) ─────────────────────────────────────────────────

def _first_existing_ftp_log():
    for p in FTP_LOG_CANDIDATES:
        if Path(p).exists():
            return p
    return None


def construire_dataset(
    lignes_auth: list,
    lignes_apache: list,
    lignes_ftp=None,
    lignes_syslog=None,
) -> pd.DataFrame:
    """
    Construit un dataset structuré depuis les logs bruts.

    FIX: chaque ligne reçoit son propre timestamp extrait du contenu
    du log — plus jamais le même timestamp pour toutes les lignes.
    """
    records = []

    # ── auth.log ──────────────────────────────────────────────────────────────
    for ligne in lignes_auth:
        ligne = ligne.strip()
        if not ligne:
            continue

        # ✅ FIX: extract REAL timestamp from this specific line
        real_ts = _extract_ts_from_auth_line(ligne)

        record = {
            "timestamp":  real_ts,          # ← was: NOW.strftime(...)
            "source_ip":  None,
            "type_event": "SSH_OTHER",
            "statut":     "INFO",
            "detail":     ligne[:300],
            "source_log": "auth.log",
        }

        if "Failed password" in ligne or "Invalid user" in ligne:
            record["type_event"] = "SSH_BRUTE_FORCE"
            record["statut"]     = "FAILED"
            m = re.search(r'from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', ligne)
            if m:
                record["source_ip"] = m.group(1)

        elif "Accepted password" in ligne or "Accepted publickey" in ligne:
            record["type_event"] = "SSH_SUCCESS"
            record["statut"]     = "SUCCESS"
            m = re.search(r'from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', ligne)
            if m:
                record["source_ip"] = m.group(1)

        elif "session opened" in ligne:
            record["type_event"] = "SSH_SUCCESS"
            record["statut"]     = "SUCCESS"

        records.append(record)

    # ── apache2/access.log ────────────────────────────────────────────────────
    for ligne in lignes_apache:
        ligne = ligne.strip()
        if not ligne:
            continue

        # ✅ FIX: extract REAL timestamp from this specific line
        real_ts = _extract_ts_from_apache_line(ligne)

        record = {
            "timestamp":  real_ts,          # ← was: NOW.strftime(...)
            "source_ip":  None,
            "type_event": "HTTP_REQUEST",
            "statut":     "N/A",
            "detail":     ligne[:300],
            "source_log": "apache2_access.log",
        }

        # Apache CLF: IP - - [date] "method path proto" status size
        parts = ligne.split('"')
        if len(parts) >= 3:
            ip_part = parts[0].strip().split(" ")[0]
            record["source_ip"] = ip_part

            after = parts[2].strip().split(" ")
            if after:
                record["statut"] = after[0]

            if "gobuster" in ligne.lower() or "dirb" in ligne.lower() or "nikto" in ligne.lower():
                record["type_event"] = "WEB_ENUMERATION"
            elif "nmap" in ligne.lower() or "masscan" in ligne.lower():
                record["type_event"] = "PORT_SCAN"

        records.append(record)

    # ── FTP (vsftpd / proftpd / pure-ftpd) ────────────────────────────────────
    if lignes_ftp:
        for ligne in lignes_ftp:
            ligne = ligne.strip()
            if not ligne:
                continue
            real_ts = _extract_ts_from_syslog_line(ligne)
            low = ligne.lower()
            te = "FTP_OTHER"
            st = "INFO"
            if any(x in low for x in ("530 ", "login incorrect", "authentication failed", "fail")):
                te, st = "FTP_AUTH_FAIL", "FAILED"
            elif any(x in low for x in ("230 ", "logged in", "login ok", "is now logged in")):
                te, st = "FTP_AUTH_OK", "SUCCESS"
            ip = None
            m = re.search(
                r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
                ligne,
            )
            if m:
                ip = m.group(1)
            records.append({
                "timestamp": real_ts,
                "source_ip": ip,
                "type_event": te,
                "statut": st,
                "detail": ligne[:300],
                "source_log": "ftp.log",
            })

    # ── Kernel / critical syslog lines (filtered — keeps CSV small) ───────────
    if lignes_syslog:
        n_kernel = 0
        for ligne in lignes_syslog:
            if n_kernel >= 800:
                break
            ligne = ligne.strip()
            if not ligne or not _KERNEL_SNIP.search(ligne):
                continue
            n_kernel += 1
            records.append({
                "timestamp": _extract_ts_from_syslog_line(ligne),
                "source_ip": None,
                "type_event": "KERNEL_SIGNAL",
                "statut": "CRITICAL" if re.search(r'panic|oom|I/O error', ligne, re.I) else "WARN",
                "detail": ligne[:400],
                "source_log": "syslog",
            })

    df = pd.DataFrame(records)
    print(f"  [OK] Dataset construit : {len(df)} événements")

    # Quick summary
    print(f"       Timestamps uniques : {df['timestamp'].nunique()} "
          f"(attendu: proche de {len(df)}, pas 1!)")

    return df


# ── S3 uploader ───────────────────────────────────────────────────────────────

def uploader_vers_s3(contenu_local: str, chemin_s3: str, est_fichier: bool = True):
    s3 = boto3.client(
        "s3",
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name=AWS_REGION,
    )
    try:
        if est_fichier:
            s3.upload_file(contenu_local, S3_BUCKET_NAME, chemin_s3)
        else:
            s3.put_object(Bucket=S3_BUCKET_NAME, Key=chemin_s3,
                          Body=contenu_local.encode("utf-8"))
        print(f"  [S3] ✅ Uploadé → s3://{S3_BUCKET_NAME}/{chemin_s3}")
    except Exception as e:
        print(f"  [S3] ❌ Erreur upload {chemin_s3} : {e}")


# ── Main pipeline ─────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print(f"  COLLECTE DES LOGS — {TIMESTAMP}")
    print("=" * 60)

    print("\n[1/4] Lecture des fichiers de logs...")
    lignes_auth   = lire_log(LOG_FILES["auth"])
    lignes_apache = lire_log(LOG_FILES["apache"])
    lignes_syslog = lire_log(LOG_FILES["syslog"])
    ftp_path = _first_existing_ftp_log()
    lignes_ftp = lire_log(ftp_path) if ftp_path else []
    if ftp_path:
        print(f"  [OK] FTP log utilisé : {ftp_path}")

    print("\n[2/4] Upload des logs bruts vers S3 (Raw Zone)...")
    for nom, lignes in [("auth", lignes_auth), ("apache", lignes_apache), ("syslog", lignes_syslog)]:
        if not lignes:
            continue
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False)
        tmp.writelines(lignes)
        tmp.close()
        uploader_vers_s3(tmp.name, f"raw/{DATE_ONLY}/{nom}_{TIMESTAMP}.log", est_fichier=True)
        os.unlink(tmp.name)

    print("\n[3/4] Construction du dataset structuré...")
    df = construire_dataset(lignes_auth, lignes_apache, lignes_ftp, lignes_syslog)

    if df.empty:
        print("  [WARN] Aucun événement trouvé.")
        return

    print(f"\n  📊 Résumé :")
    print(f"     Total événements   : {len(df)}")
    print(f"     SSH brute-force    : {len(df[df['type_event']=='SSH_BRUTE_FORCE'])}")
    print(f"     Web enumeration    : {len(df[df['type_event']=='WEB_ENUMERATION'])}")
    ips = df[df["source_ip"].notna()]["source_ip"].value_counts()
    if not ips.empty:
        print(f"     IP la plus active  : {ips.index[0]} ({ips.iloc[0]} requêtes)")

    print("\n[4/4] Upload dataset CSV vers S3 (Processed Zone)...")
    tmp_csv = tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False)
    df.to_csv(tmp_csv.name, index=False)
    tmp_csv.close()
    uploader_vers_s3(tmp_csv.name, f"processed/dataset_{TIMESTAMP}.csv", est_fichier=True)
    os.unlink(tmp_csv.name)

    df.to_csv("/tmp/latest_logs.csv", index=False)
    uploader_vers_s3("/tmp/latest_logs.csv", "processed/latest_logs.csv", est_fichier=True)

    print("\n" + "=" * 60)
    print("  ✅ COLLECTE TERMINÉE — timestamps réels extraits")
    print("=" * 60)


if __name__ == "__main__":
    main()
