"""
collect_logs.py
===============
Script de collecte automatique de TOUS les logs Linux → Upload vers Amazon S3.
À exécuter toutes les 4 heures via cron sur la VM Ubuntu.

Logs collectés :
  - auth.log      → SSH brute-force (Hydra), sudo, connexions
  - apache2       → HTTP requests (Gobuster), port scan
  - syslog        → Messages système généraux
  - kern.log      → Kernel, UFW/iptables (blocages pare-feu), Nmap
  - journald      → Logs systemd de tous les services

Auteur : Projet PFE — Tableau de Bord Prédictif Linux
"""

import os
import boto3
import datetime
import subprocess
import tempfile
import pandas as pd
from dotenv import load_dotenv
from pathlib import Path

# ─── Chargement des variables d'environnement ────────────────────────────────
load_dotenv()

AWS_ACCESS_KEY_ID     = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_REGION            = os.getenv("AWS_REGION", "us-east-1")
S3_BUCKET_NAME        = os.getenv("S3_BUCKET_NAME", "pfe-linux-logs-supervision")

# ─── Configuration ────────────────────────────────────────────────────────────
LOG_FILES = {
    "auth":    "/var/log/auth.log",
    "apache":  "/var/log/apache2/access.log",
    "syslog":  "/var/log/syslog",
    "kern":    "/var/log/kern.log",
}

NOW       = datetime.datetime.now()
TIMESTAMP = NOW.strftime("%Y-%m-%d_%H-%M")
DATE_ONLY = NOW.strftime("%Y-%m-%d")


# ─── Fonctions utilitaires ────────────────────────────────────────────────────

def lire_log(chemin_fichier: str) -> list:
    path = Path(chemin_fichier)
    if not path.exists():
        print(f"  [WARN] Fichier non trouvé : {chemin_fichier}")
        return []
    try:
        with open(path, "r", errors="ignore") as f:
            lignes = f.readlines()
        print(f"  [OK] {chemin_fichier} → {len(lignes)} lignes lues")
        return lignes
    except PermissionError:
        print(f"  [WARN] Permission refusée : {chemin_fichier}")
        return []


def lire_journald() -> list:
    try:
        result = subprocess.run(
            ["journalctl", "--no-pager", "--since", "4 hours ago", "--output", "short"],
            capture_output=True, text=True, timeout=30
        )
        lignes = result.stdout.splitlines(keepends=True)
        print(f"  [OK] journald → {len(lignes)} lignes lues (4 dernières heures)")
        return lignes
    except Exception as e:
        print(f"  [WARN] journald non disponible : {e}")
        return []


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
            s3.put_object(Bucket=S3_BUCKET_NAME, Key=chemin_s3, Body=contenu_local.encode("utf-8"))
        print(f"  [S3] ✅ Uploadé → s3://{S3_BUCKET_NAME}/{chemin_s3}")
    except Exception as e:
        print(f"  [S3] ❌ Erreur upload {chemin_s3} : {e}")


def uploader_lignes_vers_s3(lignes: list, nom: str):
    if not lignes:
        print(f"  [SKIP] {nom} — aucune ligne")
        return
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False)
    tmp.writelines(lignes)
    tmp.close()
    uploader_vers_s3(tmp.name, f"raw/{DATE_ONLY}/{nom}_{TIMESTAMP}.log", est_fichier=True)
    os.unlink(tmp.name)


# ─── Construction du dataset structuré ───────────────────────────────────────

def construire_dataset(lignes_auth, lignes_apache, lignes_syslog, lignes_kern, lignes_journal):
    records = []

    # ── auth.log — SSH / Hydra / sudo ─────────────────────────────────────
    for ligne in lignes_auth:
        ligne = ligne.strip()
        if not ligne:
            continue
        r = {"timestamp": NOW.strftime("%Y-%m-%d %H:%M:%S"), "source_ip": "N/A",
             "type_event": "SSH_OTHER", "severite": "INFO", "statut": "INFO",
             "detail": ligne[:200], "source_log": "auth.log"}
        if "Failed password" in ligne or "Invalid user" in ligne:
            r.update({"type_event": "SSH_BRUTE_FORCE", "statut": "FAILED", "severite": "CRITIQUE"})
            if " from " in ligne:
                r["source_ip"] = ligne.split(" from ")[-1].split(" ")[0].strip()
        elif "Accepted password" in ligne or "session opened" in ligne:
            r.update({"type_event": "SSH_SUCCESS", "statut": "SUCCESS"})
            if " from " in ligne:
                r["source_ip"] = ligne.split(" from ")[-1].split(" ")[0].strip()
        elif "sudo" in ligne.lower():
            r.update({"type_event": "SUDO_USAGE", "severite": "AVERTISSEMENT"})
        records.append(r)

    # ── apache2 — HTTP / Gobuster ──────────────────────────────────────────
    for ligne in lignes_apache:
        ligne = ligne.strip()
        if not ligne:
            continue
        r = {"timestamp": NOW.strftime("%Y-%m-%d %H:%M:%S"), "source_ip": "N/A",
             "type_event": "HTTP_REQUEST", "severite": "INFO", "statut": "N/A",
             "detail": ligne[:200], "source_log": "apache2_access.log"}
        parts = ligne.split('"')
        if len(parts) >= 3:
            r["source_ip"] = parts[0].strip().split(" ")[0]
            apres = parts[2].strip().split(" ")
            if apres:
                r["statut"] = apres[0]
        if "gobuster" in ligne.lower():
            r.update({"type_event": "WEB_ENUMERATION", "severite": "CRITIQUE"})
        elif "nmap" in ligne.lower() or "masscan" in ligne.lower():
            r.update({"type_event": "PORT_SCAN", "severite": "AVERTISSEMENT"})
        elif r["statut"] in ("404", "403", "500"):
            r["severite"] = "AVERTISSEMENT"
        records.append(r)

    # ── syslog — Système général ───────────────────────────────────────────
    for ligne in lignes_syslog:
        ligne = ligne.strip()
        if not ligne:
            continue
        r = {"timestamp": NOW.strftime("%Y-%m-%d %H:%M:%S"), "source_ip": "N/A",
             "type_event": "SYSLOG_EVENT", "severite": "INFO", "statut": "INFO",
             "detail": ligne[:200], "source_log": "syslog"}
        lower = ligne.lower()
        if "error" in lower or " err " in lower:
            r.update({"type_event": "SYSTEM_ERROR", "severite": "CRITIQUE", "statut": "ERROR"})
        elif "warning" in lower or "warn" in lower:
            r.update({"type_event": "SYSTEM_WARNING", "severite": "AVERTISSEMENT", "statut": "WARNING"})
        elif "cron" in lower:
            r["type_event"] = "CRON_JOB"
        elif "started" in lower or "stopped" in lower:
            r["type_event"] = "SERVICE_EVENT"
        records.append(r)

    # ── kern.log — Kernel / UFW / iptables ────────────────────────────────
    for ligne in lignes_kern:
        ligne = ligne.strip()
        if not ligne:
            continue
        r = {"timestamp": NOW.strftime("%Y-%m-%d %H:%M:%S"), "source_ip": "N/A",
             "type_event": "KERNEL_EVENT", "severite": "INFO", "statut": "INFO",
             "detail": ligne[:200], "source_log": "kern.log"}
        lower = ligne.lower()
        if "ufw block" in lower or "[ufw block]" in lower or "ufw deny" in lower:
            r.update({"type_event": "FIREWALL_BLOCK", "severite": "CRITIQUE", "statut": "BLOCKED"})
            if "SRC=" in ligne:
                try:
                    r["source_ip"] = ligne.split("SRC=")[1].split(" ")[0]
                except Exception:
                    pass
        elif "nmap" in lower or "port scan" in lower:
            r.update({"type_event": "PORT_SCAN_KERNEL", "severite": "AVERTISSEMENT"})
        elif "oom" in lower or "out of memory" in lower:
            r.update({"type_event": "MEMORY_CRITICAL", "severite": "CRITIQUE", "statut": "CRITICAL"})
        elif "error" in lower:
            r.update({"type_event": "KERNEL_ERROR", "severite": "CRITIQUE", "statut": "ERROR"})
        records.append(r)

    # ── journald — Services systemd ────────────────────────────────────────
    for ligne in lignes_journal:
        ligne = ligne.strip()
        if not ligne:
            continue
        r = {"timestamp": NOW.strftime("%Y-%m-%d %H:%M:%S"), "source_ip": "N/A",
             "type_event": "JOURNAL_EVENT", "severite": "INFO", "statut": "INFO",
             "detail": ligne[:200], "source_log": "journald"}
        lower = ligne.lower()
        if "failed" in lower or "error" in lower:
            r.update({"type_event": "SERVICE_FAILED", "severite": "CRITIQUE", "statut": "FAILED"})
        elif "started" in lower:
            r["type_event"] = "SERVICE_STARTED"
        elif "stopped" in lower:
            r["type_event"] = "SERVICE_STOPPED"
        elif "ssh" in lower:
            r["type_event"] = "SSH_SERVICE_EVENT"
        records.append(r)

    df = pd.DataFrame(records)
    print(f"  [OK] Dataset total : {len(df)} événements")
    return df


# ─── Pipeline principal ───────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print(f"  COLLECTE COMPLÈTE DES LOGS — {TIMESTAMP}")
    print("=" * 60)

    # ── 1. Lire tous les logs ───────────────────────────────────────────────
    print("\n[1/4] Lecture de tous les fichiers de logs...")
    lignes_auth    = lire_log(LOG_FILES["auth"])
    lignes_apache  = lire_log(LOG_FILES["apache"])
    lignes_syslog  = lire_log(LOG_FILES["syslog"])
    lignes_kern    = lire_log(LOG_FILES["kern"])
    lignes_journal = lire_journald()

    # ── 2. Upload logs bruts sur S3 (Raw Zone) ──────────────────────────────
    print("\n[2/4] Upload des logs bruts vers S3 (Raw Zone)...")
    uploader_lignes_vers_s3(lignes_auth,    "auth")
    uploader_lignes_vers_s3(lignes_apache,  "apache")
    uploader_lignes_vers_s3(lignes_syslog,  "syslog")
    uploader_lignes_vers_s3(lignes_kern,    "kern")
    uploader_lignes_vers_s3(lignes_journal, "journald")

    # ── 3. Construire le dataset structuré ──────────────────────────────────
    print("\n[3/4] Construction du dataset structuré...")
    df = construire_dataset(lignes_auth, lignes_apache, lignes_syslog, lignes_kern, lignes_journal)

    if df.empty:
        print("  [WARN] Aucun événement trouvé.")
        return

    # Résumé
    print(f"\n  Résumé :")
    print(f"     Total événements      : {len(df)}")
    for et in df["type_event"].value_counts().index[:8]:
        print(f"     {et:<30}: {len(df[df['type_event']==et])}")
    ips = df[df["source_ip"] != "N/A"]["source_ip"].value_counts()
    if not ips.empty:
        print(f"     IP la plus active     : {ips.index[0]} ({ips.iloc[0]} requêtes)")
    print(f"     Événements CRITIQUES  : {len(df[df['severite']=='CRITIQUE'])}")

    # ── 4. Upload dataset CSV sur S3 (Processed Zone) ───────────────────────
    print("\n[4/4] Upload des CSV vers S3 (Processed Zone)...")

    tmp_csv = tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False)
    df.to_csv(tmp_csv.name, index=False)
    tmp_csv.close()
    uploader_vers_s3(tmp_csv.name, f"processed/dataset_{TIMESTAMP}.csv", est_fichier=True)
    os.unlink(tmp_csv.name)

    # latest pour CrewAI
    df.to_csv("/tmp/latest_logs.csv", index=False)
    uploader_vers_s3("/tmp/latest_logs.csv", "processed/latest_logs.csv", est_fichier=True)

    # Stats par source
    stats = df.groupby(["source_log", "type_event", "severite"]).size().reset_index(name="count")
    stats.to_csv("/tmp/stats_logs.csv", index=False)
    uploader_vers_s3("/tmp/stats_logs.csv", "processed/stats_logs.csv", est_fichier=True)

    print("\n" + "=" * 60)
    print("  ✅ COLLECTE COMPLÈTE TERMINÉE")
    print("  Logs : auth + apache + syslog + kern + journald → S3")
    print("=" * 60)


if __name__ == "__main__":
    main()