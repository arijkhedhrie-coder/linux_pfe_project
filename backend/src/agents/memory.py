# src/agents/memory.py

import json
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
MEMORY_FILE = PROJECT_ROOT / "long_term_memory.json"


def charger_memoire() -> dict:
    if MEMORY_FILE.exists():
        with open(MEMORY_FILE, "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)
            # Compat legacy
            data.setdefault("sessions", [])
            data.setdefault("anomalies_vues", [])
            data.setdefault("ips_suspectes", [])
            data.setdefault("threshold_history", [])
            return data

    return {
        "sessions": [],
        "anomalies_vues": [],
        "ips_suspectes": [],
        "threshold_history": [],  # snapshots des seuils (par session)
    }


def sauvegarder_memoire(data: dict) -> None:
    memoire = charger_memoire()

    memoire.setdefault("threshold_history", [])

    memoire["sessions"].append(
        {
            "date": datetime.now().isoformat(),
            "donnees": data,
        }
    )
    memoire["sessions"] = memoire["sessions"][-50:]

    # Fusionner les IPs suspectes
    if "ips_suspectes" in data:
        for ip in data["ips_suspectes"]:
            if ip not in memoire["ips_suspectes"]:
                memoire["ips_suspectes"].append(ip)

    # Persister les snapshots de seuils (si présents)
    if data.get("threshold_snapshots"):
        entry = {
            "date": datetime.now().isoformat(),
            "session_id": data.get("date", datetime.now().strftime("%Y%m%d_%H%M%S")),
            "snapshots": data["threshold_snapshots"],
            "nb_alarms_pass1": data.get("nb_alarmes_pass1", 0),
            "nb_alarms_final": data.get("nb_alarmes_final", 0),
            "pass2_ran": data.get("pass2_ran", False),
            "threat_level": data.get("agent_threat_level", "NORMAL"),
        }
        memoire["threshold_history"].append(entry)
        memoire["threshold_history"] = memoire["threshold_history"][-100:]

    with open(MEMORY_FILE, "w", encoding="utf-8") as f:
        json.dump(memoire, f, indent=2, ensure_ascii=False)

    print(
        f"[MEMOIRE] Sauvegarde : {len(memoire['sessions'])} sessions | "
        f"{len(memoire['threshold_history'])} threshold records"
    )


def get_contexte_historique() -> str:
    memoire = charger_memoire()
    if not memoire["sessions"]:
        return "Aucun historique disponible."

    derniere = memoire["sessions"][-1]
    history = memoire.get("threshold_history", [])

    # One-liner compact (meilleur pour l'agent / LLM)
    thresh_line = ""
    if history:
        last_th = history[-1]
        snaps = last_th.get("snapshots", [])
        if snaps:
            s = snaps[-1]  # snapshot le plus récent
            thresh_line = (
                f" | last_thresh: SSH≥{s.get('ssh_high')}"
                f" WEB≥{s.get('web_high')}"
                f" FTP≥{s.get('ftp_high')}"
                f" pass2={last_th.get('pass2_ran')}"
                f" alarms={last_th.get('nb_alarms_pass1', 0)}→{last_th.get('nb_alarms_final', 0)}"
                f" tl={last_th.get('threat_level', 'NORMAL')}"
            )

    raw = (
        f"sessions={len(memoire['sessions'])} "
        f"known_ips={memoire['ips_suspectes'][:3]} "
        f"last={derniere.get('date', '')[:16]} "
        f"threshold_records={len(history)}"
        f"{thresh_line}"
    )
    return raw[:300]