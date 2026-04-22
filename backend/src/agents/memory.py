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
            data.setdefault("sessions", [])
            data.setdefault("anomalies_vues", [])
            data.setdefault("ips_suspectes", [])
            data.setdefault("threshold_history", [])
            data.setdefault("backtest_history", [])   # Layer 5 fix
            return data

    return {
        "sessions": [],
        "anomalies_vues": [],
        "ips_suspectes": [],
        "threshold_history": [],
        "backtest_history": [],   # Layer 5 fix
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


# ── A.4: Session-to-session stability check ───────────────────────────────────
def compute_session_stability(n_sessions: int = 3) -> dict:
    """
    A.4 — Compares the last N sessions to decide if the system is behaving
    consistently. Feeds the trust score in Phase B.

    Looks at 3 signals across the last N sessions:
      1. alarm_count      — are we raising a stable number of alarms?
      2. fp_score         — is our false positive rate stable?
      3. anomaly_rate     — is the detection rate stable?

    A signal is "stable" if its coefficient of variation (std/mean) < 0.30.

    Returns:
    {
        "confidence":       "HIGH" | "MEDIUM" | "LOW",
        "stable_signals":   int (0–3),
        "alarm_cv":         float,   # coefficient of variation for alarm counts
        "fp_cv":            float,   # CV for FP rate
        "anomaly_cv":       float,   # CV for anomaly rate
        "sessions_used":    int,
        "trend":            "STABLE" | "INCREASING" | "DECREASING",
        "summary":          str,     # human-readable one-liner
    }
    """
    import statistics

    memoire = charger_memoire()
    sessions = memoire.get("sessions", [])

    empty = {
        "confidence":     "LOW",
        "stable_signals": 0,
        "alarm_cv":       None,
        "fp_cv":          None,
        "anomaly_cv":     None,
        "sessions_used":  0,
        "trend":          "UNKNOWN",
        "summary":        "Not enough sessions to evaluate stability.",
    }

    if len(sessions) < 2:
        return empty

    # Take the last N sessions
    recent = sessions[-n_sessions:]

    alarm_counts:  list[float] = []
    fp_scores:     list[float] = []
    anomaly_rates: list[float] = []

    for s in recent:
        d = s.get("donnees", {})
        # alarm count — try multiple field names
        ac = d.get("nb_alarmes_final", d.get("nb_alarms_final", d.get("alarm_count")))
        if ac is not None:
            try:
                alarm_counts.append(float(ac))
            except (TypeError, ValueError):
                pass
        # fp score
        fp = d.get("fp_score_session", d.get("fp_score"))
        if fp is not None:
            try:
                fp_scores.append(float(fp))
            except (TypeError, ValueError):
                pass
        # anomaly rate
        ar = d.get("anomaly_rate", d.get("taux_anomalies"))
        if ar is not None:
            try:
                anomaly_rates.append(float(ar))
            except (TypeError, ValueError):
                pass

    def _cv(values: list[float]) -> float | None:
        """Coefficient of variation = std / mean. Lower = more stable."""
        if len(values) < 2:
            return None
        mean = statistics.mean(values)
        if mean == 0:
            return 0.0
        return round(statistics.stdev(values) / mean, 4)

    def _is_stable(cv: float | None, threshold: float = 0.30) -> bool:
        return cv is not None and cv < threshold

    alarm_cv  = _cv(alarm_counts)
    fp_cv     = _cv(fp_scores)
    anomaly_cv = _cv(anomaly_rates)

    stable_signals = sum([
        _is_stable(alarm_cv),
        _is_stable(fp_cv),
        _is_stable(anomaly_cv),
    ])

    # Overall confidence
    if stable_signals == 3:
        confidence = "HIGH"
    elif stable_signals >= 1:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    # Trend detection (look at alarm counts over time)
    trend = "STABLE"
    if len(alarm_counts) >= 3:
        if alarm_counts[-1] > alarm_counts[0] * 1.5:
            trend = "INCREASING"
        elif alarm_counts[-1] < alarm_counts[0] * 0.5:
            trend = "DECREASING"

    alarm_cv_str = f"{alarm_cv:.3f}" if alarm_cv is not None else "N/A"

    summary = (
        f"Stability: {confidence} | {stable_signals}/3 signals stable | "
        f"alarm_cv={alarm_cv_str} | "
        f"trend={trend} | sessions={len(recent)}"
    )

    print(f"[A.4] {summary}")

    return {
        "confidence":     confidence,
        "stable_signals": stable_signals,
        "alarm_cv":       alarm_cv,
        "fp_cv":          fp_cv,
        "anomaly_cv":     anomaly_cv,
        "sessions_used":  len(recent),
        "trend":          trend,
        "summary":        summary,
    }


# ── C.10: Threshold rollback ───────────────────────────────────────────────────
def restore_threshold(version_id: str | None = None) -> dict:
    """
    C.10 — Instant rollback to any past threshold state.

    Reads threshold_change_log.json, finds the entry by version_id
    (or the most recent ACCEPTED entry if version_id is None),
    and reapplies its thresholds to src/models/seuils_adaptatifs.json.

    Args:
        version_id: The version_id string from threshold_change_log.json
                    (format: YYYYMMDD_HHMMSS_ffffff). Pass None to restore
                    the last accepted state.

    Returns:
        dict with keys:
            success        bool
            version_id     str
            thresholds_applied  dict  — the thresholds that were written
            message        str
    """
    import json as _json
    from pathlib import Path as _Path

    CHANGE_LOG  = _Path("src/models/threshold_change_log.json")
    SEUILS_FILE = _Path("src/models/seuils_adaptatifs.json")

    result = {
        "success":            False,
        "version_id":         version_id or "latest_accepted",
        "thresholds_applied": {},
        "message":            "",
    }

    if not CHANGE_LOG.exists():
        result["message"] = f"threshold_change_log.json not found at {CHANGE_LOG}"
        print(f"[ROLLBACK] ❌ {result['message']}")
        return result

    try:
        with open(CHANGE_LOG, "r", encoding="utf-8") as f:
            log_entries: list[dict] = _json.load(f)
    except Exception as e:
        result["message"] = f"Failed to read change log: {e}"
        print(f"[ROLLBACK] ❌ {result['message']}")
        return result

    if not log_entries:
        result["message"] = "Change log is empty — nothing to restore."
        print(f"[ROLLBACK] ❌ {result['message']}")
        return result

    # Find the target entry
    target: dict | None = None
    if version_id is not None:
        for entry in reversed(log_entries):
            if entry.get("version_id") == version_id:
                target = entry
                break
        if target is None:
            result["message"] = f"version_id '{version_id}' not found in change log."
            print(f"[ROLLBACK] ❌ {result['message']}")
            return result
    else:
        # Find the most recent ACCEPTED entry
        for entry in reversed(log_entries):
            if entry.get("gate_result", {}).get("accepted") is True:
                target = entry
                break
        if target is None:
            result["message"] = "No accepted threshold change found in log."
            print(f"[ROLLBACK] ❌ {result['message']}")
            return result

    # Extract the thresholds from the proposal
    proposal = target.get("agent_proposal", {})
    thresholds_to_apply: dict[str, float] = {}

    # Map agent_proposal fields → seuils_adaptatifs keys
    # seuils_adaptatifs uses keys like Nombre_Tentatives, Nombre_Erreurs
    # We store the raw agent values for audit and also map what we can
    if proposal.get("ssh_high") is not None:
        thresholds_to_apply["Nombre_Tentatives"] = float(proposal["ssh_high"])
    if proposal.get("web_high") is not None:
        thresholds_to_apply["web_threshold"] = float(proposal["web_high"])
    if proposal.get("ftp_high") is not None:
        thresholds_to_apply["ftp_threshold"] = float(proposal["ftp_high"])
    if proposal.get("kernel_high") is not None:
        thresholds_to_apply["kernel_threshold"] = float(proposal["kernel_high"])

    if not thresholds_to_apply:
        result["message"] = (
            f"Entry {target['version_id']} has no threshold values to restore "
            f"(escalate/suppress only entries cannot be rolled back via this function)."
        )
        print(f"[ROLLBACK] ⚠️  {result['message']}")
        return result

    # Load current seuils, apply overrides, write back
    current_seuils: dict = {}
    if SEUILS_FILE.exists():
        try:
            with open(SEUILS_FILE, "r", encoding="utf-8") as f:
                current_seuils = _json.load(f)
        except Exception:
            current_seuils = {}

    current_seuils.update(thresholds_to_apply)
    current_seuils["_restored_from"]   = target["version_id"]
    current_seuils["_restored_at"]     = datetime.now().isoformat()

    SEUILS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(SEUILS_FILE, "w", encoding="utf-8") as f:
        _json.dump(current_seuils, f, indent=2, ensure_ascii=False)

    result.update({
        "success":            True,
        "version_id":         target["version_id"],
        "thresholds_applied": thresholds_to_apply,
        "message": (
            f"Restored thresholds from version {target['version_id']} "
            f"(originally {'ACCEPTED' if target.get('gate_result', {}).get('accepted') else 'REJECTED'} "
            f"on {target.get('timestamp', '?')[:16]})"
        ),
    })

    print(f"\n[ROLLBACK] ✅ {result['message']}")
    print(f"           Applied: {thresholds_to_apply}")
    return result

# ── Layer 5 fix: backtest history reader ──────────────────────────────────────
def get_backtest_history() -> list[dict]:
    """
    Returns the last 20 backtest results from long_term_memory.json.
    Used by dashboard_api.py to show historical accuracy trend.

    Each entry:
        timestamp, sessions_tested, overall_accuracy, overall_label, summary
    """
    memory = charger_memoire()
    return list(reversed(memory.get("backtest_history", [])))