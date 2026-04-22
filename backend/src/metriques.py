# metriques.py — FINAL (binôme complet + wrapper compat)

from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd

# ── Constants ────────────────────────────────────────────────────────────────
HEALTH_KERNEL_WEIGHT = 0.40   # Kernel errors are the most critical
HEALTH_SSH_WEIGHT = 0.30
HEALTH_WEB_WEIGHT = 0.15
HEALTH_FTP_WEIGHT = 0.15

VELOCITY_SPIKE_THRESHOLD = 2.5   # ratio last-window / baseline → alert
ENTROPY_LOW_THRESHOLD = 1.0      # bits — low entropy = single-source attack
ENTROPY_HIGH_THRESHOLD = 3.0     # bits — high entropy = distributed botnet


# ── Wrapper compat (POINT FORT: ton API historique) ──────────────────────────
def calculer_metriques(df_clean: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Compat avec ton ancien code: retourne 3 DataFrames.
    En interne, utilise la version avancée (binôme) et garantit les colonnes legacy.
    """
    erreurs_par_heure, tentatives_par_ip, events_par_service = calculer_metriques_avancees(df_clean)

    # Garanties legacy (au cas où df_clean est vide ou colonnes manquantes)
    if not erreurs_par_heure.empty and "Nombre_Erreurs" not in erreurs_par_heure.columns:
        # sécurité: si un jour la fonction change, on reconstruit le minimum
        erreurs_par_heure = erreurs_par_heure.rename(columns={"count": "Nombre_Erreurs"})

    if tentatives_par_ip.empty:
        tentatives_par_ip = pd.DataFrame(columns=["IP_Source", "Nombre_Tentatives"])
    elif "Nombre_Tentatives" not in tentatives_par_ip.columns:
        # binôme fournit déjà Nombre_Tentatives via Total_Events, mais on sécurise
        tentatives_par_ip["Nombre_Tentatives"] = tentatives_par_ip.get("Total_Events", 0)

    if events_par_service.empty:
        events_par_service = pd.DataFrame(columns=["Service", "Nombre_Events"])
    elif "Nombre_Events" not in events_par_service.columns:
        events_par_service = events_par_service.rename(columns={"count": "Nombre_Events"})

    return erreurs_par_heure, tentatives_par_ip, events_par_service


# ── Version avancée (BINÔME) ─────────────────────────────────────────────────
def calculer_metriques_avancees(df_clean: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Version avancée: identique à l’esprit du binôme.
    Retourne 3 DataFrames enrichis.
    """
    if df_clean is None or df_clean.empty:
        return pd.DataFrame(), pd.DataFrame(), pd.DataFrame()

    df_clean = df_clean.copy()
    df_clean["Date"] = pd.to_datetime(df_clean.get("Date"), errors="coerce")
    df_clean = df_clean.dropna(subset=["Date"])
    if df_clean.empty:
        return pd.DataFrame(), pd.DataFrame(), pd.DataFrame()

    df_clean["Heure"] = df_clean["Date"].dt.floor("h")

    erreurs_par_heure = _build_error_velocity(df_clean)
    tentatives_par_ip = _build_ip_threat_table(df_clean)
    events_par_service = _build_service_stability(df_clean)

    health = compute_health_score(df_clean)
    print(
        f"[METRIQUES] Health: {health:.1f}% | "
        f"Errors/h peak: {erreurs_par_heure['Nombre_Erreurs'].max() if not erreurs_par_heure.empty else 0} | "
        f"Top threat weight: {tentatives_par_ip['Threat_Weight'].max() if not tentatives_par_ip.empty else 0:.1f}"
    )

    return erreurs_par_heure, tentatives_par_ip, events_par_service


# ── Error velocity ───────────────────────────────────────────────────────────
def _build_error_velocity(df: pd.DataFrame) -> pd.DataFrame:
    errors = df[df["Etat"] == "Error"].groupby("Heure").size().reset_index()
    errors.columns = ["Heure", "Nombre_Erreurs"]

    if len(errors) > 1:
        errors["Velocity"] = errors["Nombre_Erreurs"].diff().fillna(0)
        errors["Acceleration"] = errors["Velocity"].diff().fillna(0)
    else:
        errors["Velocity"] = 0
        errors["Acceleration"] = 0

    if len(errors) >= 3:
        errors["Baseline_3h"] = errors["Nombre_Erreurs"].rolling(3, min_periods=1).mean().round(2)
        errors["Spike_Ratio"] = (errors["Nombre_Erreurs"] / errors["Baseline_3h"].replace(0, 1)).round(3)
        errors["Is_Spike"] = errors["Spike_Ratio"] >= VELOCITY_SPIKE_THRESHOLD
    else:
        errors["Baseline_3h"] = errors["Nombre_Erreurs"]
        errors["Spike_Ratio"] = 1.0
        errors["Is_Spike"] = False

    return errors


# ── IP threat table ──────────────────────────────────────────────────────────
def _build_ip_threat_table(df: pd.DataFrame) -> pd.DataFrame:
    ip_df = df[df["IP_Source"].notna()].copy()
    if ip_df.empty:
        return pd.DataFrame()

    agg = ip_df.groupby("IP_Source").agg(
        Total_Events=("Message", "count"),
        Unique_Services=("Service", "nunique"),
        Total_Errors=("Etat", lambda x: (x == "Error").sum()),
        First_Seen=("Date", "min"),
        Last_Seen=("Date", "max"),
    ).reset_index()

    agg.columns = [
        "IP_Source", "Total_Events", "Unique_Services",
        "Total_Errors", "First_Seen", "Last_Seen"
    ]

    agg["Duration_min"] = (
        (agg["Last_Seen"] - agg["First_Seen"]).dt.total_seconds() / 60
    ).round(1).clip(lower=0.1)

    agg["Rate_per_min"] = (agg["Total_Events"] / agg["Duration_min"]).round(3)

    agg["Threat_Weight"] = (agg["Total_Errors"] * 0.7 + agg["Unique_Services"] * 5.0).round(2)

    agg = agg.sort_values("Threat_Weight", ascending=False).reset_index(drop=True)

    # Legacy attendu par ton app
    agg["Nombre_Tentatives"] = agg["Total_Events"]

    return agg


# ── Service stability ────────────────────────────────────────────────────────
def _build_service_stability(df: pd.DataFrame) -> pd.DataFrame:
    counts = df.groupby("Service").size().reset_index()
    counts.columns = ["Service", "Nombre_Events"]

    errors = df[df["Etat"] == "Error"].groupby("Service").size().reset_index()
    errors.columns = ["Service", "Error_Count"]

    result = pd.merge(counts, errors, on="Service", how="left").fillna(0)
    result["Failure_Rate_%"] = (result["Error_Count"] / result["Nombre_Events"] * 100).round(2)

    return result.sort_values("Nombre_Events", ascending=False).reset_index(drop=True)


# ── Health score ─────────────────────────────────────────────────────────────
def compute_health_score(df: pd.DataFrame) -> float:
    if df.empty:
        return 100.0

    total = len(df)
    if total == 0:
        return 100.0

    kernel_errors = df[
        (df["Etat"] == "Error")
        & (df["Service"].str.lower().str.contains("kernel|syslog", na=False))
    ]
    ssh_errors = df[
        (df["Etat"] == "Error")
        & (df["Service"].str.lower().str.contains("ssh|auth|pam", na=False))
    ]
    web_errors = df[
        (df["Etat"] == "Error")
        & (df["Service"].str.lower().str.contains("apache|nginx|http", na=False))
    ]
    ftp_errors = df[
        (df["Etat"] == "Error")
        & (df["Service"].str.lower().str.contains("ftp|vsftpd|proftpd", na=False))
    ]
    other_errors = df[
        (df["Etat"] == "Error")
        & ~df["Service"].str.lower().str.contains(
            "kernel|syslog|ssh|auth|pam|apache|nginx|http|ftp|vsftpd|proftpd",
            na=False,
        )
    ]

    def ratio(subset: pd.DataFrame) -> float:
        return min(1.0, len(subset) / max(total, 1))

    penalty = (
        ratio(kernel_errors) * HEALTH_KERNEL_WEIGHT * 100
        + ratio(ssh_errors) * HEALTH_SSH_WEIGHT * 100
        + ratio(web_errors) * HEALTH_WEB_WEIGHT * 100
        + ratio(ftp_errors) * HEALTH_FTP_WEIGHT * 100
        + ratio(other_errors) * 0.10 * 100
    )

    return round(max(0.0, 100.0 - penalty * 2), 1)


# ── IP entropy ───────────────────────────────────────────────────────────────
def compute_ip_entropy(df: pd.DataFrame) -> dict[str, Any]:
    ip_series = df[df["IP_Source"].notna()]["IP_Source"]
    if ip_series.empty:
        return {"entropy": 0.0, "interpretation": "no_data", "unique_ips": 0}

    counts = ip_series.value_counts()
    probs = counts / counts.sum()
    entropy = float(-np.sum(probs * np.log2(probs + 1e-10)))

    if entropy < ENTROPY_LOW_THRESHOLD:
        interp = "concentrated_attacker"
    elif entropy > ENTROPY_HIGH_THRESHOLD:
        interp = "distributed_botnet"
    else:
        interp = "moderate_activity"

    return {
        "entropy": round(entropy, 3),
        "interpretation": interp,
        "unique_ips": int(counts.shape[0]),
        "top_ip_share_%": round(float(probs.iloc[0]) * 100, 1) if len(probs) else 0.0,
    }


# ── Temporal rhythm ──────────────────────────────────────────────────────────
def compute_temporal_pattern(df: pd.DataFrame) -> dict[str, Any]:
    if df.empty or "Date" not in df.columns:
        return {}

    df = df.copy()
    df["Date"] = pd.to_datetime(df["Date"], errors="coerce")
    df = df.dropna(subset=["Date"])
    if df.empty:
        return {}

    df["hour"] = df["Date"].dt.hour
    df["ddate"] = df["Date"].dt.date

    hour_dist = df.groupby("hour").size().reindex(range(24), fill_value=0)

    night_events = int(hour_dist[0:6].sum())
    total_events = int(len(df))
    night_ratio = round(night_events / max(total_events, 1), 3)

    peak_hour = int(hour_dist.idxmax())

    days_active = df["ddate"].nunique()
    peak_days = df[df["hour"] == peak_hour]["ddate"].nunique()
    is_scheduled = (days_active >= 2) and (peak_days / max(days_active, 1) >= 0.6)

    return {
        "hour_distribution": hour_dist.to_dict(),
        "peak_hour": peak_hour,
        "night_ratio": night_ratio,
        "is_scheduled": is_scheduled,
        "days_active": days_active,
    }


# ── Compact summary for agents ───────────────────────────────────────────────
def get_summary_for_detector(
    erreurs_par_heure: pd.DataFrame,
    tentatives_par_ip: pd.DataFrame,
    df_clean: pd.DataFrame | None = None,
) -> dict[str, Any]:
    top_threat = tentatives_par_ip.iloc[0]["IP_Source"] if not tentatives_par_ip.empty else "None"
    top_weight = (
        float(tentatives_par_ip.iloc[0]["Threat_Weight"])
        if (not tentatives_par_ip.empty and "Threat_Weight" in tentatives_par_ip.columns)
        else 0.0
    )
    recent_velocity = (
        float(erreurs_par_heure.iloc[-1]["Velocity"])
        if (not erreurs_par_heure.empty and "Velocity" in erreurs_par_heure.columns)
        else 0.0
    )
    is_spike = (
        bool(erreurs_par_heure.iloc[-1]["Is_Spike"])
        if (not erreurs_par_heure.empty and "Is_Spike" in erreurs_par_heure.columns)
        else False
    )

    health = compute_health_score(df_clean) if df_clean is not None else 100.0
    entropy_info = compute_ip_entropy(df_clean) if df_clean is not None else {}
    temporal = compute_temporal_pattern(df_clean) if df_clean is not None else {}

    alert_level = (
        "CRITICAL" if is_spike and recent_velocity > 15 else
        "HIGH" if is_spike or recent_velocity > 5 else
        "NORMAL"
    )

    return {
        "health_score": health,
        "critical_ip": top_threat,
        "top_threat_weight": top_weight,
        "attack_velocity": recent_velocity,
        "is_velocity_spike": is_spike,
        "alert_status": alert_level,
        "ip_entropy": entropy_info.get("entropy", 0.0),
        "attack_pattern": entropy_info.get("interpretation", "unknown"),
        "unique_attacking_ips": entropy_info.get("unique_ips", 0),
        "night_ratio": temporal.get("night_ratio", 0.0),
        "is_scheduled_attack": temporal.get("is_scheduled", False),
        "peak_attack_hour": temporal.get("peak_hour", -1),
    }


# ── A.3: Drift score ─────────────────────────────────────────────────────────
def compute_drift_score(
    current_anomaly_rate: float,
    memory_file: str = "long_term_memory.json",
) -> dict[str, Any]:
    """
    A.3 — Drift score: measures how much the system's anomaly rate has shifted
    compared to the previous session.

    drift = abs(current_anomaly_rate - previous_anomaly_rate)

    Thresholds:
      drift < 0.05  → STABLE   — normal session-to-session variation
      drift < 0.15  → MODERATE — worth watching
      drift >= 0.15 → HIGH     — system behavior has changed significantly

    Returns a dict with:
      drift_score, previous_anomaly_rate, drift_label, drift_flagged
    """
    import json
    from pathlib import Path

    result: dict[str, Any] = {
        "drift_score":           0.0,
        "current_anomaly_rate":  round(current_anomaly_rate, 4),
        "previous_anomaly_rate": None,
        "drift_label":           "STABLE",
        "drift_flagged":         False,
        "sessions_compared":     0,
    }

    # Try to load previous session's anomaly rate from long_term_memory.json
    mem_path = Path(memory_file)
    if not mem_path.exists():
        # Also try relative path from project root
        for candidate in ["long_term_memory.json", "../long_term_memory.json",
                          "backend/long_term_memory.json"]:
            p = Path(candidate)
            if p.exists():
                mem_path = p
                break
        else:
            return result  # no memory yet — first session

    try:
        with open(mem_path, "r", encoding="utf-8", errors="replace") as f:
            memory = json.load(f)
    except Exception:
        return result

    sessions = memory.get("sessions", [])
    if not sessions:
        return result

    # Extract anomaly rates from past sessions (stored in donnees)
    past_rates: list[float] = []
    for s in sessions[-10:]:  # look at last 10 sessions max
        donnees = s.get("donnees", {})
        # Try several field names the pipeline may have stored it under
        rate = (
            donnees.get("anomaly_rate")
            or donnees.get("taux_anomalies")
            or donnees.get("fp_score_session")
        )
        if rate is not None:
            try:
                past_rates.append(float(rate))
            except (TypeError, ValueError):
                pass

    if not past_rates:
        return result

    previous_rate = past_rates[-1]
    drift = abs(current_anomaly_rate - previous_rate)

    if drift < 0.05:
        label = "STABLE"
        flagged = False
    elif drift < 0.15:
        label = "MODERATE"
        flagged = False
    else:
        label = "HIGH"
        flagged = True

    result.update({
        "drift_score":           round(drift, 4),
        "previous_anomaly_rate": round(previous_rate, 4),
        "drift_label":           label,
        "drift_flagged":         flagged,
        "sessions_compared":     len(past_rates),
    })

    print(
        f"[A.3] Drift score: {drift:.4f} ({label}) | "
        f"current={current_anomaly_rate:.4f} prev={previous_rate:.4f}"
        + (" ⚠️  DRIFT FLAGGED" if flagged else "")
    )
    return result