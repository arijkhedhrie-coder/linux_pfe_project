"""
ip_profiler.py — Phase 0: Data Clarity Layer
═══════════════════════════════════════════════════════════════════════════════
Two responsibilities:

  1. dedup_logs(df, window_minutes)
     Collapses duplicate log lines from the same IP within a time window.
     Same IP + same message within N minutes = 1 event (with a repeat_count).
     Prevents 85K rows of noise from overwhelming the ML models.

  2. build_ip_profiles(df)
     Before any ML runs, builds a compact behavioral fingerprint per IP:
       first_seen, last_seen, total_events, unique_messages,
       burst_windows (minutes with > threshold events),
       services_hit, error_rate, night_ratio, repeat_ratio
     This is the "fekra" — what did this IP actually do?
     Fed into alarm dicts and the trust engine.

  3. compute_noise_ratio(raw_count, deduped_count)
     Returns what fraction of the raw data was real vs repeated noise.
     Written to PIPELINE_START JSONL event.

Usage in main.py:
    from src.ip_profiler import dedup_logs, build_ip_profiles, compute_noise_ratio

    df_raw = load_logs_from_s3()
    df, noise_ratio = dedup_logs(df_raw, window_minutes=5)
    ip_profiles = build_ip_profiles(df)
    LOG.info("Noise ratio: %.1f%% unique events", noise_ratio * 100)
═══════════════════════════════════════════════════════════════════════════════
"""

from __future__ import annotations

import logging
from typing import Any

import pandas as pd
import numpy as np

logger = logging.getLogger("ip_profiler")
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("[ip_profiler] %(levelname)s %(message)s"))
    logger.addHandler(_h)
logger.setLevel(logging.INFO)

# ── Constants ─────────────────────────────────────────────────────────────────
BURST_THRESHOLD = 10          # events/minute to count as a burst window
NIGHT_HOURS = frozenset(range(0, 6))  # 00:00–05:59 = suspicious night activity
WINDOW_MINUTES = 5            # default dedup window


# ══════════════════════════════════════════════════════════════════════════════
# 1. DEDUPLICATION
# ══════════════════════════════════════════════════════════════════════════════

def dedup_logs(
    df: pd.DataFrame,
    window_minutes: int = WINDOW_MINUTES,
    ip_col: str = "IP_Source",
    msg_col: str = "Message",
    date_col: str = "Date",
) -> tuple[pd.DataFrame, float]:
    """
    Collapse duplicate log lines from the same IP within `window_minutes`.

    A "duplicate" is defined as: same IP + same message content within the
    rolling time window. Only the first occurrence is kept; a `repeat_count`
    column records how many duplicates were collapsed into it.

    Args:
        df             : Normalized DataFrame (must have IP_Source, Message, Date).
        window_minutes : Rolling window in minutes (default 5).
        ip_col         : Column name for source IP.
        msg_col        : Column name for log message.
        date_col       : Column name for timestamp.

    Returns:
        (deduped_df, noise_ratio)
        noise_ratio = 1 - (deduped_rows / raw_rows), i.e. fraction that was noise.
        A ratio of 0.72 means 72% of the data was duplicate noise.
    """
    raw_count = len(df)
    if raw_count == 0:
        return df.copy(), 0.0

    # Ensure we have the columns we need — graceful fallback
    missing = [c for c in [ip_col, msg_col, date_col] if c not in df.columns]
    if missing:
        logger.warning("dedup_logs: missing columns %s — skipping dedup", missing)
        return df.copy(), 0.0

    df = df.copy()
    df[date_col] = pd.to_datetime(df[date_col], errors="coerce")
    df = df.dropna(subset=[date_col]).sort_values(date_col).reset_index(drop=True)

    # Truncate timestamp to window buckets — this is the key operation:
    # two events in the same bucket from the same IP with the same message
    # are identical for our purposes.
    window_td = pd.Timedelta(minutes=window_minutes)
    epoch = df[date_col].min()

    df["_bucket"] = ((df[date_col] - epoch) / window_td).astype(int)

    # Normalise message for comparison (lowercase, strip whitespace)
    df["_msg_key"] = df[msg_col].astype(str).str.lower().str.strip()

    # Group by (IP, message_key, bucket) — count duplicates
    group_cols = [ip_col, "_msg_key", "_bucket"]
    counts = (
        df.groupby(group_cols, sort=False)
        .size()
        .reset_index(name="repeat_count")
    )

    # Keep only the first row per group
    df["_group_idx"] = df.groupby(group_cols, sort=False).cumcount()
    deduped = df[df["_group_idx"] == 0].copy()
    deduped = deduped.merge(counts, on=group_cols, how="left")

    # Clean up helper columns
    deduped = deduped.drop(columns=["_bucket", "_msg_key", "_group_idx"])
    deduped["repeat_count"] = deduped["repeat_count"].fillna(1).astype(int)
    deduped = deduped.reset_index(drop=True)

    deduped_count = len(deduped)
    noise_ratio = 1.0 - (deduped_count / raw_count) if raw_count > 0 else 0.0

    logger.info(
        "dedup_logs: %d raw → %d unique (noise=%.1f%%, window=%dmin)",
        raw_count, deduped_count, noise_ratio * 100, window_minutes,
    )
    return deduped, round(noise_ratio, 4)


# ══════════════════════════════════════════════════════════════════════════════
# 2. IP BEHAVIOR PROFILER
# ══════════════════════════════════════════════════════════════════════════════

def build_ip_profiles(
    df: pd.DataFrame,
    ip_col: str = "IP_Source",
    msg_col: str = "Message",
    date_col: str = "Date",
    etat_col: str = "Etat",
    service_col: str = "Service",
) -> dict[str, dict[str, Any]]:
    """
    Build a behavioral fingerprint for every IP in the dataset.

    Returns a dict keyed by IP string. Each value is:
    {
        "first_seen":      ISO timestamp string,
        "last_seen":       ISO timestamp string,
        "duration_minutes": float,
        "total_events":    int,
        "unique_messages": int,
        "repeat_ratio":    float,   # how repetitive this IP was (0=all unique)
        "error_rate":      float,   # fraction of events that were errors
        "warning_rate":    float,
        "services_hit":    list[str],
        "burst_windows":   int,     # number of 1-min windows with > BURST_THRESHOLD events
        "night_ratio":     float,   # fraction of events during night hours (00:00-05:59)
        "peak_minute":     str,     # minute with most activity (HH:MM)
        "avg_events_per_min": float,
    }

    These profiles feed:
      - alarm dicts (richer explainability)
      - model agreement cross-check
      - trust score engine (Phase B)
    """
    if df is None or df.empty:
        return {}

    # Ensure required columns exist
    for col in [ip_col, date_col]:
        if col not in df.columns:
            logger.warning("build_ip_profiles: missing column '%s' — returning empty", col)
            return {}

    df = df.copy()
    df[date_col] = pd.to_datetime(df[date_col], errors="coerce")
    df = df.dropna(subset=[date_col, ip_col])
    df = df[df[ip_col].astype(str).str.strip().ne("") & df[ip_col].notna()]

    if df.empty:
        return {}

    profiles: dict[str, dict[str, Any]] = {}

    for ip, grp in df.groupby(ip_col):
        ip_str = str(ip)
        grp = grp.sort_values(date_col)

        ts_series = grp[date_col]
        first_seen = ts_series.min()
        last_seen  = ts_series.max()
        duration_s = (last_seen - first_seen).total_seconds()
        duration_min = duration_s / 60.0

        total_events = len(grp)

        # Unique messages
        messages = grp[msg_col].astype(str).str.lower().str.strip() if msg_col in grp.columns else pd.Series([], dtype=str)
        unique_messages = int(messages.nunique()) if len(messages) > 0 else total_events
        repeat_ratio = round(1.0 - (unique_messages / total_events), 4) if total_events > 0 else 0.0

        # Error / warning rates
        if etat_col in grp.columns:
            etat = grp[etat_col].astype(str).str.lower()
            error_rate   = round(float((etat == "error").mean()), 4)
            warning_rate = round(float((etat == "warning").mean()), 4)
        else:
            error_rate   = 0.0
            warning_rate = 0.0

        # Services hit
        if service_col in grp.columns:
            services_hit = sorted(grp[service_col].astype(str).dropna().unique().tolist())
        else:
            services_hit = []

        # Burst windows — count 1-minute buckets with > BURST_THRESHOLD events
        grp = grp.copy()
        grp["_min_bucket"] = grp[date_col].dt.floor("1min")
        events_per_min = grp.groupby("_min_bucket").size()
        burst_windows = int((events_per_min > BURST_THRESHOLD).sum())
        avg_events_per_min = round(float(events_per_min.mean()), 2) if len(events_per_min) > 0 else 0.0

        # Peak minute
        if len(events_per_min) > 0:
            peak_minute = str(events_per_min.idxmax().strftime("%H:%M"))
        else:
            peak_minute = "N/A"

        # Night ratio — fraction of events between 00:00 and 05:59
        hours = grp[date_col].dt.hour
        night_ratio = round(float(hours.isin(NIGHT_HOURS).mean()), 4) if len(hours) > 0 else 0.0

        profiles[ip_str] = {
            "first_seen":         first_seen.isoformat(),
            "last_seen":          last_seen.isoformat(),
            "duration_minutes":   round(duration_min, 1),
            "total_events":       total_events,
            "unique_messages":    unique_messages,
            "repeat_ratio":       repeat_ratio,
            "error_rate":         error_rate,
            "warning_rate":       warning_rate,
            "services_hit":       services_hit,
            "burst_windows":      burst_windows,
            "night_ratio":        night_ratio,
            "peak_minute":        peak_minute,
            "avg_events_per_min": avg_events_per_min,
        }

    logger.info("build_ip_profiles: profiled %d unique IPs", len(profiles))
    return profiles


# ══════════════════════════════════════════════════════════════════════════════
# 3. NOISE RATIO HELPER
# ══════════════════════════════════════════════════════════════════════════════

def compute_noise_ratio(raw_count: int, deduped_count: int) -> float:
    """
    Returns the fraction of raw rows that were duplicate noise.

    noise_ratio = 1 - (deduped / raw)

    Examples:
      raw=85187, deduped=24000 → 0.72 (72% was noise)
      raw=5000,  deduped=4800  → 0.04 (4% was noise — clean session)

    Used to:
      - Weight ML scores lower when noise_ratio > 0.70
      - Display "Data quality: X% unique events" in the dashboard
    """
    if raw_count <= 0:
        return 0.0
    ratio = 1.0 - (min(deduped_count, raw_count) / raw_count)
    return round(max(0.0, min(1.0, ratio)), 4)


def data_quality_label(noise_ratio: float) -> str:
    """Human-readable label for the dashboard KPI bar."""
    unique_pct = round((1.0 - noise_ratio) * 100, 1)
    if noise_ratio < 0.20:
        quality = "CLEAN"
    elif noise_ratio < 0.50:
        quality = "MODERATE"
    elif noise_ratio < 0.75:
        quality = "NOISY"
    else:
        quality = "HIGH NOISE"
    return f"{unique_pct}% unique — {quality}"


# ══════════════════════════════════════════════════════════════════════════════
# 4. NOISE-AWARE SCORE WEIGHT
# ══════════════════════════════════════════════════════════════════════════════

def noise_score_weight(noise_ratio: float) -> float:
    """
    Returns a multiplier (0.75–1.0) to apply to ML anomaly scores
    when the session has high noise.

    High noise means the models saw inflated counts — their scores
    may be slightly over-estimated. We dampen but never zero them out.

      noise_ratio < 0.50  → weight = 1.0  (no adjustment)
      noise_ratio = 0.70  → weight = 0.90
      noise_ratio = 0.85  → weight = 0.80
      noise_ratio > 0.95  → weight = 0.75 (floor)
    """
    if noise_ratio < 0.50:
        return 1.0
    # Linear scale from 1.0 at 0.50 down to 0.75 at 1.0
    weight = 1.0 - (noise_ratio - 0.50) * 0.50
    return round(max(0.75, min(1.0, weight)), 3)


# ══════════════════════════════════════════════════════════════════════════════
# 5. SESSION-LEVEL GLOBALS (set by main.py, read by bridge/detection modules)
# ══════════════════════════════════════════════════════════════════════════════
# These are set once per pipeline run, before Pass 1 starts.
# Access from any module:
#   import src.ip_profiler as _prof
#   profiles = _prof._current_session_profiles   # dict[ip_str -> profile_dict]
#   weight   = _prof._current_ml_score_weight    # float 0.75–1.0

_current_session_profiles: dict[str, dict] = {}
_current_ml_score_weight: float = 1.0
# Step 2: trust score made available to the bridge gate
# Set in main.py after compute_trust(), read in ml_engine_bridge._ab_gate()
_current_trust_score: float = 0.5   # default = UNCERTAIN → conservative
_current_trust_label: str   = "UNCERTAIN"