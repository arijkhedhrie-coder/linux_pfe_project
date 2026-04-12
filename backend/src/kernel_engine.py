"""
kernel_engine.py — v3 (Phase 1 Standardized + Feature Engineering)
══════════════════════════════════════════════════════════════════════
Scores kernel/syslog instability: OOM, panics, I/O errors, segfaults.

CHANGES vs v2:
  - Standard output schema matching other engines:
    returned dict now includes a 'features' key with all signals
  - Attack type classification: EXPLOIT_ATTEMPT, RESOURCE_EXHAUSTION,
    DISK_FAILURE_OR_ATTACK, CRITICAL_SYSTEM_FAILURE
  - Three separate alarm types (CRITICAL, ACCELERATION, LOAD_SPIKE)
  - Added 'source_ip' = 'SYSTEM' to output for correlation map
══════════════════════════════════════════════════════════════════════
"""
from __future__ import annotations

import re
from typing import Any

import pandas as pd


# ── Thresholds ─────────────────────────────────────────────────────────────────
HIGH_RISK_THRESHOLD = 50.0
MED_RISK_THRESHOLD  = 28.0

_CRITICAL_PAT = re.compile(
    r'kernel panic|Kernel panic|BUG:|Oops:|general protection fault|'
    r'segfault|segmentation fault|Call Trace:|EXT4-fs error|I/O error|'
    r'Out of memory|oom-killer|Killed process|blk_update_request: I/O error|'
    r'Buffer I/O error|Machine Check Exception',
    re.I,
)
_WARN_PAT = re.compile(
    r'\bWARN\b|\bWARNING\b|error|failed|timeout|reset|watchdog|'
    r'soft lockup|hard LOCKUP|NIC Link is Down|transmit timed out',
    re.I,
)


# ── Attack classification ──────────────────────────────────────────────────────

def _classify_kernel_event(content: str) -> str:
    """Map kernel message to an attacker-relevant event type."""
    c = content.lower()
    if 'segfault' in c or 'general protection fault' in c:
        return 'EXPLOIT_ATTEMPT'
    if 'oom' in c or 'out of memory' in c or 'oom-killer' in c:
        return 'RESOURCE_EXHAUSTION'
    if 'i/o error' in c or 'buffer i/o' in c or 'blk_update' in c:
        return 'DISK_FAILURE_OR_ATTACK'
    if 'kernel panic' in c or 'oops' in c or 'bug:' in c:
        return 'CRITICAL_SYSTEM_FAILURE'
    if 'soft lockup' in c or 'hard lockup' in c:
        return 'CPU_LOCKUP'
    return 'SYSTEM_WARNING'


# ── Row detection ──────────────────────────────────────────────────────────────

def _is_kernel_row(row: pd.Series) -> bool:
    sl = str(row.get('source_log', '')).lower()
    c  = str(row.get('Content', ''))
    if 'kernel' in sl or sl == 'syslog':
        return bool(_CRITICAL_PAT.search(c) or _WARN_PAT.search(c))
    if re.search(r'\bkernel:\b|\[\s*\d+\.\d+\]', c):
        return bool(_CRITICAL_PAT.search(c) or _WARN_PAT.search(c))
    return False


def parse_kernel_logs(df: pd.DataFrame) -> pd.DataFrame:
    if df is None or df.empty or 'Content' not in df.columns:
        return pd.DataFrame()
    sub = df.copy()
    sub['ts'] = pd.to_datetime(sub['timestamp'], errors='coerce')
    sub = sub.dropna(subset=['ts'])
    if sub.empty:
        return pd.DataFrame()
    sub = sub[sub.apply(_is_kernel_row, axis=1)].copy()
    if sub.empty:
        return pd.DataFrame()
    sub['sev']         = sub['Content'].apply(lambda x: 3 if _CRITICAL_PAT.search(str(x)) else 1)
    sub['attack_type'] = sub['Content'].apply(_classify_kernel_event)
    return sub.sort_values('ts').reset_index(drop=True)


# ── Time intelligence ──────────────────────────────────────────────────────────

def _ewma(series: pd.Series, alpha: float = 0.3) -> float:
    if series.empty:
        return 0.0
    v = 0.0
    for val in series.astype(float).values:
        v = alpha * val + (1 - alpha) * v
    return float(v)


def _acceleration_score(ts: pd.Series, weights: pd.Series) -> float:
    """Compare error density in the last half vs first half of the timeline."""
    if len(ts) < 4:
        return 0.0
    tmin, tmax = ts.min(), ts.max()
    if tmax <= tmin:
        return 0.0
    mid    = tmin + (tmax - tmin) / 2
    first  = weights[ts <= mid].sum()
    second = weights[ts > mid].sum()
    dur    = max((tmax - tmin).total_seconds() / 3600.0, 1e-6)
    r1 = first  / max(dur / 2, 1e-6)
    r2 = second / max(dur / 2, 1e-6)
    if r2 > r1 * 1.5 and r2 > 2:
        return min(100.0, (r2 - r1) * 8.0)
    return min(40.0, max(0.0, (r2 - r1) * 4.0))


# ── Main engine ────────────────────────────────────────────────────────────────

def run_kernel_idps(
    df: pd.DataFrame,
    high_risk_threshold: float | None = None,
) -> dict[str, Any]:
    """
    Host-global kernel/syslog instability detector.

    Output schema (Phase 1 standard):
      status, weighted_risk_score, action,
      source_ip = 'SYSTEM' (for bridge correlation),
      features (dict with all signals),
      alarms (list of alarm dicts)

    Args:
        high_risk_threshold: Override for ESCALATE threshold (default: module HIGH_RISK_THRESHOLD = 50).
    """
    _high = high_risk_threshold if high_risk_threshold is not None else HIGH_RISK_THRESHOLD
    kdf = parse_kernel_logs(df)

    empty_result: dict[str, Any] = {
        'status':              'no_kernel_data',
        'weighted_risk_score': 0.0,
        'action':              'MONITOR',
        'source_ip':           'SYSTEM',
        'alarms':              [],
        'features':            {
            'engine':               'kernel',
            'attack_vector':        'NONE',
            'critical_events':      0,
            'warning_events':       0,
            'ewma_load':            0.0,
            'acceleration':         0.0,
            'attack_distribution':  {},
            'dominant_attack_type': 'NONE',
        },
    }

    if kdf.empty:
        return empty_result

    crit_n = int((kdf['sev'] >= 3).sum())
    warn_n = int(len(kdf) - crit_n)

    attack_counts    = kdf['attack_type'].value_counts().to_dict()
    dominant_attack  = max(attack_counts, key=attack_counts.get)

    kidx = kdf.set_index('ts')
    if len(kidx) >= 2 and kidx.index.max() > kidx.index.min():
        hourly = kidx.resample('h')['sev'].count().reindex(
            pd.date_range(
                kidx.index.min().floor('h'),
                kidx.index.max().ceil('h'),
                freq='h',
            ),
            fill_value=0,
        )
        ewma_load = _ewma(hourly, alpha=0.35)
        kr        = kidx.reset_index()
        accel     = _acceleration_score(kr['ts'], kr['sev'].clip(upper=1) + 0.5)
    else:
        ewma_load = float(len(kdf))
        accel     = 0.0

    crit_score = min(100.0, crit_n * 18.0)
    warn_score = min(60.0,  warn_n * 2.5)
    ewma_score = min(100.0, ewma_load * 12.0)

    weighted = round(
        crit_score * 0.40 + warn_score * 0.15 +
        ewma_score * 0.25 + accel * 0.20, 2,
    )

    risk_level = ('HIGH'   if weighted >= _high        else
                  'MEDIUM' if weighted >= MED_RISK_THRESHOLD  else 'LOW')
    action     = ('ESCALATE'        if risk_level == 'HIGH'   else
                  'WATCHLIST_30MIN' if risk_level == 'MEDIUM' else 'MONITOR')

    # ── Standard features dict ─────────────────────────────────────────────
    features: dict[str, Any] = {
        'engine':               'kernel',
        'attack_vector':        dominant_attack,
        'critical_events':      crit_n,
        'warning_events':       warn_n,
        'ewma_load':            round(ewma_load, 3),
        'acceleration':         round(accel, 2),
        'attack_distribution':  attack_counts,
        'dominant_attack_type': dominant_attack,
        'crit_score':           round(crit_score, 2),
        'warn_score':           round(warn_score, 2),
        'ewma_score':           round(ewma_score, 2),
    }

    # ── Multi-signal alarm generation ──────────────────────────────────────
    alarms: list[dict] = []

    if crit_n > 0:
        alarms.append({
            'type':     'KERNEL_CRITICAL',
            'severite': 'CRITIQUE',
            'score':    weighted,
            'ip':       'SYSTEM',
            'message':  (
                f"🔴 KERNEL/SYSLOG CRITICAL | {crit_n} critical-class events | "
                f"Risk: {weighted:.1f}/100 | Dominant: {dominant_attack}"
            ),
        })

    if accel > 20:
        alarms.append({
            'type':     'KERNEL_ACCELERATION',
            'severite': 'CRITIQUE',
            'score':    round(accel, 2),
            'ip':       'SYSTEM',
            'message':  f"⚡ ERROR ACCELERATION | Score {accel:.1f} — errors are accelerating",
        })

    if ewma_load > 3.0:
        alarms.append({
            'type':     'KERNEL_LOAD_SPIKE',
            'severite': 'AVERTISSEMENT',
            'score':    round(ewma_score, 2),
            'ip':       'SYSTEM',
            'message':  f"📈 ERROR RATE SPIKE | EWMA {ewma_load:.2f} errors/h",
        })

    if not alarms and weighted >= MED_RISK_THRESHOLD:
        alarms.append({
            'type':     'KERNEL_INSTABILITY',
            'severite': 'AVERTISSEMENT',
            'score':    weighted,
            'ip':       'SYSTEM',
            'message':  (
                f"🟠 KERNEL INSTABILITY | warnings trend | "
                f"EWMA≈{ewma_load:.2f}/h | Risk: {weighted:.1f}/100"
            ),
        })

    return {
        'status':              risk_level,
        'weighted_risk_score': weighted,
        'action':              action,
        'source_ip':           'SYSTEM',
        'alarms':              alarms,
        'features':            features,
        # Legacy fields kept for backward compat with existing streamlit_app
        'critical_hits':       crit_n,
        'warn_hits':           warn_n,
        'ewma_errors_per_hour': round(ewma_load, 3),
        'acceleration_score':  round(accel, 2),
    }