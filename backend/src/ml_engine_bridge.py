"""
ml_engine_bridge.py — v4 HYBRID (Rule-based + LLM-adaptive)
═══════════════════════════════════════════════════════════════════════════════
New in v4 — Hybrid Architecture:

  PASS 1 (always runs):
    All 5 engines run with their DEFAULT thresholds.
    Produces initial alarms + metrics for the agent layer.

  AGENT REASONING (outside this file):
    Orchestrator agent reads Pass 1 output + metrics context.
    Emits a DynamicConfig: threshold overrides, IPs to escalate,
    engines to re-run.

  PASS 2 (only if DynamicConfig has overrides):
    Bridge re-runs only the engines flagged in DynamicConfig.rerun_engines,
    with adjusted thresholds from the agent.
    Force-escalates IPs in DynamicConfig.escalate_ips.
    Suppresses IPs in DynamicConfig.suppress_ips.
    Merges Pass 2 results with Pass 1 — best score wins per IP.

This keeps detection DETERMINISTIC and AUDITABLE (Pass 1 never changes)
while adding CONTEXTUAL INTELLIGENCE (Pass 2 adapts based on reasoning).

Preserved from v3:
  ✅ Time-aware correlation (30-min sliding window)
  ✅ Attack chain detection (SCAN→BRUTE→BREACH→EXFIL)
  ✅ Weighted combo scores per protocol pair
═══════════════════════════════════════════════════════════════════════════════
"""

from __future__ import annotations

import json
import os
import pandas as pd
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path
from typing import Any

from src.adapter import normalize
from src.ml_engine import run_idps, get_model_performance
from src.web_engine import run_web_idps
from src.session_engine import run_session_idps
from src.ftp_engine import run_ftp_idps
from src.kernel_engine import run_kernel_idps
from src.prediction_engine import run_prediction_engine
from src.hybrid_config import DynamicConfig


# ── Thresholds (defaults — can be overridden by DynamicConfig) ────────────────
HIGH_RISK_THRESHOLD  = 38
MED_RISK_THRESHOLD   = 22
CORR_TIME_WINDOW_MIN = 30

# ── Phase C.9: Audit log path ─────────────────────────────────────────────────
_MODELS_DIR      = "src/models"
CHANGE_LOG_PATH  = os.path.join(_MODELS_DIR, "threshold_change_log.json")


# ── Threshold snapshot helper ─────────────────────────────────────────────────

def _build_threshold_snapshot(cfg: DynamicConfig, pass_number: int) -> dict:
    """
    Returns a compact dict recording the effective thresholds applied
    during a given detection pass. Stored on every alarm for full auditability.

    Fields:
      pass          — 1 (default) or 2 (agent-adjusted)
      issued_by     — "default" or "orchestrator_agent"
      ssh_high      — effective SSH block threshold
      ssh_med       — effective SSH watchlist threshold
      web_high      — effective WEB block threshold
      web_med       — effective WEB watchlist threshold
      ftp_high      — effective FTP block threshold
      ftp_med       — effective FTP watchlist threshold
      kernel_high   — effective KERNEL escalate threshold
      session_high  — effective SESSION block threshold
      session_med   — effective SESSION watchlist threshold
      corr_window   — correlation time window in minutes
      escalate_ips  — IPs force-escalated by agent
      suppress_ips  — IPs suppressed by agent
      threat_level  — agent threat assessment
      confidence    — agent confidence (0–1)
    """
    return {
        "pass":          pass_number,
        "issued_by":     cfg.issued_by,
        "ssh_high":      cfg.ssh_high_risk_threshold    if cfg.ssh_high_risk_threshold    is not None else HIGH_RISK_THRESHOLD,
        "ssh_med":       cfg.ssh_med_risk_threshold     if cfg.ssh_med_risk_threshold     is not None else MED_RISK_THRESHOLD,
        "web_high":      cfg.web_high_risk_threshold    if cfg.web_high_risk_threshold    is not None else 55,
        "web_med":       cfg.web_med_risk_threshold     if cfg.web_med_risk_threshold     is not None else 30,
        "ftp_high":      cfg.ftp_high_risk_threshold    if cfg.ftp_high_risk_threshold    is not None else 55,
        "ftp_med":       cfg.ftp_med_risk_threshold     if cfg.ftp_med_risk_threshold     is not None else 30,
        "kernel_high":   cfg.kernel_high_risk_threshold if cfg.kernel_high_risk_threshold is not None else 50,
        "session_high":  cfg.session_high_risk_threshold if cfg.session_high_risk_threshold is not None else 50,
        "session_med":   cfg.session_med_risk_threshold  if cfg.session_med_risk_threshold  is not None else 25,
        "corr_window":   cfg.correlation_window_min     if cfg.correlation_window_min     is not None else CORR_TIME_WINDOW_MIN,
        "escalate_ips":  cfg.escalate_ips,
        "suppress_ips":  cfg.suppress_ips,
        "threat_level":  cfg.threat_level,
        "confidence":    cfg.confidence,
    }

INVALID_IP_VALUES = {'', 'nan', 'none', 'null', 'unknown', 'n/a'}

SEUILS = {
    'SSH_BRUTE_FORCE': 5,
    'WEB_ENUMERATION': 100,
    'PORT_SCAN': 3,
}

COMBO_WEIGHTS: dict[frozenset, float] = {
    frozenset({'SSH', 'WEB'}):     20.0,
    frozenset({'WEB', 'FTP'}):     25.0,
    frozenset({'SSH', 'FTP'}):     22.0,
    frozenset({'SSH', 'SESSION'}): 30.0,
    frozenset({'WEB', 'SESSION'}): 30.0,
    frozenset({'FTP', 'SESSION'}): 30.0,
}
THREE_VECTOR_MULTIPLIER = 1.5

ATTACK_CHAINS: list[dict] = [
    {
        'name': 'FULL_KILL_CHAIN', 'steps': ['SSH', 'WEB', 'SESSION', 'FTP'],
        'severity': 'CRITIQUE', 'score': 95.0,
        'label': '💀 FULL KILL CHAIN: SCAN → BRUTE → BREACH → EXFIL',
    },
    {
        'name': 'SCAN_TO_BRUTEFORCE', 'steps': ['WEB', 'SSH'],
        'severity': 'CRITIQUE', 'score': 75.0,
        'label': '🔴 SCAN → BRUTE FORCE sequence detected',
    },
    {
        'name': 'BRUTEFORCE_TO_BREACH', 'steps': ['SSH', 'SESSION'],
        'severity': 'CRITIQUE', 'score': 85.0,
        'label': '🔴 BRUTE FORCE → SESSION BREACH confirmed',
    },
    {
        'name': 'BREACH_TO_EXFIL', 'steps': ['SESSION', 'FTP'],
        'severity': 'CRITIQUE', 'score': 90.0,
        'label': '🔴 POST-BREACH DATA EXFILTRATION in progress',
    },
    {
        'name': 'WEB_TO_EXFIL', 'steps': ['WEB', 'FTP'],
        'severity': 'CRITIQUE', 'score': 80.0,
        'label': '🔴 WEB PIVOT → FTP EXFILTRATION detected',
    },
]


# ── Utility helpers ────────────────────────────────────────────────────────────

def _clean_ip(value, fallback: str = 'N/A') -> str:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return fallback
    text = str(value).strip()
    return fallback if text.lower() in INVALID_IP_VALUES else text


def _is_usable_ip(value) -> bool:
    cleaned = _clean_ip(value, fallback='')
    return bool(cleaned) and cleaned not in {'GLOBAL', 'SYSTEM', 'local', 'N/A'}


def _parse_ts(value) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, pd.Timestamp):
        return value.to_pydatetime()
    try:
        return pd.to_datetime(value).to_pydatetime()
    except Exception:
        return None


def _same_time_window(ts_a: datetime | None, ts_b: datetime | None,
                      window_min: float = CORR_TIME_WINDOW_MIN) -> bool:
    if ts_a is None or ts_b is None:
        return True
    return abs((ts_a - ts_b).total_seconds()) / 60.0 <= window_min


# ── Engine runner (respects DynamicConfig thresholds) ─────────────────────────

def _run_engines(
    df_norm: pd.DataFrame,
    cfg: DynamicConfig,
    engines_filter: list[str] | None = None,
) -> dict[str, Any]:
    """
    Runs all 5 engines (or a subset if engines_filter is given).
    Passes threshold overrides from DynamicConfig directly as function arguments.
    No module-level patching — each call is fully isolated and concurrency-safe.

    Returns dict: {web_table, sess_result, ftp_table, kernel_meta, risk_table}
    """
    run_all = engines_filter is None
    results: dict[str, Any] = {}

    # SSH / ml_engine
    if run_all or 'ssh' in engines_filter:
        results['risk_table'] = run_idps(
            df_norm,
            high_risk_threshold=cfg.ssh_high_risk_threshold,
            med_risk_threshold=cfg.ssh_med_risk_threshold,
        )
    else:
        results['risk_table'] = None

    # WEB engine
    if run_all or 'web' in engines_filter:
        results['web_table'] = run_web_idps(
            df_norm,
            high_risk_threshold=cfg.web_high_risk_threshold,
            med_risk_threshold=cfg.web_med_risk_threshold,
        )
    else:
        results['web_table'] = pd.DataFrame()

    # SESSION engine
    if run_all or 'session' in engines_filter:
        results['sess_result'] = run_session_idps(
            df_norm,
            high_risk_threshold=cfg.session_high_risk_threshold,
            med_risk_threshold=cfg.session_med_risk_threshold,
        )
    else:
        results['sess_result'] = {'alarms': [], 'features': {}}

    # FTP engine
    if run_all or 'ftp' in engines_filter:
        results['ftp_table'] = run_ftp_idps(
            df_norm,
            high_risk_threshold=cfg.ftp_high_risk_threshold,
            med_risk_threshold=cfg.ftp_med_risk_threshold,
        )
    else:
        results['ftp_table'] = pd.DataFrame()

    # KERNEL engine
    if run_all or 'kernel' in engines_filter:
        results['kernel_meta'] = run_kernel_idps(
            df_norm,
            high_risk_threshold=cfg.kernel_high_risk_threshold,
        )
    else:
        results['kernel_meta'] = {'alarms': [], 'weighted_risk_score': 0}

    return results


# ── Phase C.8: A/B gate helpers ───────────────────────────────────────────────

def _compute_pass_metrics(alarmes: list[dict]) -> dict[str, float]:
    """
    Derive comparable metrics from an alarm list for the A/B gate.

    Returns:
        fp_rate   — fraction of alarms flagged by only 1 model (0–1)
        recall    — fraction of real IPs that were flagged (proxy: non-SYSTEM alarms / total IPs seen)
        alarm_count — raw count of real (non-SYSTEM) alarms
        avg_score — mean alarm score, used as proxy for detection intensity
    """
    real = [a for a in alarmes if a.get('ip', 'SYSTEM') != 'SYSTEM']
    total = len(real)

    isolated = [
        a for a in real
        if a.get('models_agreed', 4) <= 1 or a.get('agreement_label') == 'LOW'
    ]
    fp_rate = round(len(isolated) / max(total, 1), 4)

    # Recall proxy: what fraction of flagged IPs were at CRITIQUE level?
    # (We can't know true positives without ground truth, so we use severity ratio
    #  as a relative measure — lower severity ratio = lower recall proxy)
    critiques = [a for a in real if a.get('severite') == 'CRITIQUE']
    recall = round(len(critiques) / max(total, 1), 4)

    avg_score = round(
        sum(float(a.get('score', 0)) for a in real) / max(total, 1), 4
    )

    return {
        'fp_rate':     fp_rate,
        'recall':      recall,
        'alarm_count': total,
        'avg_score':   avg_score,
    }


def _ab_gate(
    p1_metrics: dict[str, float],
    p2_metrics: dict[str, float],
    trust_score: float = 0.5,
    trust_label: str = "UNCERTAIN",
) -> tuple[bool, str, list[str], list[str]]:
    """
    Step 2 — Trust-score gate (replaces the 3-check raw-metric gate).

    Decision Governance: the gate asks ONE question —
      "Is the system trustworthy enough to apply AI-driven changes?"

    Rules (deterministic, no LLM):
      trust_score > 0.80  → FULL ACCEPT  — apply Pass 2 alarms + threshold changes
      trust_score 0.50–0.80 → PARTIAL    — apply escalate_ips only, block threshold changes
      trust_score < 0.50  → REJECT       — revert to Pass 1, ignore AI proposal entirely

    The raw metrics (fp_rate, recall, alarm_count) are still computed and logged
    for the audit trail but no longer drive the accept/reject decision.

    Returns:
        (accepted, mode, passed_checks, failed_checks)
        accepted      — True if FULL or PARTIAL (Pass 2 results used)
        mode          — "FULL" | "PARTIAL" | "REJECTED"
        passed_checks — what the gate found acceptable
        failed_checks — what the gate found problematic
    """
    passed: list[str] = []
    failed: list[str] = []

    # Primary decision — trust score
    if trust_score > 0.80:
        mode = "FULL"
        passed.append(f"TRUST_HIGH ({trust_score:.3f} > 0.80 [{trust_label}]) — full Pass 2 applied")
    elif trust_score >= 0.50:
        mode = "PARTIAL"
        passed.append(f"TRUST_MEDIUM ({trust_score:.3f} ∈ [0.50, 0.80] [{trust_label}]) — escalate_ips only")
        failed.append("THRESHOLD_CHANGES_BLOCKED — trust < 0.80, only IP escalations allowed")
    else:
        mode = "REJECTED"
        failed.append(f"TRUST_LOW ({trust_score:.3f} < 0.50 [{trust_label}]) — Pass 2 fully rejected")

    # Secondary info — raw metrics included in audit trail but don't drive the decision
    fp_delta = p2_metrics['fp_rate'] - p1_metrics['fp_rate']
    alarm_delta = p2_metrics['alarm_count'] - p1_metrics['alarm_count']
    passed.append(
        f"METRICS_INFO fp_delta={fp_delta:+.3f} alarm_delta={alarm_delta:+d} "
        f"p1_recall={p1_metrics['recall']:.3f} p2_recall={p2_metrics['recall']:.3f}"
    )

    accepted = mode in ("FULL", "PARTIAL")
    return accepted, mode, passed, failed


def _write_change_log(
    cfg: DynamicConfig,
    p1_metrics: dict,
    p2_metrics: dict,
    accepted: bool,
    gate_mode: str,
    passed_checks: list[str],
    failed_checks: list[str],
    alarm_delta: int,
    trust_score: float = 0.5,
    trust_label: str = "UNCERTAIN",
) -> str:
    """
    Phase C.9 — Write every Pass 2 decision to threshold_change_log.json.
    Creates the file if it doesn't exist. Keeps last 200 entries.
    Returns the version_id (timestamp string) for the written entry.
    """
    version_id = datetime.now().strftime("%Y%m%d_%H%M%S_%f")

    entry = {
        "version_id":    version_id,
        "timestamp":     datetime.now().isoformat(),
        "agent_proposal": {
            "ssh_high":  cfg.ssh_high_risk_threshold,
            "web_high":  cfg.web_high_risk_threshold,
            "ftp_high":  cfg.ftp_high_risk_threshold,
            "kernel_high": cfg.kernel_high_risk_threshold,
            "session_high": cfg.session_high_risk_threshold,
            "escalate_ips": cfg.escalate_ips,
            "suppress_ips": cfg.suppress_ips,
            "rerun_engines": cfg.rerun_engines,
            "threat_level": cfg.threat_level,
            "confidence":  cfg.confidence,
            "reasoning":   (cfg.reasoning or "")[:300],
        },
        "gate_result": {
            "accepted":      accepted,
            "gate_mode":     gate_mode,      # FULL | PARTIAL | REJECTED
            "decision":      (
                "FULL_ACCEPT"    if gate_mode == "FULL"    else
                "PARTIAL_ACCEPT" if gate_mode == "PARTIAL" else
                "REVERTED_TO_PASS1"
            ),
            "trust_score":   trust_score,
            "trust_label":   trust_label,
            "passed_checks": passed_checks,
            "failed_checks": failed_checks,
        },
        "comparison": {
            "pass1_fp_rate":     p1_metrics.get("fp_rate"),
            "pass2_fp_rate":     p2_metrics.get("fp_rate"),
            "pass1_recall":      p1_metrics.get("recall"),
            "pass2_recall":      p2_metrics.get("recall"),
            "pass1_alarm_count": p1_metrics.get("alarm_count"),
            "pass2_alarm_count": p2_metrics.get("alarm_count"),
            "alarm_delta":       alarm_delta,
        },
    }

    os.makedirs(_MODELS_DIR, exist_ok=True)
    log_path = Path(CHANGE_LOG_PATH)

    existing: list[dict] = []
    if log_path.exists():
        try:
            with open(log_path, "r", encoding="utf-8") as f:
                existing = json.load(f)
            if not isinstance(existing, list):
                existing = []
        except Exception:
            existing = []

    existing.append(entry)
    existing = existing[-200:]

    with open(log_path, "w", encoding="utf-8") as f:
        json.dump(existing, f, indent=2, ensure_ascii=False)

    mode_str = {
        "FULL":     "✅ FULL ACCEPT",
        "PARTIAL":  "⚠️  PARTIAL (escalate only)",
        "REJECTED": "❌ REVERTED TO PASS 1",
    }.get(gate_mode, gate_mode)

    print(f"\n[C.9] Gate log: {mode_str} | trust={trust_score:.3f} [{trust_label}] | version={version_id}")
    if failed_checks:
        for fc in failed_checks:
            print(f"      ✗ {fc}")

    return version_id


# ── Main entry point ───────────────────────────────────────────────────────────

def detecter_anomalies(
    df_raw: pd.DataFrame,
    dynamic_config: DynamicConfig | None = None,
) -> tuple[pd.DataFrame, pd.DataFrame, list, list[dict]]:
    """
    Full hybrid detection pipeline.

    Args:
        df_raw:         Raw log DataFrame (from ingestion / transformation)
        dynamic_config: Optional agent-issued config. If None or default,
                        only Pass 1 runs (identical to v3 behavior).

    Returns:
        (df_annotated, df_anomalies, alarmes, threshold_snapshots)

        threshold_snapshots — list of threshold snapshot dicts, one per pass
        that ran. Always contains at least the Pass 1 snapshot. Contains two
        entries when Pass 2 ran. Each snapshot is a dict produced by
        _build_threshold_snapshot() and is also stamped on every alarm under
        alarm["threshold_snapshot"].
    """
    cfg = dynamic_config or DynamicConfig.default()
    print(f"\n[BRIDGE v4] Hybrid IDPS — Pass 1 (default thresholds)")

    df_norm = normalize(df_raw, verbose=True)

    # ── PASS 1: default thresholds ────────────────────────────────────────
    p1 = _run_engines(df_norm, DynamicConfig.default())

    try:
        prediction = run_prediction_engine(df_norm)
    except Exception as e:
        print(f"[BRIDGE] [PREDICTION] Failed: {type(e).__name__}: {e}")
        prediction = {"prediction_score": 0, "flags": [], "predicted_events": [], "signals": {}}

    p1_snapshot = _build_threshold_snapshot(DynamicConfig.default(), pass_number=1)
    corr_map_p1 = build_correlation_map(
        p1['risk_table'], p1['web_table'], p1['ftp_table'],
        p1['sess_result'], p1['kernel_meta'], df_norm,
        window_min=CORR_TIME_WINDOW_MIN,
    )
    alarmes_p1 = _collect_all_alarms(p1, corr_map_p1, prediction, threshold_snapshot=p1_snapshot)
    threshold_snapshots = [p1_snapshot]

    # ── PASS 2: shadow mode — results NEVER applied automatically ────────────
    # C.7: Pass 2 runs in shadow. Its alarms are stored separately.
    # C.8: A deterministic 3-check math gate decides if they replace Pass 1.
    # C.9: Every decision is written to threshold_change_log.json.
    if not cfg.is_default():
        print(f"\n[BRIDGE v5] Pass 2 SHADOW RUN (agent config: {cfg.summary()})")
        print(f"[BRIDGE v5] Reasoning: {cfg.reasoning[:120]}")
        print(f"[BRIDGE v5] Pass 2 results are NOT applied until the gate approves.")

        engines_to_rerun = cfg.rerun_engines if cfg.rerun_engines else None
        p2 = _run_engines(df_norm, cfg, engines_filter=engines_to_rerun)

        p2_snapshot = _build_threshold_snapshot(cfg, pass_number=2)
        window = cfg.correlation_window_min or CORR_TIME_WINDOW_MIN
        corr_map_p2 = build_correlation_map(
            p2['risk_table'], p2['web_table'], p2['ftp_table'],
            p2['sess_result'], p2['kernel_meta'], df_norm,
            window_min=window,
        )
        alarmes_shadow = _collect_all_alarms(p2, corr_map_p2, prediction, threshold_snapshot=p2_snapshot)
        threshold_snapshots.append(p2_snapshot)

        # ── Step 2: Compute pass metrics, read trust score, run gate ─────────
        p1_metrics = _compute_pass_metrics(alarmes_p1)
        p2_metrics = _compute_pass_metrics(alarmes_shadow)

        # Read the trust score computed in main.py after Pass 1
        # (stored in ip_profiler globals so bridge doesn't need a circular import)
        try:
            import src.ip_profiler as _prof
            trust_score = getattr(_prof, '_current_trust_score', 0.5)
            trust_label = getattr(_prof, '_current_trust_label', 'UNCERTAIN')
        except Exception:
            trust_score, trust_label = 0.5, 'UNCERTAIN'

        accepted, gate_mode, passed_checks, failed_checks = _ab_gate(
            p1_metrics, p2_metrics, trust_score, trust_label
        )

        alarm_delta = p2_metrics['alarm_count'] - p1_metrics['alarm_count']

        # ── C.9: Write audit log entry ────────────────────────────────────────
        version_id = _write_change_log(
            cfg, p1_metrics, p2_metrics,
            accepted, gate_mode, passed_checks, failed_checks, alarm_delta,
            trust_score=trust_score, trust_label=trust_label,
        )
        p2_snapshot['gate_accepted']   = accepted
        p2_snapshot['gate_mode']       = gate_mode
        p2_snapshot['gate_version_id'] = version_id
        p2_snapshot['gate_passed']     = passed_checks
        p2_snapshot['gate_failed']     = failed_checks
        p2_snapshot['trust_score']     = trust_score

        if gate_mode == "FULL":
            # High trust → apply everything: Pass 2 alarms + threshold changes
            print(f"\n[BRIDGE v5] Gate FULL ACCEPT (trust={trust_score:.3f}) — Pass 2 applied (delta={alarm_delta:+d})")
            alarmes       = alarmes_shadow
            corr_map      = corr_map_p2
            engines_final = _merge_engine_results(p1, p2)
            alarmes.append({
                'timestamp': datetime.now().isoformat(),
                'type':      'GATE_ACCEPTED',
                'ip':        'SYSTEM', 'severite': 'INFO', 'action': 'MONITOR',
                'score':     0.0, 'country': 'N/A', 'failures': 0,
                'message': (
                    f"✅ GATE FULL ACCEPT | trust={trust_score:.3f} [{trust_label}] | "
                    f"delta={alarm_delta:+d} | version={version_id} | {cfg.summary()}"
                ),
                'feature': 'ab_gate', 'domain': 'GATE', 'version_id': version_id,
                'gate_mode': gate_mode,
            })

        elif gate_mode == "PARTIAL":
            # Medium trust → apply escalate_ips only, keep Pass 1 thresholds
            print(f"\n[BRIDGE v5] Gate PARTIAL (trust={trust_score:.3f}) — escalate_ips applied, threshold changes blocked")
            alarmes       = alarmes_p1   # keep Pass 1 alarms
            corr_map      = corr_map_p1
            engines_final = p1
            # Apply only the IP escalations from Pass 2 shadow results
            if cfg.escalate_ips:
                alarmes = _apply_escalations(alarmes, cfg.escalate_ips)
                print(f"[BRIDGE v5] PARTIAL: escalated {cfg.escalate_ips}")
            alarmes.append({
                'timestamp': datetime.now().isoformat(),
                'type':      'GATE_PARTIAL',
                'ip':        'SYSTEM', 'severite': 'INFO', 'action': 'MONITOR',
                'score':     0.0, 'country': 'N/A', 'failures': 0,
                'message': (
                    f"⚠️ GATE PARTIAL | trust={trust_score:.3f} [{trust_label}] | "
                    f"escalate_ips={cfg.escalate_ips} applied | threshold changes blocked | "
                    f"version={version_id}"
                ),
                'feature': 'ab_gate', 'domain': 'GATE', 'version_id': version_id,
                'gate_mode': gate_mode,
            })

        else:
            # Low trust → reject everything, revert to Pass 1
            print(f"\n[BRIDGE v5] Gate REJECTED (trust={trust_score:.3f} < 0.50) — reverting to Pass 1")
            alarmes       = alarmes_p1
            corr_map      = corr_map_p1
            engines_final = p1
            alarmes.append({
                'timestamp': datetime.now().isoformat(),
                'type':      'GATE_REJECTED',
                'ip':        'SYSTEM', 'severite': 'INFO', 'action': 'MONITOR',
                'score':     0.0, 'country': 'N/A', 'failures': 0,
                'message': (
                    f"❌ GATE REJECTED | trust={trust_score:.3f} [{trust_label}] | "
                    f"Pass 2 fully reverted | version={version_id}"
                ),
                'feature': 'ab_gate', 'domain': 'GATE', 'version_id': version_id,
                'gate_mode': gate_mode,
            })
    else:
        print("[BRIDGE v5] No agent config overrides — single pass only")
        alarmes       = alarmes_p1
        corr_map      = corr_map_p1
        engines_final = p1

    # ── Force-escalate / suppress — only for FULL gate acceptance ────────────
    # PARTIAL mode already applied escalate_ips inside the gate block above.
    # REJECTED mode ignores all agent decisions.
    # Single-pass sessions (no Pass 2) still honour these if set.
    _gate_mode = locals().get('gate_mode', 'NONE')   # 'NONE' = Pass 2 didn't run

    if cfg.escalate_ips and _gate_mode in ('FULL', 'NONE'):
        alarmes = _apply_escalations(alarmes, cfg.escalate_ips)
        print(f"[BRIDGE v5] Force-escalated: {cfg.escalate_ips}")

    if cfg.suppress_ips and _gate_mode in ('FULL', 'NONE'):
        alarmes = [a for a in alarmes if _clean_ip(a.get('ip')) not in cfg.suppress_ips]
        print(f"[BRIDGE v5] Suppressed: {cfg.suppress_ips}")

    alarmes = _apply_correlation_bonus(alarmes)
    alarmes.sort(key=lambda a: a.get('score', 0), reverse=True)

    df_anomalies = _build_unified_anomalies(
        engines_final['risk_table'], engines_final['web_table'],
        engines_final['ftp_table'], engines_final['kernel_meta'], corr_map,
    )
    df_annotated = _annotate_df_unified(
        df_raw, engines_final['risk_table'],
        engines_final['web_table'], engines_final['ftp_table'],
    )

    perf = (
        get_model_performance(engines_final['risk_table'])
        if engines_final.get('risk_table') is not None
        and not engines_final['risk_table'].empty
        else {}
    )

    chain_hits = [a for a in alarmes if a.get('domain') == 'CHAIN']
    multi_vec  = [i for i in corr_map.values() if i['vector_count'] >= 2]

    # ── A.2: False positive score (isolated anomaly rate) ─────────────────────
    # fp_score = alarms flagged by only 1 model / total alarms
    # High value → models disagree → low reliability → used by Phase D gate
    real_alarmes = [a for a in alarmes if a.get('ip', 'SYSTEM') != 'SYSTEM']
    total_alarms = len(real_alarmes)
    isolated     = [a for a in real_alarmes
                    if a.get('models_agreed', 4) <= 1 or a.get('agreement_label') == 'LOW']
    fp_score     = round(len(isolated) / max(total_alarms, 1), 4)

    # Attach fp_score + session agreement to each alarm for downstream use
    session_agreement = (
        sum(a.get('model_agreement', 1.0) for a in real_alarmes) / max(total_alarms, 1)
    )
    for a in alarmes:
        if 'fp_score_session' not in a:
            a['fp_score_session'] = fp_score

    print(f"\n[A.2] Session FP score (isolated anomaly rate): {fp_score:.3f} "
          f"({len(isolated)}/{total_alarms} alarms flagged by only 1 model)")

    print(f"\n[BRIDGE v5] Summary:")
    print(f"  Unified anomaly rows : {len(df_anomalies)}")
    print(f"  Alarms generated     : {len(alarmes)}")
    print(f"  Correlated incidents : {len(multi_vec)}")
    print(f"  Attack chains        : {len(chain_hits)}")
    print(f"  Model agreement avg  : {session_agreement:.3f}")
    print(f"  FP score (isolated)  : {fp_score:.3f}")
    gate_info = "Pass 1 only (no overrides)"
    if len(threshold_snapshots) > 1:
        snap2    = threshold_snapshots[1]
        gmode    = snap2.get('gate_mode', '?')
        gtrust   = snap2.get('trust_score', '?')
        gate_info = f"Pass 2 gate={gmode} trust={gtrust}"
    print(f"  Gate decision        : {gate_info}")
    print(f"  Threshold passes     : {len(threshold_snapshots)}")
    for snap in threshold_snapshots:
        print(f"    Pass {snap['pass']} ({snap['issued_by']}): "
              f"SSH≥{snap['ssh_high']} WEB≥{snap['web_high']} "
              f"FTP≥{snap['ftp_high']} KERNEL≥{snap['kernel_high']}")
    if perf:
        print(f"  SSH IPs analyzed     : {perf.get('total_ips', 0)}")
        print(f"  SSH blocked          : {perf.get('blocked_ips', 0)}")

    # Attach session-level A.1+A.2 metrics to threshold_snapshots[0] for JSONL
    if threshold_snapshots:
        threshold_snapshots[0]['session_model_agreement'] = round(session_agreement, 4)
        threshold_snapshots[0]['session_fp_score']        = fp_score
        threshold_snapshots[0]['session_alarm_count']     = total_alarms

    return df_annotated, df_anomalies, alarmes, threshold_snapshots


# ── Pass merging helpers ───────────────────────────────────────────────────────

def _merge_passes(
    alarmes_p1: list[dict],
    alarmes_p2: list[dict],
    cfg: DynamicConfig,
) -> list[dict]:
    """
    Merges Pass 1 and Pass 2 alarms.
    Strategy: per IP+type combination, keep the entry with the higher score.
    This ensures the agent's adjusted thresholds can only RAISE sensitivity,
    never silently drop alarms that Pass 1 already found.
    """
    # Index Pass 1 by (ip, type)
    p1_index: dict[tuple, dict] = {}
    for a in alarmes_p1:
        key = (_clean_ip(a.get('ip')), a.get('type', ''))
        if key not in p1_index or a.get('score', 0) > p1_index[key].get('score', 0):
            p1_index[key] = a

    merged = dict(p1_index)  # start with all Pass 1 alarms

    for a in alarmes_p2:
        key = (_clean_ip(a.get('ip')), a.get('type', ''))
        if key not in merged or a.get('score', 0) > merged[key].get('score', 0):
            a['source_pass'] = 'pass2_agent_adjusted'
            merged[key] = a

    result = list(merged.values())

    # Add a meta-alarm explaining what the agent changed (for audit trail)
    if cfg.reasoning:
        result.append({
            'timestamp': datetime.now().isoformat(),
            'type':      'AGENT_CONFIG_APPLIED',
            'ip':        'SYSTEM',
            'severite':  'INFO',
            'action':    'MONITOR',
            'score':     0.0,
            'country':   'N/A',
            'failures':  0,
            'message': (
                f"🤖 HYBRID PASS | Agent config applied | "
                f"Threat level: {cfg.threat_level} | "
                f"Config: {cfg.summary()} | "
                f"Confidence: {cfg.confidence:.0%} | "
                f"Reasoning: {cfg.reasoning[:150]}"
            ),
            'feature': 'hybrid_config',
            'valeur':   0.0,
            'seuil':    0.0,
            'domain':   'HYBRID',
        })

    return result


def _merge_engine_results(p1: dict, p2: dict) -> dict:
    """
    Merges engine DataFrames from Pass 1 and Pass 2.
    For each engine, concatenates and deduplicates by IP, keeping highest score.
    """
    merged = {}
    for key in ('risk_table', 'web_table', 'ftp_table'):
        t1 = p1.get(key)
        t2 = p2.get(key)
        if t1 is None or (hasattr(t1, 'empty') and t1.empty):
            merged[key] = t2
        elif t2 is None or (hasattr(t2, 'empty') and t2.empty):
            merged[key] = t1
        else:
            combined = pd.concat([t1, t2], ignore_index=True)
            if 'source_ip' in combined.columns and 'weighted_risk_score' in combined.columns:
                combined = (
                    combined.sort_values('weighted_risk_score', ascending=False)
                    .drop_duplicates(subset=['source_ip'], keep='first')
                    .reset_index(drop=True)
                )
            merged[key] = combined

    # For dict results (kernel, session) keep the one with higher score
    for key in ('kernel_meta', 'sess_result'):
        k1 = p1.get(key, {})
        k2 = p2.get(key, {})
        s1 = k1.get('weighted_risk_score', 0) if isinstance(k1, dict) else 0
        s2 = k2.get('weighted_risk_score', 0) if isinstance(k2, dict) else 0
        merged[key] = k1 if s1 >= s2 else k2

    return merged


def _merge_corr_maps(m1: dict, m2: dict) -> dict:
    """Merges two correlation maps, keeping the highest combined_score per window."""
    merged = dict(m1)
    for key, info in m2.items():
        if key not in merged or info['combined_score'] > merged[key]['combined_score']:
            merged[key] = info
    return merged


def _apply_escalations(alarmes: list[dict], escalate_ips: list[str]) -> list[dict]:
    """
    Force-elevates any alarm whose IP is in escalate_ips to CRITIQUE / BLOCK_24H.
    Adds a note explaining the agent escalation.
    """
    for a in alarmes:
        if _clean_ip(a.get('ip')) in escalate_ips:
            a['severite'] = 'CRITIQUE'
            a['action']   = 'BLOCK_24H'
            a['score']    = min(100.0, float(a.get('score', 0)) + 20.0)
            msg = a.get('message', '')
            if '[AGENT ESCALATED]' not in msg:
                a['message'] = msg + ' [AGENT ESCALATED]'
    return alarmes


# ── Alarm collector (internal) ─────────────────────────────────────────────────

def _collect_all_alarms(
    engines: dict[str, Any],
    corr_map: dict,
    prediction: dict,
    threshold_snapshot: dict | None = None,
) -> list[dict]:
    """
    Builds the full alarm list from a single set of engine outputs.
    Each alarm receives a 'threshold_snapshot' dict recording which
    thresholds were active when it was produced — enables end-to-end audit.
    """
    alarmes: list[dict] = []

    risk_table  = engines.get('risk_table')
    web_table   = engines.get('web_table', pd.DataFrame())
    ftp_table   = engines.get('ftp_table', pd.DataFrame())
    sess_result = engines.get('sess_result', {})
    kernel_meta = engines.get('kernel_meta', {})

    if risk_table is not None and not risk_table.empty:
        alarmes.extend(_build_ssh_alarmes(risk_table, corr_map))

    if not web_table.empty:
        alarmes.extend(_alarms_from_risk_table(web_table, domain='WEB', corr_map=corr_map))

    alarmes.extend(_alarms_from_session(sess_result))

    if not ftp_table.empty:
        alarmes.extend(_alarms_from_risk_table(ftp_table, domain='FTP', corr_map=corr_map))

    alarmes.extend(_alarms_from_kernel(kernel_meta))
    alarmes.extend(_build_correlation_alarms(corr_map))
    alarmes.extend(_build_chain_alarms(corr_map))
    alarmes.extend(_build_prediction_alarms(prediction, risk_table, ftp_table))

    # Stamp every alarm with the threshold snapshot for full auditability
    if threshold_snapshot:
        for a in alarmes:
            a.setdefault("threshold_snapshot", threshold_snapshot)

    # Fix 2: Bridge alarms come from multi-engine consensus — treat as high agreement.
    # anomaly_detection.py sets models_agreed per-IP from the C2 vote matrix.
    # Bridge alarms don't have that, so we default to 4/4 (all engines that fired agree).
    # This prevents model_agreement from being 0.000 in the trust score.
    for a in alarmes:
        a.setdefault("models_agreed",   4)
        a.setdefault("model_agreement", 1.0)
        a.setdefault("agreement_label", "HIGH")
        a.setdefault("fp_score_session", 0.0)

    return alarmes


# ── Correlation map ────────────────────────────────────────────────────────────

def build_correlation_map(
    risk_table: pd.DataFrame,
    web_table: pd.DataFrame,
    ftp_table: pd.DataFrame,
    sess_result: dict,
    kernel_meta: dict,
    df_norm: pd.DataFrame,
    window_min: float = CORR_TIME_WINDOW_MIN,
) -> dict[str, dict]:
    raw_findings: dict[str, list[dict]] = defaultdict(list)

    def _collect(df: pd.DataFrame, vector: str,
                 ip_col='source_ip', score_col='weighted_risk_score',
                 ts_col_first='first_seen', ts_col_last='last_seen'):
        if df is None or df.empty:
            return
        for _, row in df.iterrows():
            ip = _clean_ip(row.get(ip_col))
            if not _is_usable_ip(ip):
                continue
            ts_first = _parse_ts(row.get(ts_col_first))
            ts_last  = _parse_ts(row.get(ts_col_last))
            anchor   = ts_first or ts_last or datetime.now()
            raw_findings[ip].append({
                'vector': vector,
                'score':  float(row.get(score_col, 0)),
                'ts':     anchor,
                'detail': row.to_dict(),
            })

    _collect(risk_table, 'SSH')
    _collect(web_table,  'WEB')
    _collect(ftp_table,  'FTP')

    for alarm in sess_result.get('alarms', []):
        ip = _clean_ip(alarm.get('ip'))
        if _is_usable_ip(ip):
            ts = _parse_ts(alarm.get('timestamp')) or datetime.now()
            raw_findings[ip].append({
                'vector': 'SESSION',
                'score':  float(alarm.get('score', 50)),
                'ts':     ts,
                'detail': alarm,
            })

    def _window_bucket(ts: datetime) -> str:
        bucket_min = (ts.minute // int(window_min)) * int(window_min)
        return ts.replace(minute=bucket_min, second=0, microsecond=0).isoformat()

    incident_findings: dict[str, list[dict]] = defaultdict(list)
    for ip, findings in raw_findings.items():
        findings.sort(key=lambda f: f['ts'])
        window_anchor: datetime | None = None
        current_key: str | None = None
        for f in findings:
            ts = f['ts']
            if window_anchor is None or not _same_time_window(window_anchor, ts, window_min):
                window_anchor = ts
                current_key   = f"{ip}::{_window_bucket(ts)}"
            incident_findings[current_key].append({**f, 'ip': ip})

    corr_map: dict[str, dict] = {}
    for incident_key, findings in incident_findings.items():
        ip        = findings[0]['ip']
        vectors   = list(dict.fromkeys(f['vector'] for f in findings))
        max_score = max(f['score'] for f in findings)
        combo_bonus = _compute_combo_bonus(vectors)
        combined  = min(100.0, max_score + combo_bonus)
        ts_list   = [f['ts'] for f in findings if f['ts'] is not None]
        first_ts  = min(ts_list) if ts_list else None
        last_ts   = max(ts_list) if ts_list else None
        corr_map[incident_key] = {
            'ip':              ip,
            'window_key':      incident_key,
            'vectors':         vectors,
            'vector_count':    len(vectors),
            'chain_sequence':  vectors,
            'max_score':       round(max_score, 2),
            'combo_bonus':     round(combo_bonus, 2),
            'combined_score':  round(combined, 2),
            'first_seen':      first_ts,
            'last_seen':       last_ts,
            'is_multi_vector': len(vectors) >= 2,
            'details':         {f['vector']: f['detail'] for f in findings},
        }

    return corr_map


def _compute_combo_bonus(vectors: list[str]) -> float:
    if len(vectors) < 2:
        return 0.0
    vset = set(vectors)
    if len(vset) == 2:
        return COMBO_WEIGHTS.get(frozenset(vset), 15.0)
    max_pair_bonus = 0.0
    vec_list = list(vset)
    for i in range(len(vec_list)):
        for j in range(i + 1, len(vec_list)):
            bonus = COMBO_WEIGHTS.get(frozenset({vec_list[i], vec_list[j]}), 15.0)
            if bonus > max_pair_bonus:
                max_pair_bonus = bonus
    return round(max_pair_bonus * THREE_VECTOR_MULTIPLIER, 2)


# ── Attack chain detection ─────────────────────────────────────────────────────

def _build_chain_alarms(corr_map: dict[str, dict]) -> list[dict]:
    alarms = []
    for incident_key, info in corr_map.items():
        if info['vector_count'] < 2:
            continue
        sequence = info['chain_sequence']
        ip       = info['ip']
        matched  = [c for c in ATTACK_CHAINS if _is_subsequence(c['steps'], sequence)]
        if not matched:
            continue
        best = max(matched, key=lambda c: c['score'])
        chain_score = min(100.0, max(best['score'], info['combined_score']))
        time_range = ''
        if info['first_seen'] and info['last_seen']:
            fmt = '%H:%M'
            time_range = (
                f" | Window: {info['first_seen'].strftime(fmt)}"
                f"–{info['last_seen'].strftime(fmt)}"
            )
        alarms.append({
            'timestamp':      datetime.now().isoformat(),
            'type':           best['name'],
            'ip':             ip,
            'severite':       best['severity'],
            'action':         'BLOCK_24H',
            'score':          chain_score,
            'country':        info['details'].get('SSH', {}).get('country', 'Unknown'),
            'failures':       0,
            'message': (
                f"{best['label']} | IP: {ip} | "
                f"Sequence: {' → '.join(sequence)}{time_range} | "
                f"Risk: {chain_score:.1f}/100"
            ),
            'feature':        'attack_chain',
            'valeur':         chain_score,
            'seuil':          HIGH_RISK_THRESHOLD,
            'domain':         'CHAIN',
            'chain_name':     best['name'],
            'chain_sequence': sequence,
            'all_chains':     [c['name'] for c in matched],
        })
    return alarms


def _is_subsequence(pattern: list[str], sequence: list[str]) -> bool:
    it = iter(sequence)
    return all(step in it for step in pattern)


# ── Correlation alarms ─────────────────────────────────────────────────────────

def _build_correlation_alarms(corr_map: dict[str, dict]) -> list[dict]:
    alarms = []
    for incident_key, info in corr_map.items():
        if info['vector_count'] < 2:
            continue
        vectors = ', '.join(info['vectors'])
        score   = info['combined_score']
        bonus   = info['combo_bonus']
        time_note = ''
        if info['first_seen']:
            time_note = f" | At: {info['first_seen'].strftime('%H:%M')}"
        alarms.append({
            'timestamp': datetime.now().isoformat(),
            'type':      'CROSS_PROTOCOL_ATTACK',
            'ip':        info['ip'],
            'severite':  'CRITIQUE' if score >= HIGH_RISK_THRESHOLD else 'AVERTISSEMENT',
            'action':    'BLOCK_24H' if score >= HIGH_RISK_THRESHOLD else 'WATCHLIST_30MIN',
            'score':     score,
            'country':   info['details'].get('SSH', {}).get('country', 'Unknown'),
            'failures':  0,
            'message': (
                f"🔴 MULTI-VECTOR ATTACK | IP: {info['ip']} | "
                f"Protocols: {vectors}{time_note} | "
                f"Combined risk: {score:.1f}/100 | Combo bonus: +{bonus:.0f}pts"
            ),
            'feature':     'cross_protocol_correlation',
            'valeur':      score,
            'seuil':       MED_RISK_THRESHOLD,
            'domain':      'CORRELATION',
            'vectors':     info['vectors'],
            'combo_bonus': bonus,
            'window_key':  incident_key,
        })
    return alarms


# ── Engine-specific alarm builders ────────────────────────────────────────────

def _resolve_score_for_ip(ip: str, base_score: float, corr_map: dict) -> float:
    best = base_score
    for info in corr_map.values():
        if info['ip'] == ip and info['vector_count'] >= 2:
            best = max(best, info['combined_score'])
    return best


def _build_ssh_alarmes(risk_table: pd.DataFrame, corr_map: dict) -> list:
    alarmes = []
    for _, row in risk_table.iterrows():
        action = row['action']
        if action == 'MONITOR':
            continue
        ip       = _clean_ip(row.get('source_ip'))
        score    = float(row['weighted_risk_score'])
        severite = 'CRITIQUE' if action == 'BLOCK_24H' else 'AVERTISSEMENT'
        type_a   = _classify_ssh_alarm(row)
        message  = _build_ssh_message(row, type_a)
        corr_score = _resolve_score_for_ip(ip, score, corr_map)
        if corr_score > score:
            score    = corr_score
            severite = 'CRITIQUE'
        alarmes.append({
            'timestamp': datetime.now().isoformat(),
            'type':      type_a,
            'ip':        ip,
            'severite':  severite,
            'action':    action,
            'score':     round(score, 2),
            'country':   row.get('country', 'Unknown'),
            'failures':  int(row.get('total_failures', 0)),
            'message':   message,
            'feature':   'weighted_risk_score',
            'valeur':    score,
            'seuil':     float(HIGH_RISK_THRESHOLD),
            'domain':    'SSH',
        })
    return alarmes


def _alarms_from_risk_table(table: pd.DataFrame, domain: str, corr_map: dict) -> list:
    alarmes = []
    for _, row in table.iterrows():
        action = row.get('action', 'MONITOR')
        if action == 'MONITOR':
            continue
        ip    = _clean_ip(row.get('source_ip'))
        score = float(row.get('weighted_risk_score', 0))
        score = _resolve_score_for_ip(ip, score, corr_map)
        alarmes.append({
            'timestamp': datetime.now().isoformat(),
            'type':      f"{domain}_ATTACK",
            'ip':        ip,
            'severite':  'CRITIQUE' if action == 'BLOCK_24H' else 'AVERTISSEMENT',
            'action':    action,
            'score':     round(score, 2),
            'country':   row.get('country', 'Unknown'),
            'failures':  int(row.get('total_failures', row.get('total_requests', 0))),
            'message':   f"⚠️ {domain} ATTACK | IP: {ip} | Risk: {score:.1f}/100 | {action}",
            'feature':   'weighted_risk_score',
            'valeur':    score,
            'seuil':     float(HIGH_RISK_THRESHOLD),
            'domain':    domain,
        })
    return alarmes


def _alarms_from_session(sess_result: dict) -> list:
    alarmes = []
    for alarm in sess_result.get('alarms', []):
        alarmes.append({
            'timestamp': datetime.now().isoformat(),
            'type':      alarm.get('type', 'SESSION_ANOMALY'),
            'ip':        _clean_ip(alarm.get('ip')),
            'severite':  alarm.get('severite', 'AVERTISSEMENT'),
            'action':    'BLOCK_24H' if alarm.get('score', 0) >= HIGH_RISK_THRESHOLD else 'WATCHLIST_30MIN',
            'score':     float(alarm.get('score', 0)),
            'country':   'local',
            'failures':  0,
            'message':   alarm.get('message', ''),
            'feature':   'session_score',
            'valeur':    float(alarm.get('score', 0)),
            'seuil':     60.0,
            'domain':    'SESSION',
        })
    return alarmes


def _alarms_from_kernel(kernel_meta: dict) -> list:
    alarmes = []
    for alarm in kernel_meta.get('alarms', []):
        alarmes.append({
            'timestamp': datetime.now().isoformat(),
            'type':      alarm.get('type', 'KERNEL_ANOMALY'),
            'ip':        'SYSTEM',
            'severite':  alarm.get('severite', 'AVERTISSEMENT'),
            'action':    'ESCALATE',
            'score':     float(alarm.get('score', 0)),
            'country':   'N/A',
            'failures':  0,
            'message':   alarm.get('message', ''),
            'feature':   'kernel_risk_score',
            'valeur':    float(alarm.get('score', 0)),
            'seuil':     50.0,
            'domain':    'KERNEL',
        })
    return alarmes


def _build_prediction_alarms(prediction: dict, risk_table, ftp_table) -> list:
    alarmes = []
    pred_score  = int(prediction.get("prediction_score", 0) or 0)
    pred_flags  = list(prediction.get("flags", []) or [])
    pred_events = list(prediction.get("predicted_events", []) or [])
    if pred_score < 12:
        return alarmes
    action = ("PREEMPTIVE_BLOCK" if pred_score >= 30 else
              "TRAFFIC_THROTTLE" if pred_score >= 20 else "ALERT_HIGH_PRIORITY")
    alarmes.append({
        'timestamp': datetime.now().isoformat(),
        'type':      'PRE_ATTACK_ALERT',
        'ip':        'GLOBAL',
        'severite':  'AVERTISSEMENT',
        'action':    action,
        'score':     float(pred_score),
        'country':   'N/A',
        'failures':  0,
        'message': (
            f"🛡️ PRE-ATTACK FORECAST | Score: {pred_score}/100 | "
            f"Flags: {', '.join(pred_flags) or 'none'} | "
            f"Next: {', '.join(pred_events) or 'n/a'}"
        ),
        'feature': 'prediction_score',
        'valeur':  float(pred_score),
        'seuil':   12.0,
        'domain':  'PREDICTION',
    })
    return alarmes


def _apply_correlation_bonus(alarmes: list) -> list:
    ip_domains: dict[str, set] = defaultdict(set)
    for a in alarmes:
        ip = a.get('ip', '')
        if _is_usable_ip(ip):
            ip_domains[ip].add(a.get('domain', ''))
    for a in alarmes:
        ip = a.get('ip', '')
        if _is_usable_ip(ip) and len(ip_domains.get(ip, set())) >= 2:
            a['score']    = min(100.0, float(a.get('score', 0)) + 10.0)
            a['severite'] = 'CRITIQUE'
            existing_msg  = a.get('message', '')
            if '[CORR]' not in existing_msg:
                a['message'] = existing_msg + f" [CORR +10pts: {len(ip_domains[ip])} domains]"
    return alarmes


# ── Unified anomaly table + annotation ────────────────────────────────────────

def _build_unified_anomalies(
    risk_table, web_table, ftp_table, kernel_meta, corr_map
) -> pd.DataFrame:
    parts = []
    if risk_table is not None and not risk_table.empty:
        t = risk_table[risk_table['action'] != 'MONITOR'].copy()
        if not t.empty:
            t['engine'] = 'ssh_ml'
            parts.append(t)
    if web_table is not None and not web_table.empty:
        t = web_table[web_table['action'] != 'MONITOR'].copy()
        if not t.empty:
            t['engine'] = 'web'
            parts.append(t)
    if ftp_table is not None and not ftp_table.empty:
        t = ftp_table[ftp_table['action'] != 'MONITOR'].copy()
        if not t.empty:
            t['engine'] = 'ftp'
            parts.append(t)
    if kernel_meta and kernel_meta.get('action') not in (None, 'MONITOR'):
        parts.append(pd.DataFrame([{
            'source_ip':           'SYSTEM',
            'weighted_risk_score': kernel_meta.get('weighted_risk_score', 0),
            'action':              kernel_meta.get('action'),
            'engine':              'kernel',
            'risk_level':          kernel_meta.get('status'),
        }]))
    if not parts:
        return pd.DataFrame()
    result = pd.concat(parts, ignore_index=True, sort=False)
    if 'source_ip' in result.columns:
        def _best_corr(ip: str) -> dict:
            candidates = [v for v in corr_map.values() if v['ip'] == str(ip)]
            return max(candidates, key=lambda c: c['combined_score']) if candidates else {}
        result['is_multi_vector'] = result['source_ip'].apply(
            lambda ip: any(v['ip'] == str(ip) and v['is_multi_vector'] for v in corr_map.values())
        )
        result['attack_vectors']   = result['source_ip'].apply(
            lambda ip: ', '.join(_best_corr(ip).get('vectors', []))
        )
        result['correlated_score'] = result['source_ip'].apply(
            lambda ip: _best_corr(ip).get('combined_score',
                result.loc[result['source_ip'] == ip, 'weighted_risk_score'].max()
                if not result.empty else 0)
        )
        result['chain_sequence'] = result['source_ip'].apply(
            lambda ip: ' → '.join(_best_corr(ip).get('chain_sequence', []))
        )
    return result


def _annotate_df_unified(df_raw, risk_table, web_table, ftp_table) -> pd.DataFrame:
    df = df_raw.copy()
    score_map: dict[str, float] = {}
    if risk_table is not None and not risk_table.empty:
        for _, r in risk_table.iterrows():
            ip = str(r['source_ip'])
            score_map[ip] = max(score_map.get(ip, 0), float(r['weighted_risk_score']))
    for tbl in (web_table, ftp_table):
        if tbl is None or tbl.empty:
            continue
        for _, r in tbl.iterrows():
            ip = str(r.get('source_ip', ''))
            if ip:
                score_map[ip] = max(score_map.get(ip, 0), float(r.get('weighted_risk_score', 0)))
    ip_col = next(
        (c for c in df.columns if 'ip' in c.lower() or c.lower() == 'ip_source'), None
    )
    if ip_col:
        df['weighted_risk_score'] = df[ip_col].map(
            lambda x: score_map.get(str(x), 0.0) if pd.notna(x) else 0.0
        )
        df['anomalie'] = df['weighted_risk_score'].apply(
            lambda s: -1 if s >= MED_RISK_THRESHOLD else 1
        )
    else:
        mx = max(score_map.values()) if score_map else 0.0
        df['weighted_risk_score'] = mx
        df['anomalie'] = -1 if mx >= MED_RISK_THRESHOLD else 1
    return df


# ── SSH alarm helpers ──────────────────────────────────────────────────────────

def _classify_ssh_alarm(row: pd.Series) -> str:
    scores = {
        'BRUTE-FORCE SSH': row.get('failed_rate_score', 0),
        'SWARM ATTACK':    row.get('swarm_detection_score', 0),
        'BOTNET':          row.get('botnet_aggregation_score', 0),
        'KNOWN BAD IP':    row.get('ip_reputation_score_l8', 0),
        'GEO SUSPICIOUS':  row.get('geo_risk_score', 0),
    }
    return max(scores, key=scores.get)


def _build_ssh_message(row: pd.Series, type_a: str) -> str:
    ip      = row['source_ip']
    score   = row['weighted_risk_score']
    action  = row['action']
    country = row.get('country', 'Unknown')
    fails   = int(row.get('total_failures', 0))
    if 'BRUTE' in type_a or 'SSH' in type_a:
        return (f"🔴 BRUTE-FORCE SSH | IP: {ip} | Country: {country} | "
                f"{fails} failures | Risk: {score:.1f}/100 | {action}")
    if 'SWARM' in type_a:
        return (f"🔴 SWARM ATTACK | IP: {ip} | Coordinated multi-IP | "
                f"Risk: {score:.1f}/100 | {action}")
    if 'BOTNET' in type_a:
        return f"🟠 BOTNET | IP: {ip} | Country: {country} | Risk: {score:.1f}/100 | {action}"
    if 'KNOWN' in type_a:
        return f"🔴 KNOWN MALICIOUS IP | IP: {ip} | Risk: {score:.1f}/100 | {action}"
    return f"⚠️ SUSPICIOUS | IP: {ip} | Country: {country} | Risk: {score:.1f}/100 | {action}"


# ── Agent input builder ────────────────────────────────────────────────────────

def get_agent_inputs(alarmes: list, df_anomalies: pd.DataFrame) -> dict:
    critiques = [a for a in alarmes if a.get('severite') == 'CRITIQUE']
    critiques_valides = [a for a in critiques if _is_usable_ip(a.get('ip'))]
    top_alarm     = critiques_valides[0] if critiques_valides else (critiques[0] if critiques else None)
    ip_principale = _clean_ip(top_alarm.get('ip')) if top_alarm else 'N/A'

    # ── Compact alarm summary — hard-capped at 200 chars ─────────────────
    # This replaces the full alarmes_json dump which could be 2000+ tokens.
    # Each entry: IP(score, TYPE) — enough for the agent to reason on.
    if critiques:
        src = critiques_valides[:3] if critiques_valides else critiques[:3]
        parts = [
            f"{_clean_ip(a.get('ip'))}({a.get('failures', a.get('valeur', 0))},{a['type']})"
            for a in src
        ]
        alarmes_resumees = ', '.join(parts)
        if len(df_anomalies) > 3:
            alarmes_resumees += f" +{len(df_anomalies)} total"
    else:
        alarmes_resumees = "No critical alarms"

    # Hard cap — prevents prompt blowup when many IPs are involved
    if len(alarmes_resumees) > 200:
        alarmes_resumees = alarmes_resumees[:197] + "..."

    corr_count  = 0
    chain_count = len([a for a in alarmes if a.get('domain') == 'CHAIN'])
    if not df_anomalies.empty and 'is_multi_vector' in df_anomalies.columns:
        corr_count = int(df_anomalies['is_multi_vector'].sum())

    return {
        'nb_anomalies':      str(len(df_anomalies)),
        'ip_principale':     ip_principale,
        'alarmes_resumees':  alarmes_resumees,
        'corr_incidents':    str(corr_count),
        'chain_incidents':   str(chain_count),
    }


def reentralner_avec_nouveaux_logs(df: pd.DataFrame):
    print("[BRIDGE v4] ml_engine retrains automatically on each run.")
    return None, None