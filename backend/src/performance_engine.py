"""
performance_engine.py — Phase B: Trust Score Engine
═══════════════════════════════════════════════════════════════════════════════
Single public function:

    compute_trust(session_data, alarmes, threshold_snapshots) → dict

Takes all Phase A outputs as inputs and collapses them into 5 numbers that
answer the question: "how well is our IDPS working right now?"

Output:
    {
        "trust_score":             0.91,   # unified trust score 0–1 (= confidence_in_metrics)
        "status":                  "TRUSTWORTHY",   # label for dashboard
        "risk_of_false_decision":  "LOW",  # HIGH / MEDIUM / LOW
        "model_agreement":         0.87,   # avg agreement of IF/LOF/SVM/DBSCAN
        "false_positive_rate":     0.33,   # fraction of alarms with only 1 model
        "drift_score":             0.031,  # abs change in anomaly rate vs last session
        "stability":               "HIGH", # HIGH / MEDIUM / LOW — session consistency
        "confidence_in_metrics":   0.91,   # same as trust_score (backward compat)
        "confidence_label":        "TRUSTWORTHY",   # same as status (backward compat)
        "signals_summary":         "...",  # human-readable one-liner
    }

Inputs come from:
    A.1 → model_agreement, false_positive_rate  (from threshold_snapshots[0])
    A.3 → drift_score, drift_label              (from session_data / metrics_summary)
    A.4 → stability, stable_signals             (from session_data / metrics_summary)
    Ph0 → noise_ratio, ml_score_weight          (from session_data / pipeline_start)

The confidence_in_metrics score is a weighted combination:
    0.35 × model_agreement
    0.25 × (1 - false_positive_rate)
    0.20 × (1 - drift_score capped at 0.30)
    0.20 × stability_score (HIGH=1.0, MEDIUM=0.6, LOW=0.2)

Pure math — no LLM, no randomness. Same inputs always produce the same output.
═══════════════════════════════════════════════════════════════════════════════
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("performance_engine")
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("[performance_engine] %(levelname)s %(message)s"))
    logger.addHandler(_h)
logger.setLevel(logging.INFO)

# ── Weight constants (must sum to 1.0) ────────────────────────────────────────
W_MODEL_AGREEMENT = 0.35
W_FP_RATE         = 0.25
W_DRIFT           = 0.20
W_STABILITY       = 0.20

# ── Stability label → numeric score ───────────────────────────────────────────
_STABILITY_SCORE = {"HIGH": 1.0, "MEDIUM": 0.6, "LOW": 0.2}

# ── Confidence thresholds for label ───────────────────────────────────────────
_CONFIDENCE_LABELS = [
    (0.85, "TRUSTWORTHY"),
    (0.65, "ACCEPTABLE"),
    (0.45, "UNCERTAIN"),
    (0.0,  "UNRELIABLE"),
]


def _extract_model_agreement(
    alarmes: list[dict],
    threshold_snapshots: list[dict],
) -> float:
    """
    Pull model_agreement from the best available source.
    Priority: threshold_snapshots[0] (written by A.2 in bridge)
              → alarm-level averages (written by A.1 in anomaly_detection)
              → fallback 1.0 (no data = assume clean)
    """
    # Source 1: bridge attaches session_model_agreement to snapshot
    if threshold_snapshots:
        snap = threshold_snapshots[0]
        v = snap.get("session_model_agreement")
        if v is not None:
            return float(v)

    # Source 2: average over individual alarm dicts (A.1 field)
    agreements = [
        float(a["model_agreement"])
        for a in alarmes
        if isinstance(a, dict) and "model_agreement" in a
    ]
    if agreements:
        return round(sum(agreements) / len(agreements), 4)

    return 1.0  # no anomalies flagged → full agreement by default


def _extract_fp_rate(
    alarmes: list[dict],
    threshold_snapshots: list[dict],
) -> float:
    """
    Pull the session FP score (isolated anomaly rate).
    Priority: threshold_snapshots[0].session_fp_score (A.2)
              → individual alarm fp_score_session fields
              → 0.0 fallback
    """
    if threshold_snapshots:
        snap = threshold_snapshots[0]
        v = snap.get("session_fp_score")
        if v is not None:
            return float(v)

    fp_scores = [
        float(a["fp_score_session"])
        for a in alarmes
        if isinstance(a, dict) and "fp_score_session" in a
    ]
    if fp_scores:
        return float(fp_scores[0])  # all alarms carry the same session value

    return 0.0


def _extract_drift(session_data: dict) -> tuple[float, str, bool]:
    """
    Pull drift_score, drift_label, drift_flagged from metrics_summary.
    Returns (score, label, flagged).
    """
    score   = float(session_data.get("drift_score",   0.0))
    label   = str(session_data.get("drift_label",     "STABLE"))
    flagged = bool(session_data.get("drift_flagged",  False))
    return score, label, flagged


def _extract_stability(session_data: dict) -> tuple[str, int]:
    """
    Pull stability confidence and stable_signals count from metrics_summary.
    Returns (confidence_label, stable_signals_count).
    """
    confidence = str(session_data.get("stability",          "LOW"))
    signals    = int(session_data.get("stability_signals",  0))
    return confidence, signals


def _extract_noise(session_data: dict) -> tuple[float, float]:
    """
    Pull noise_ratio and ml_score_weight from session_data.
    These come from Phase 0 (written into pipeline_start and accessible
    via metrics_summary enrichment in main.py).
    """
    noise_ratio     = float(session_data.get("noise_ratio",     0.0))
    ml_score_weight = float(session_data.get("ml_score_weight", 1.0))
    return noise_ratio, ml_score_weight


def _confidence_label(score: float) -> str:
    for threshold, label in _CONFIDENCE_LABELS:
        if score >= threshold:
            return label
    return "UNRELIABLE"


# ══════════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ══════════════════════════════════════════════════════════════════════════════

def compute_trust(
    session_data: dict[str, Any],
    alarmes: list[dict],
    threshold_snapshots: list[dict],
) -> dict[str, Any]:
    """
    Compute the trust score for the current pipeline session.

    Args:
        session_data:         metrics_summary dict from main.py — contains
                              drift_score, drift_label, stability, noise_ratio
                              and all other metrics computed so far.
        alarmes:              Final alarm list (alarmes_pass1 from Pass 1).
                              Each alarm may carry model_agreement, fp_score_session
                              fields written by Phase A.
        threshold_snapshots:  List of threshold snapshot dicts from bridge.
                              threshold_snapshots[0] carries session_model_agreement
                              and session_fp_score written by A.2.

    Returns:
        dict with keys:
            model_agreement        float  0–1   (A.1)
            false_positive_rate    float  0–1   (A.2)
            drift_score            float  0–∞   (A.3, capped at 0.30 for weighting)
            drift_label            str          (A.3)
            drift_flagged          bool         (A.3)
            stability              str          (A.4)
            stable_signals         int  0–3     (A.4)
            noise_ratio            float  0–1   (Phase 0)
            ml_score_weight        float  0.75–1.0  (Phase 0)
            confidence_in_metrics  float  0–1   (weighted combination)
            confidence_label       str          (TRUSTWORTHY/ACCEPTABLE/UNCERTAIN/UNRELIABLE)
            signals_summary        str          (human-readable one-liner)
    """
    # ── Extract all Phase A inputs ────────────────────────────────────────────
    model_agreement  = _extract_model_agreement(alarmes, threshold_snapshots)
    fp_rate          = _extract_fp_rate(alarmes, threshold_snapshots)
    drift, drift_lbl, drift_flagged = _extract_drift(session_data)
    stability, stable_signals       = _extract_stability(session_data)
    noise_ratio, ml_score_weight    = _extract_noise(session_data)

    # ── Compute weighted confidence score ─────────────────────────────────────
    # Each component is normalised to [0, 1] before weighting.
    # drift is capped at 0.30 before inverting (above 0.30 is already "HIGH drift")
    stability_score  = _STABILITY_SCORE.get(stability, 0.2)
    drift_capped     = min(drift, 0.30)
    drift_component  = 1.0 - (drift_capped / 0.30)   # 0 drift → 1.0, 0.30 drift → 0.0
    fp_component     = 1.0 - fp_rate                  # 0 FP → 1.0, 1.0 FP → 0.0

    # Noise penalty — if session is very noisy, reduce confidence slightly
    # (the models saw inflated counts; their agreement may be less meaningful)
    noise_penalty = max(0.0, noise_ratio - 0.50) * 0.20  # only kicks in above 50% noise

    raw_confidence = (
        W_MODEL_AGREEMENT * model_agreement
        + W_FP_RATE        * fp_component
        + W_DRIFT          * drift_component
        + W_STABILITY      * stability_score
        - noise_penalty
    )
    confidence = round(max(0.0, min(1.0, raw_confidence)), 4)
    label      = _confidence_label(confidence)

    # ── Human-readable summary ────────────────────────────────────────────────
    alarm_count = len([a for a in alarmes if isinstance(a, dict)
                       and a.get("ip", "SYSTEM") != "SYSTEM"])

    summary_parts = [
        f"agreement={model_agreement:.2f}",
        f"fp_rate={fp_rate:.2f}",
        f"drift={drift:.3f}({drift_lbl})",
        f"stability={stability}({stable_signals}/3)",
        f"noise={noise_ratio:.0%}",
        f"alarms={alarm_count}",
    ]
    signals_summary = f"[{label}] conf={confidence:.3f} | " + " | ".join(summary_parts)

    # ── Step 1: risk_of_false_decision ────────────────────────────────────────
    # HIGH  → majority of alarms came from only 1 model (fp_rate > 0.50)
    #         OR models strongly disagree (agreement < 0.50)
    #         → a wrong decision based on these alarms is likely
    # MEDIUM → one warning signal present (fp_rate > 0.25 or agreement < 0.75)
    # LOW   → models agree and FP rate is controlled — decisions are reliable
    if fp_rate > 0.50 or model_agreement < 0.50:
        risk_of_false_decision = "HIGH"
    elif fp_rate > 0.25 or model_agreement < 0.75:
        risk_of_false_decision = "MEDIUM"
    else:
        risk_of_false_decision = "LOW"

    result: dict[str, Any] = {
        # Core trust outputs
        "trust_score":             confidence,          # alias — same as confidence_in_metrics
        "status":                  label,               # alias — same as confidence_label
        "risk_of_false_decision":  risk_of_false_decision,
        # Detailed breakdown
        "model_agreement":         model_agreement,
        "false_positive_rate":     fp_rate,
        "drift_score":             round(drift, 4),
        "drift_label":             drift_lbl,
        "drift_flagged":           drift_flagged,
        "stability":               stability,
        "stable_signals":          stable_signals,
        "noise_ratio":             round(noise_ratio, 4),
        "ml_score_weight":         round(ml_score_weight, 4),
        "confidence_in_metrics":   confidence,          # kept for backward compatibility
        "confidence_label":        label,               # kept for backward compatibility
        "signals_summary":         signals_summary,
    }

    print(f"\n[TRUST] {signals_summary}")
    print(f"[TRUST] risk_of_false_decision={risk_of_false_decision}")
    if drift_flagged:
        print(f"[TRUST] ⚠️  Drift flagged — anomaly rate shifted significantly")
    if fp_rate > 0.50:
        print(f"[TRUST] ⚠️  High FP rate — majority of alarms from only 1 model")
    if model_agreement < 0.50:
        print(f"[TRUST] ⚠️  Low model agreement — detection reliability is low")

    logger.info("Trust computed: %s", signals_summary)
    return result