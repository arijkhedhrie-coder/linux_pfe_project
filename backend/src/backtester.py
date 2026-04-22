"""
backtester.py — Phase D: Self-Validation Engine
═══════════════════════════════════════════════════════════════════════════════
Validates the IDPS against its own history.

Core question: "Were our past alarms correct?"

Method — for each session we test:
  1. Take session N — treat its alarms as predictions
  2. Look at sessions N+1 onwards — treat those as ground truth
  3. Check:
     - Did flagged IPs reappear in later sessions? (persistence = likely real threat)
     - Did the alarm count stay consistent across similar sessions? (stability)
     - Did health score degrade after sessions with high alarm counts? (correlation)
     - Did the system over-react? (false alarm ratio)

Usage:
    python main.py --backtest               → runs on last 3 sessions
    python main.py --backtest --sessions 5  → runs on last 5 sessions

    Or import directly:
        from src.backtester import run_backtest
        report = run_backtest(n_sessions=3)
        print(report["summary"])
═══════════════════════════════════════════════════════════════════════════════
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger("backtester")
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("[backtester] %(levelname)s %(message)s"))
    logger.addHandler(_h)
logger.setLevel(logging.INFO)

MEMORY_FILE = "long_term_memory.json"


# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _load_memory(memory_file: str = MEMORY_FILE) -> dict:
    for path in [memory_file, f"../{memory_file}", f"backend/{memory_file}"]:
        p = Path(path)
        if p.exists():
            try:
                with open(p, "r", encoding="utf-8", errors="replace") as f:
                    return json.load(f)
            except Exception:
                pass
    return {"sessions": [], "ips_suspectes": [], "threshold_history": []}


def _extract_session_ips(session: dict) -> set[str]:
    """All IPs flagged as suspicious in a session."""
    d = session.get("donnees", {})
    ips = set()

    # From ips_suspectes list
    for ip in d.get("ips_suspectes", []):
        if ip and str(ip).strip() not in {"", "nan", "None"}:
            ips.add(str(ip).strip())

    # From alarm list
    for a in d.get("alarmes", []):
        if isinstance(a, dict):
            ip = a.get("ip", "")
            if ip and str(ip).strip() not in {"", "nan", "None", "SYSTEM"}:
                ips.add(str(ip).strip())

    return ips


def _extract_alarm_count(session: dict) -> int:
    d = session.get("donnees", {})
    return int(
        d.get("nb_alarmes_final",
        d.get("nb_alarmes_pass1",
        d.get("nb_alarmes", 0))) or 0
    )


def _extract_health(session: dict) -> float | None:
    d = session.get("donnees", {})
    h = d.get("health_score")
    if h is None:
        return None
    try:
        return float(h)
    except (TypeError, ValueError):
        return None


def _extract_nb_anomalies(session: dict) -> int:
    d = session.get("donnees", {})
    return int(d.get("nb_anomalies", 0) or 0)


# ══════════════════════════════════════════════════════════════════════════════
# BACKTEST CHECKS
# ══════════════════════════════════════════════════════════════════════════════

def _check_ip_persistence(
    target_session: dict,
    future_sessions: list[dict],
) -> dict:
    """
    Check 1: Did the IPs flagged in this session reappear later?

    A high reappearance rate = the system correctly identified real threats.
    A low reappearance rate = may be false positives (or genuinely new/one-off attackers).

    Returns:
        flagged_ips         — IPs flagged in the target session
        reappeared_ips      — which ones showed up in future sessions
        persistence_rate    — fraction that reappeared (0–1)
        verdict             — GOOD / ACCEPTABLE / POOR
    """
    flagged = _extract_session_ips(target_session)
    if not flagged:
        return {
            "flagged_ips":      [],
            "reappeared_ips":   [],
            "persistence_rate": None,
            "verdict":          "NO_ALARMS",
            "note":             "No IPs flagged in this session — nothing to validate.",
        }

    future_ips: set[str] = set()
    for s in future_sessions:
        future_ips.update(_extract_session_ips(s))

    reappeared = flagged & future_ips
    rate = round(len(reappeared) / len(flagged), 4) if flagged else 0.0

    if rate >= 0.60:
        verdict = "GOOD"
    elif rate >= 0.30:
        verdict = "ACCEPTABLE"
    else:
        verdict = "POOR"

    return {
        "flagged_ips":      sorted(flagged),
        "reappeared_ips":   sorted(reappeared),
        "total_flagged":    len(flagged),
        "total_reappeared": len(reappeared),
        "persistence_rate": rate,
        "verdict":          verdict,
        "note": (
            f"{len(reappeared)}/{len(flagged)} flagged IPs reappeared in "
            f"{len(future_sessions)} later session(s)."
        ),
    }


def _check_alarm_stability(
    target_session: dict,
    all_sessions: list[dict],
    target_idx: int,
) -> dict:
    """
    Check 2: Is the alarm count for this session consistent with nearby sessions?

    Compares the alarm count of the target session against the rolling mean
    of its neighbors. A sudden spike = over-reaction. Sustained low = under-detection.

    Returns:
        alarm_count         — alarms in this session
        rolling_mean        — mean of surrounding sessions
        ratio               — alarm_count / rolling_mean
        verdict             — NORMAL / SPIKE / LOW
    """
    alarm_count = _extract_alarm_count(target_session)

    # Compare against up to 4 neighboring sessions (2 before, 2 after)
    neighbor_indices = [
        i for i in range(target_idx - 2, target_idx + 3)
        if i != target_idx and 0 <= i < len(all_sessions)
    ]
    neighbor_counts = [_extract_alarm_count(all_sessions[i]) for i in neighbor_indices]

    if not neighbor_counts:
        return {
            "alarm_count":  alarm_count,
            "rolling_mean": None,
            "ratio":        None,
            "verdict":      "INSUFFICIENT_DATA",
            "note":         "Not enough neighboring sessions to compare.",
        }

    mean = sum(neighbor_counts) / len(neighbor_counts)
    ratio = round(alarm_count / mean, 3) if mean > 0 else (1.0 if alarm_count == 0 else float("inf"))

    if ratio > 3.0:
        verdict = "SPIKE"
    elif ratio < 0.2 and alarm_count == 0 and mean > 2:
        verdict = "LOW"
    else:
        verdict = "NORMAL"

    return {
        "alarm_count":       alarm_count,
        "neighbor_mean":     round(mean, 2),
        "ratio":             ratio,
        "neighbor_counts":   neighbor_counts,
        "verdict":           verdict,
        "note": (
            f"This session: {alarm_count} alarms | "
            f"Neighbors mean: {mean:.1f} | ratio={ratio:.2f}"
        ),
    }


def _check_health_correlation(
    target_session: dict,
    next_session: dict | None,
) -> dict:
    """
    Check 3: Did health score degrade after high-alarm sessions?

    If a session had many alarms but the next session's health score
    did NOT drop, it may indicate the alarms didn't correspond to real damage.

    Returns:
        this_health         — health score this session
        next_health         — health score next session
        alarm_count         — how many alarms this session
        health_changed      — bool
        verdict             — CONSISTENT / INCONSISTENT / NO_DATA
    """
    this_health = _extract_health(target_session)
    alarm_count = _extract_alarm_count(target_session)
    next_health = _extract_health(next_session) if next_session else None

    if this_health is None or next_health is None:
        return {
            "this_health":   this_health,
            "next_health":   next_health,
            "alarm_count":   alarm_count,
            "verdict":       "NO_DATA",
            "note":          "Health score not available for comparison.",
        }

    health_delta = next_health - this_health

    # High alarms + health stayed fine = possible over-reaction
    # High alarms + health dropped = consistent (real damage)
    # Zero alarms + health fine = consistent (clean session)
    if alarm_count >= 3 and health_delta > -5.0:
        verdict = "INCONSISTENT"
        note = (
            f"{alarm_count} alarms raised but health {this_health:.1f}% → {next_health:.1f}% "
            f"(+{health_delta:.1f}%) — alarms may not have matched real impact."
        )
    elif alarm_count >= 3 and health_delta <= -5.0:
        verdict = "CONSISTENT"
        note = (
            f"{alarm_count} alarms + health degraded {this_health:.1f}% → {next_health:.1f}% "
            f"({health_delta:.1f}%) — alarms correlated with system impact."
        )
    else:
        verdict = "CONSISTENT"
        note = (
            f"{alarm_count} alarms, health {this_health:.1f}% → {next_health:.1f}% — normal."
        )

    return {
        "this_health":   this_health,
        "next_health":   next_health,
        "health_delta":  round(health_delta, 2),
        "alarm_count":   alarm_count,
        "verdict":       verdict,
        "note":          note,
    }


# ══════════════════════════════════════════════════════════════════════════════
# SCORING
# ══════════════════════════════════════════════════════════════════════════════

def _score_session(
    ip_check: dict,
    stability_check: dict,
    health_check: dict,
) -> tuple[float, str]:
    """
    Combine the 3 check verdicts into a single session accuracy score (0–1).

    Returns (score, label).
    """
    score = 0.0

    # IP persistence (weight 0.50 — most important signal)
    v = ip_check.get("verdict", "NO_ALARMS")
    if v == "GOOD":           score += 0.50
    elif v == "ACCEPTABLE":   score += 0.30
    elif v == "NO_ALARMS":    score += 0.40   # clean session, neutral
    # POOR = +0

    # Alarm stability (weight 0.30)
    v = stability_check.get("verdict", "INSUFFICIENT_DATA")
    if v == "NORMAL":             score += 0.30
    elif v == "INSUFFICIENT_DATA": score += 0.20
    elif v == "LOW":               score += 0.15
    # SPIKE = +0

    # Health correlation (weight 0.20)
    v = health_check.get("verdict", "NO_DATA")
    if v == "CONSISTENT":    score += 0.20
    elif v == "NO_DATA":     score += 0.10
    # INCONSISTENT = +0

    score = round(min(1.0, score), 4)

    if score >= 0.75:    label = "ACCURATE"
    elif score >= 0.50:  label = "ACCEPTABLE"
    elif score >= 0.25:  label = "UNRELIABLE"
    else:                label = "POOR"

    return score, label


# ══════════════════════════════════════════════════════════════════════════════
# MAIN BACKTEST FUNCTION
# ══════════════════════════════════════════════════════════════════════════════

def run_backtest(
    n_sessions: int = 3,
    memory_file: str = MEMORY_FILE,
    verbose: bool = True,
) -> dict[str, Any]:
    """
    Run the backtest on the last N sessions from long_term_memory.json.

    Args:
        n_sessions:  Number of past sessions to test (default 3).
        memory_file: Path to long_term_memory.json.
        verbose:     Print results to terminal.

    Returns:
        {
            "sessions_tested":  int,
            "results":          list of per-session dicts,
            "overall_accuracy": float 0–1,
            "overall_label":    str,
            "summary":          str,
            "timestamp":        str,
        }
    """
    memory  = _load_memory(memory_file)
    sessions = memory.get("sessions", [])

    if len(sessions) < 2:
        msg = f"Not enough sessions to backtest (found {len(sessions)}, need ≥ 2)."
        if verbose:
            print(f"[BACKTEST] ⚠️  {msg}")
        return {
            "sessions_tested":  0,
            "results":          [],
            "overall_accuracy": 0.0,
            "overall_label":    "INSUFFICIENT_DATA",
            "summary":          msg,
            "timestamp":        datetime.now().isoformat(),
        }

    # Select the sessions to test: take last N but keep at least 1 future session
    # for ground truth comparison
    max_testable = len(sessions) - 1
    n_to_test    = min(n_sessions, max_testable)

    # Indices of sessions to test (second-to-last through n_to_test back)
    test_indices = list(range(len(sessions) - 1 - n_to_test + 1, len(sessions)))
    # Exclude the very last session (no future to compare against)
    test_indices = [i for i in test_indices if i < len(sessions) - 1]

    if not test_indices:
        msg = "No testable sessions found (need at least 2 sessions total)."
        if verbose:
            print(f"[BACKTEST] ⚠️  {msg}")
        return {
            "sessions_tested":  0,
            "results":          [],
            "overall_accuracy": 0.0,
            "overall_label":    "INSUFFICIENT_DATA",
            "summary":          msg,
            "timestamp":        datetime.now().isoformat(),
        }

    if verbose:
        print(f"\n{'='*60}")
        print(f"  BACKTEST — {n_to_test} session(s) | {len(sessions)} total in memory")
        print(f"{'='*60}")

    results: list[dict] = []
    scores:  list[float] = []

    for idx in test_indices:
        target  = sessions[idx]
        future  = sessions[idx + 1:]   # all sessions after this one
        next_s  = sessions[idx + 1] if idx + 1 < len(sessions) else None
        date_str = target.get("date", "?")[:16]

        if verbose:
            print(f"\n[BACKTEST] Testing session {idx} ({date_str}) ...")

        ip_check      = _check_ip_persistence(target, future)
        stab_check    = _check_alarm_stability(target, sessions, idx)
        health_check  = _check_health_correlation(target, next_s)
        score, label  = _score_session(ip_check, stab_check, health_check)

        if verbose:
            print(f"  IP persistence : {ip_check['verdict']:12s}  {ip_check['note']}")
            print(f"  Alarm stability: {stab_check['verdict']:12s}  {stab_check['note']}")
            print(f"  Health corr.   : {health_check['verdict']:12s}  {health_check['note']}")
            print(f"  ─── Session score: {score:.3f} [{label}]")

        results.append({
            "session_idx":    idx,
            "session_date":   date_str,
            "alarm_count":    _extract_alarm_count(target),
            "nb_anomalies":   _extract_nb_anomalies(target),
            "score":          score,
            "label":          label,
            "ip_check":       ip_check,
            "stability_check": stab_check,
            "health_check":   health_check,
        })
        scores.append(score)

    overall = round(sum(scores) / len(scores), 4) if scores else 0.0

    if overall >= 0.75:    overall_label = "ACCURATE"
    elif overall >= 0.50:  overall_label = "ACCEPTABLE"
    elif overall >= 0.25:  overall_label = "UNRELIABLE"
    else:                  overall_label = "POOR"

    good_count = sum(1 for s in scores if s >= 0.75)
    poor_count = sum(1 for s in scores if s < 0.25)

    summary = (
        f"Backtest: {len(results)} session(s) | "
        f"overall={overall:.3f} [{overall_label}] | "
        f"{good_count} ACCURATE, {poor_count} POOR"
    )

    if verbose:
        print(f"\n{'='*60}")
        print(f"  BACKTEST COMPLETE")
        print(f"  Overall accuracy : {overall:.3f} [{overall_label}]")
        print(f"  Sessions tested  : {len(results)}")
        print(f"  ACCURATE         : {good_count}")
        print(f"  POOR             : {poor_count}")
        print(f"{'='*60}\n")

    report = {
        "sessions_tested":  len(results),
        "results":          results,
        "overall_accuracy": overall,
        "overall_label":    overall_label,
        "summary":          summary,
        "timestamp":        datetime.now().isoformat(),
    }

    # Layer 5 fix: persist results so dashboard can show historical accuracy
    _save_backtest_results(report, memory_file)

    return report


# ── CLI entry point (called from main.py --backtest) ──────────────────────────

def _save_backtest_results(report: dict, memory_file: str = MEMORY_FILE) -> None:
    """
    Persist backtest results into long_term_memory.json under 'backtest_history'.
    Keeps last 20 backtest runs. Dashboard reads this for historical accuracy trend.
    """
    for path in [memory_file, f"../{memory_file}", f"backend/{memory_file}"]:
        p = Path(path)
        if p.exists():
            try:
                with open(p, "r", encoding="utf-8", errors="replace") as f:
                    memory = json.load(f)
                memory.setdefault("backtest_history", [])
                memory["backtest_history"].append({
                    "timestamp":        report["timestamp"],
                    "sessions_tested":  report["sessions_tested"],
                    "overall_accuracy": report["overall_accuracy"],
                    "overall_label":    report["overall_label"],
                    "summary":          report["summary"],
                })
                memory["backtest_history"] = memory["backtest_history"][-20:]
                with open(p, "w", encoding="utf-8") as f:
                    json.dump(memory, f, indent=2, ensure_ascii=False)
                logger.info("Backtest results saved to memory (%s)", p)
                return
            except Exception as e:
                logger.warning("Could not save backtest results: %s", e)
                return
    """
    Standalone backtest runner. Reads only — no alarms, no S3, no memory writes.
    """
    print("\n[BACKTEST] Running in read-only mode (no alarms, no uploads).")
    report = run_backtest(n_sessions=n_sessions, verbose=True)
    print(f"\n[BACKTEST] {report['summary']}")