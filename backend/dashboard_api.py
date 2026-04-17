"""
dashboard_api.py — Flask REST API bridge
=========================================
Connects the IDPS dashboard (frontend/idps-dashboard.html) to the
real pipeline outputs from main.py.

HOW IT WORKS:
  1. main.py runs the pipeline → writes output/session_*.jsonl + long_term_memory.json
  2. This API reads those files and serves them as JSON endpoints
  3. The dashboard polls every 12s → shows real data instead of mock data

USAGE:
  pip install flask flask-cors
  python dashboard_api.py

  Then open frontend/idps-dashboard.html in your browser.
  The dashboard will auto-switch from MOCK DATA → API LIVE in the top bar.

ENDPOINTS:
  GET /api/health          → {"status": "ok", "version": "1.0"}
  GET /api/kpis            → KPI object for the gauge row
  GET /api/alarms          → list of recent alarms (last session)
  GET /api/engine-scores   → per-engine risk scores
  GET /api/memory          → full long_term_memory.json contents
  GET /api/sessions        → list of past sessions (for memory timeline)
  GET /api/pipeline/latest → latest session_*.jsonl parsed into events
  GET /api/decisions       → agent decisions from latest session
  GET /api/logs/stream     → last 60 log lines from latest JSONL session
"""

from __future__ import annotations

import glob
import json
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, request
from flask_cors import CORS

# ─── Config ───────────────────────────────────────────────────────────────────
PROJECT_ROOT    = Path(__file__).resolve().parent.parent
MEMORY_FILE     = PROJECT_ROOT / "long_term_memory.json"
OUTPUT_DIR      = PROJECT_ROOT / "output"
CACHE_TTL_S     = 10   # re-read files at most every 10s

app = Flask(__name__)
CORS(app)  # allow dashboard (file://) to call localhost:5000

# ─── File cache (avoid hammering disk on every poll) ─────────────────────────
_cache: dict[str, tuple[float, Any]] = {}

def _cached(key: str, loader_fn):
    now = time.time()
    if key in _cache:
        ts, val = _cache[key]
        if now - ts < CACHE_TTL_S:
            return val
    val = loader_fn()
    _cache[key] = (now, val)
    return val

# ─── Readers ─────────────────────────────────────────────────────────────────

def _load_memory() -> dict:
    if not MEMORY_FILE.exists():
        return {"sessions": [], "anomalies_vues": [], "ips_suspectes": [], "threshold_history": []}
    with open(MEMORY_FILE, encoding="utf-8", errors="replace") as f:
        return json.load(f)


def _latest_jsonl() -> list[dict]:
    """Return parsed events from the most recent session_*.jsonl file."""
    files = sorted(glob.glob(str(OUTPUT_DIR / "session_*.jsonl")))
    if not files:
        return []
    with open(files[-1], encoding="utf-8", errors="replace") as f:
        events = []
        for line in f:
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return events


def _get_event(events: list[dict], event_type: str) -> dict:
    """Get the last event of a given type from a JSONL event list."""
    for e in reversed(events):
        if e.get("event_type") == event_type:
            return e
    return {}


# ─── KPI builder ─────────────────────────────────────────────────────────────

def _build_kpis(events: list[dict], memory: dict) -> dict:
    metrics   = _get_event(events, "METRICS_COMPUTED")
    summary   = _get_event(events, "SESSION_SUMMARY")
    pass1     = _get_event(events, "PASS1_COMPLETE")
    pipeline  = _get_event(events, "PIPELINE_START")

    health    = float(metrics.get("health_score") or summary.get("health_score") or 85.0)
    # Derive proxy KPIs from alarm/metrics data
    alarm_count   = int(pass1.get("alarm_count", 0))
    ssh_alarms    = int(pass1.get("alarms_by_domain", {}).get("SSH", 0))
    crit_count    = int(pass1.get("alarms_by_severity", {}).get("CRITIQUE", 0))
    ip_count      = int(metrics.get("unique_attacking_ips") or 0)
    velocity      = float(metrics.get("attack_velocity") or 0)

    return {
        "health_score":       round(health, 1),
        "cpu_load":           round(max(10, min(100, 100 - health + 15)), 1),
        "ssh_failures":       ssh_alarms,
        "active_connections": int(metrics.get("unique_attacking_ips") or ip_count or 0) * 12,
        "error_rate":         round(float(metrics.get("ip_entropy") or 0) * 2, 1),
        "blocked_ips":        crit_count,
        "alert_status":       metrics.get("alert_status", "NOMINAL"),
        "attack_pattern":     metrics.get("attack_pattern", "unknown"),
        "ip_entropy":         round(float(metrics.get("ip_entropy") or 0), 3),
        "unique_attacking_ips": ip_count,
        "attack_velocity":    round(velocity, 2),
        "is_velocity_spike":  bool(metrics.get("is_velocity_spike", False)),
        "night_ratio":        round(float(metrics.get("night_ratio") or 0), 2),
        "row_count":          int(pipeline.get("row_count", 0)),
        "server_count":       int(pipeline.get("server_count", 0)),
        "data_sources":       pipeline.get("data_sources", []),
    }


# ─── Alarm builder ───────────────────────────────────────────────────────────

_SEV_MAP = {"CRITIQUE": "CRITICAL", "AVERTISSEMENT": "HIGH", "AVERTISSEMENT_MOYEN": "MED"}
_ACTION_MAP = {
    "BLOCK_24H":       "BLOCK_NOW",
    "WATCHLIST_30MIN": "WATCHLIST",
    "ESCALATE":        "ESCALATE",
    "PREEMPTIVE_BLOCK":"BLOCK_NOW",
    "TRAFFIC_THROTTLE":"WATCHLIST",
    "MONITOR":         "MONITOR",
}
_HUMAN_INSIGHTS = {
    "SSH":         "Repeated login failures — credential stuffing or brute-force pattern.",
    "WEB":         "Suspicious HTTP path scanning — automated vulnerability scanner.",
    "FTP":         "Abnormal file transfer rate — possible data exfiltration.",
    "SESSION":     "Anomalous session token reuse — session compromise suspected.",
    "KERNEL":      "Kernel error spike — system instability, possible crash imminent.",
    "PREDICTION":  "Pre-attack signals detected — distributed attack likely incoming.",
    "CORRELATION": "Multi-vector cross-protocol attack — coordinated threat actor.",
    "CHAIN":       "Attack chain confirmed: SCAN→BRUTE→BREACH — active intrusion.",
}

def _build_alarms(memory: dict) -> list[dict]:
    """Extract real alarms from the most recent memory session."""
    sessions = memory.get("sessions", [])
    if not sessions:
        return []

    # Find latest session with actual alarms
    for sess in reversed(sessions):
        raw_alarms = sess.get("donnees", {}).get("alarmes", [])
        if raw_alarms:
            break
    else:
        return []

    result = []
    for i, a in enumerate(raw_alarms[:15]):
        domain   = a.get("domain", a.get("type", "SSH")).split("_")[0].upper()
        sev_raw  = a.get("severite", "AVERTISSEMENT")
        sev      = _SEV_MAP.get(sev_raw, "MED")
        action   = _ACTION_MAP.get(a.get("action", "MONITOR"), "MONITOR")
        score    = float(a.get("score", a.get("valeur", a.get("score_final", 0))))
        ip       = str(a.get("ip", a.get("IP_Source", "N/A")))
        ts_raw   = a.get("timestamp", datetime.now().isoformat())
        try:
            ts = datetime.fromisoformat(ts_raw).strftime("%H:%M:%S")
        except Exception:
            ts = ts_raw[:8]

        result.append({
            "id":           f"alarm-{i}-{int(time.time())}",
            "timestamp":    ts,
            "type":         a.get("type", "UNKNOWN").replace("🔴 ", "").replace("🟠 ", "").replace("⚠️ ", ""),
            "source_ip":    ip,
            "severity":     sev,
            "engine":       domain if domain in ("SSH","WEB","FTP","SESSION","KERNEL","PREDICTION","CORRELATION","CHAIN") else "SSH",
            "score":        round(score, 1),
            "message":      a.get("message", "")[:120],
            "human_insight": _HUMAN_INSIGHTS.get(domain, "Anomalous activity detected — review required."),
            "action":       action,
            "country":      a.get("country", "Unknown"),
            "failures":     int(a.get("failures", a.get("valeur", 0)) or 0),
        })

    return sorted(result, key=lambda x: {"CRITICAL":0,"HIGH":1,"MED":2,"LOW":3,"INFO":4}.get(x["severity"], 4))


# ─── Engine scores builder ────────────────────────────────────────────────────

def _build_engine_scores(events: list[dict], memory: dict) -> list[dict]:
    pass1  = _get_event(events, "PASS1_COMPLETE")
    pass2  = _get_event(events, "PASS2_COMPLETE")
    by_dom = pass1.get("alarms_by_domain", {})

    engines = ["SSH", "WEB", "FTP", "SESSION", "KERNEL", "PREDICTION"]
    scores  = []

    # Use threshold snapshots if available
    snaps = _get_event(events, "SESSION_SUMMARY").get("threshold_snapshots", [])
    thresh_p1 = snaps[0] if snaps else {}
    thresh_p2 = snaps[1] if len(snaps) > 1 else {}

    for eng in engines:
        alarm_count = int(by_dom.get(eng, 0))
        # Derive a score from alarm count (rough but real)
        base_score  = min(95.0, alarm_count * 8.5) if alarm_count else 5.0
        p1_thresh   = float(thresh_p1.get(f"{eng.lower()}_high", 55) or 55)
        p2_thresh   = float(thresh_p2.get(f"{eng.lower()}_high", p1_thresh) or p1_thresh)

        # Check if pass2 changed anything for this engine
        rerun_engines = pass2.get("engines_rerun", [])
        p2_ran = eng.lower() in [e.lower() for e in rerun_engines]

        status = "BLOCK" if base_score >= 60 else "WATCH" if base_score >= 25 else "CLEAR"
        scores.append({
            "engine":   eng,
            "score":    round(base_score, 1),
            "pass1":    round(p1_thresh, 1),
            "pass2":    round(p2_thresh, 1),
            "alarms":   alarm_count,
            "status":   status,
            "rerun_p2": p2_ran,
        })

    return scores


# ─── Agent decisions builder ──────────────────────────────────────────────────

def _build_decisions(events: list[dict], memory: dict) -> list[dict]:
    """Build agent decision objects from JSONL events."""
    decisions = []

    # DynamicConfig event → Orchestrateur decision
    dc = _get_event(events, "DYNAMIC_CONFIG_ISSUED")
    if dc:
        decisions.append({
            "id":         "dec-orchestrateur",
            "ts":         dc.get("timestamp", "")[-8:][:8] or "—",
            "agent":      "Orchestrateur",
            "action":     "ESCALATE_TO_PASS2" if dc.get("rerun_engines") else "CONFIG_ISSUED",
            "threat":     dc.get("threat_level", "NORMAL"),
            "confidence": float(dc.get("confidence", 0.9)),
            "severity":   "HIGH" if dc.get("threat_level") == "ELEVATED" else
                          "CRITICAL" if dc.get("threat_level") == "CRITICAL" else "INFO",
            "reasoning":  dc.get("reasoning_excerpt", "Agent issued DynamicConfig based on Pass 1 results."),
            "targets":    dc.get("escalate_ips", []),
            "config": {
                "ssh_high_risk_threshold": dc.get("ssh_high_override"),
                "ssh_med_risk_threshold":  None,
                "web_high_risk_threshold": dc.get("web_high_override"),
                "ftp_high_risk_threshold": dc.get("ftp_high_override"),
                "kernel_high_risk_threshold": dc.get("kernel_override"),
                "session_high_risk_threshold": dc.get("session_override"),
                "escalate_ips":  dc.get("escalate_ips", []),
                "rerun_engines": dc.get("rerun_engines", []),
            },
            "approved": None,
            "feedback": "",
        })

    # No-override event → Orchestrateur normal
    dc_def = _get_event(events, "DYNAMIC_CONFIG_DEFAULT")
    if dc_def and not dc:
        decisions.append({
            "id":         "dec-orchestrateur-normal",
            "ts":         dc_def.get("timestamp", "")[-8:][:8] or "—",
            "agent":      "Orchestrateur",
            "action":     "SURVEILLANCE_NORMALE",
            "threat":     "NORMAL",
            "confidence": 0.95,
            "severity":   "INFO",
            "reasoning":  "Pass 1 found no significant threats. No threshold overrides needed. Pass 2 skipped.",
            "targets":    [],
            "config":     None,
            "approved":   None,
            "feedback":   "",
        })

    # Agents complete → Rapporteur decision
    agents_ev = _get_event(events, "AGENTS_COMPLETE")
    if agents_ev:
        excerpt = agents_ev.get("result_excerpt", "")
        action  = "BLOCK_AWS_SG" if "BLOCAGE" in excerpt.upper() or "BLOCK" in excerpt.upper() else "SAVE_REPORT_S3"
        decisions.append({
            "id":         "dec-rapporteur",
            "ts":         agents_ev.get("timestamp", "")[-8:][:8] or "—",
            "agent":      "Rapporteur",
            "action":     action,
            "threat":     "NORMAL",
            "confidence": 1.0,
            "severity":   "INFO",
            "reasoning":  excerpt[:300] or "Session complete. Report saved to S3. Memory updated.",
            "targets":    [],
            "config":     None,
            "approved":   None,
            "feedback":   "",
        })

    # Pass1 complete → Détecteur
    p1 = _get_event(events, "PASS1_COMPLETE")
    if p1 and int(p1.get("alarm_count", 0)) > 0:
        top5 = p1.get("top5_messages", [])
        decisions.append({
            "id":         "dec-detecteur",
            "ts":         p1.get("timestamp", "")[-8:][:8] or "—",
            "agent":      "Détecteur",
            "action":     "TRIGGER_ALARM",
            "threat":     "CRITICAL" if int(p1.get("alarms_by_severity", {}).get("CRITIQUE", 0)) > 0 else "ELEVATED",
            "confidence": 0.94,
            "severity":   "CRITICAL" if int(p1.get("alarms_by_severity", {}).get("CRITIQUE", 0)) > 0 else "HIGH",
            "reasoning":  (top5[0] if top5 else "Anomalies detected in Pass 1 detection.") + f" | Total: {p1.get('alarm_count')} alarms.",
            "targets":    [],
            "config":     None,
            "approved":   None,
            "feedback":   "",
        })

    # Session start → Collecteur
    pipe = _get_event(events, "PIPELINE_START")
    if pipe:
        decisions.append({
            "id":         "dec-collecteur",
            "ts":         pipe.get("timestamp", "")[-8:][:8] or "—",
            "agent":      "Collecteur",
            "action":     "SURVEILLANCE_NORMALE",
            "threat":     "NORMAL",
            "confidence": 0.99,
            "severity":   "INFO",
            "reasoning":  f"S3 ingestion complete: {pipe.get('row_count', 0)} rows from {pipe.get('server_count', 0)} servers ({', '.join(pipe.get('data_sources', []))}).",
            "targets":    [],
            "config":     None,
            "approved":   None,
            "feedback":   "",
        })

    return decisions


# ─── Log lines builder ────────────────────────────────────────────────────────

def _build_log_lines(events: list[dict]) -> list[str]:
    """Convert JSONL events into human-readable log lines for the dashboard terminal."""
    lines = []
    for e in events:
        ts  = e.get("timestamp", "")
        try:
            ts = datetime.fromisoformat(ts).strftime("%H:%M:%S")
        except Exception:
            ts = ts[:8]

        et  = e.get("event_type", "")
        if et == "PIPELINE_START":
            lines.append(f"{ts} [PIPELINE_START] rows={e.get('row_count')} servers={e.get('server_count')} sources={e.get('data_sources')}")
        elif et == "METRICS_COMPUTED":
            lines.append(f"{ts} [METRICS] health={e.get('health_score')}% alert={e.get('alert_status')} pattern={e.get('attack_pattern')} entropy={e.get('ip_entropy')}bits")
        elif et == "PASS1_COMPLETE":
            lines.append(f"{ts} [PASS1_COMPLETE] alarms={e.get('alarm_count')} by_domain={e.get('alarms_by_domain')} by_sev={e.get('alarms_by_severity')}")
        elif et == "DYNAMIC_CONFIG_ISSUED":
            lines.append(f"{ts} [DYNAMIC_CONFIG] threat={e.get('threat_level')} conf={e.get('confidence')} ssh_override={e.get('ssh_high_override')} rerun={e.get('rerun_engines')}")
        elif et == "DYNAMIC_CONFIG_DEFAULT":
            lines.append(f"{ts} [DYNAMIC_CONFIG_DEFAULT] no overrides — Pass 2 skipped")
        elif et == "PASS2_COMPLETE":
            lines.append(f"{ts} [PASS2_COMPLETE] alarms={e.get('alarm_count')} delta={e.get('alarm_delta'):+d} engines={e.get('engines_rerun')}")
        elif et == "AGENTS_COMPLETE":
            lines.append(f"{ts} [AGENTS_COMPLETE] {str(e.get('result_excerpt',''))[:100]}")
        elif et == "SESSION_SUMMARY":
            lines.append(f"{ts} [SESSION_SUMMARY] final_alarms={e.get('alarm_count')} pass2={e.get('pass2_ran')} elapsed={e.get('elapsed_seconds')}s threat={e.get('agent_threat_level')}")
        elif et == "WARNING":
            lines.append(f"{ts} [WARN:{e.get('source')}] {e.get('message','')[:100]}")
        elif et == "ERROR":
            lines.append(f"{ts} [ERROR:{e.get('source')}] {e.get('error','')[:100]}")
    return lines


# ─── API Routes ───────────────────────────────────────────────────────────────

@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "version": "1.0", "timestamp": datetime.now().isoformat()})


@app.route("/api/kpis")
def kpis():
    def load():
        events = _latest_jsonl()
        memory = _load_memory()
        return _build_kpis(events, memory)
    return jsonify(_cached("kpis", load))


@app.route("/api/alarms")
def alarms():
    def load():
        memory = _load_memory()
        return _build_alarms(memory)
    return jsonify(_cached("alarms", load))


@app.route("/api/engine-scores")
def engine_scores():
    def load():
        events = _latest_jsonl()
        memory = _load_memory()
        return _build_engine_scores(events, memory)
    return jsonify(_cached("engine_scores", load))


@app.route("/api/memory")
def memory():
    def load():
        return _load_memory()
    return jsonify(_cached("memory", load))


@app.route("/api/sessions")
def sessions():
    def load():
        mem  = _load_memory()
        sess = mem.get("sessions", [])
        result = []
        for s in reversed(sess[-20:]):          # last 20, newest first
            d = s.get("donnees", {})
            result.append({
                "date":           s.get("date", ""),
                "threat_level":   d.get("agent_threat_level", "NORMAL"),
                "nb_alarms_pass1":int(d.get("nb_alarmes_pass1", d.get("nb_alarmes", 0))),
                "nb_alarms_final":int(d.get("nb_alarmes_final", d.get("nb_alarmes", 0))),
                "pass2_ran":      bool(d.get("pass2_ran", False)),
                "health_score":   float(d.get("health_score", 99.0)),
                "ips_suspectes":  d.get("ips_suspectes", []),
                "attack_pattern": d.get("attack_pattern", "unknown"),
            })
        return result
    return jsonify(_cached("sessions", load))


@app.route("/api/pipeline/latest")
def pipeline_latest():
    def load():
        events = _latest_jsonl()
        return {
            "events":    events,
            "log_lines": _build_log_lines(events),
            "step_count": len(events),
        }
    return jsonify(_cached("pipeline_latest", load))


@app.route("/api/decisions")
def decisions():
    def load():
        events = _latest_jsonl()
        memory = _load_memory()
        return _build_decisions(events, memory)
    return jsonify(_cached("decisions", load))


@app.route("/api/logs/stream")
def logs_stream():
    def load():
        events = _latest_jsonl()
        return {"lines": _build_log_lines(events)[-60:]}
    return jsonify(_cached("logs", load))


@app.route("/api/suspicious-ips")
def suspicious_ips():
    def load():
        mem = _load_memory()
        return {"ips": mem.get("ips_suspectes", [])}
    return jsonify(_cached("suspicious_ips", load))


# ─── CORS preflight ───────────────────────────────────────────────────────────
@app.after_request
def after_request(response):
    response.headers["Access-Control-Allow-Origin"]  = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
    return response


# ─── Entry point ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("  IDPS Dashboard API — starting on http://localhost:5000")
    print("=" * 60)
    print(f"  Project root : {PROJECT_ROOT}")
    print(f"  Memory file  : {MEMORY_FILE} ({'EXISTS' if MEMORY_FILE.exists() else 'NOT FOUND'})")
    print(f"  Output dir   : {OUTPUT_DIR} ({'EXISTS' if OUTPUT_DIR.exists() else 'NOT FOUND'})")
    jsonl_files = sorted(glob.glob(str(OUTPUT_DIR / "session_*.jsonl")))
    print(f"  JSONL files  : {len(jsonl_files)} found")
    if jsonl_files:
        print(f"  Latest JSONL : {Path(jsonl_files[-1]).name}")
    print("=" * 60)
    print()
    print("  Endpoints:")
    print("    GET /api/health          -> server status")
    print("    GET /api/kpis            -> gauge row data")
    print("    GET /api/alarms          -> live alarm feed")
    print("    GET /api/engine-scores   -> per-engine risk bars")
    print("    GET /api/memory          -> long_term_memory.json")
    print("    GET /api/sessions        -> session timeline")
    print("    GET /api/pipeline/latest -> pipeline events + logs")
    print("    GET /api/decisions       -> agent decisions")
    print("    GET /api/logs/stream     -> last 60 log lines")
    print("    GET /api/suspicious-ips  -> known bad IPs")
    print()
    print("  Open frontend/idps-dashboard.html in your browser.")
    print("  Dashboard auto-detects this server and switches from")
    print("  MOCK DATA -> API LIVE in the top bar.")
    print()
    app.run(host="0.0.0.0", port=5000, debug=False)
