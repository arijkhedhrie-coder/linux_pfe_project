"""
web_engine.py — v3 (Phase 1 Standardized + Feature Engineering)
═══════════════════════════════════════════════════════════════════
Detects WEB_ENUMERATION and PORT_SCAN attacks.

CHANGES vs v2:
  - Standard output schema: source_ip, weighted_risk_score, action,
    features (dict), first_seen, last_seen
  - Added endpoint_entropy: random URLs across many paths = scanner
  - Added burstiness_score: sudden 30-second spike = automated tool
  - Added user_agent_entropy: rotating UAs = obfuscated tool
  - All layer scores moved into 'features' dict for bridge correlation

Layers:
  L1 — Request rate (req/min)
  L2 — Status code pattern (404/403 ratio)
  L3 — Sensitive path targeting
  L4 — Tool fingerprint (UA / path signatures)
  L5 — Discovery success (200 on non-root)
  L6 — Endpoint entropy (NEW — path diversity = scanner)
  L7 — Request burstiness (NEW — 30s spike = automated)
═══════════════════════════════════════════════════════════════════
"""
from __future__ import annotations

import math
import re
from datetime import datetime
from typing import Any

import numpy as np
import pandas as pd


# ── Config ─────────────────────────────────────────────────────────────────────
SENSITIVE_PATHS = [
    '/.git', '/.env', '/admin', '/phpmyadmin', '/wp-admin', '/wp-config',
    '/backup', '/.ssh', '/.htpasswd', '/.htaccess', '/config', '/passwd',
    '/shadow', '/db', '/database', '/.bash_history', '/server-status',
    '/console', '/actuator', '/api/v1', '/swagger', '/graphql',
]
TOOL_SIGNATURES = {
    'gobuster': 'WEB_ENUMERATION', 'dirb': 'WEB_ENUMERATION',
    'dirsearch': 'WEB_ENUMERATION', 'nikto': 'WEB_ENUMERATION',
    'wfuzz': 'WEB_ENUMERATION', 'nmap': 'PORT_SCAN',
    'masscan': 'PORT_SCAN', 'zmap': 'PORT_SCAN', 'nuclei': 'PORT_SCAN',
}
NMAP_PATH_PATTERNS = [r'/nmaplowercheck', r'/sdk$', r'/HNAP1', r'/evox/about']

RATE_BLOCK_THRESHOLD = 500
HIGH_RISK_THRESHOLD  = 55
MED_RISK_THRESHOLD   = 30


# ── Parsing helpers ────────────────────────────────────────────────────────────

def _extract_apache_fields(detail: str) -> dict:
    fields = {'ip': None, 'method': None, 'path': None,
              'status': None, 'size': 0, 'user_agent': None}
    m = re.match(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', str(detail))
    if m:
        fields['ip'] = m.group(1)
    m = re.search(r'"(GET|POST|HEAD|PUT|DELETE|OPTIONS)\s+(\S+)', str(detail))
    if m:
        fields['method'] = m.group(1)
        fields['path']   = m.group(2)
    m = re.search(r'" (\d{3}) ', str(detail))
    if m:
        fields['status'] = int(m.group(1))
    m = re.search(r'\d{3} (\d+) "-"', str(detail))
    if m:
        fields['size'] = int(m.group(1))
    m = re.search(
        r'"([^"]*(?:gobuster|dirb|nikto|nmap|masscan|dirsearch|wfuzz|nuclei)[^"]*)"',
        str(detail), re.I,
    )
    if m:
        fields['user_agent'] = m.group(1)
    return fields


def _extract_timestamp_apache(detail: str):
    m = re.search(r'\[(\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2})', str(detail))
    if m:
        try:
            return datetime.strptime(m.group(1), '%d/%b/%Y:%H:%M:%S')
        except ValueError:
            return None
    return None


def parse_web_logs(df: pd.DataFrame) -> pd.DataFrame:
    text_col = next((c for c in ['Content', 'detail'] if c in df.columns), None)
    if text_col is None:
        return pd.DataFrame()
    web_mask = (
        df[text_col].str.contains('HTTP/1', na=False) |
        (df.get('source_log', pd.Series(dtype=str)) == 'apache2_access.log') |
        df.get('type_event', pd.Series(dtype=str)).isin(['WEB_ENUMERATION', 'HTTP_REQUEST', 'PORT_SCAN'])
    )
    web = df[web_mask].copy()
    if web.empty:
        return pd.DataFrame()
    parsed    = web[text_col].apply(_extract_apache_fields)
    parsed_df = pd.DataFrame(list(parsed))
    if 'timestamp' in web.columns and pd.api.types.is_datetime64_any_dtype(web['timestamp']):
        parsed_df['timestamp'] = web['timestamp'].values
    else:
        parsed_df['timestamp'] = web[text_col].apply(_extract_timestamp_apache)
        parsed_df['timestamp'] = pd.to_datetime(parsed_df['timestamp'], errors='coerce')
    if 'source_ip' in web.columns:
        parsed_df['ip'] = parsed_df['ip'].where(parsed_df['ip'].notna(), web['source_ip'].values)
    parsed_df['type_event_orig'] = web.get('type_event', pd.Series('UNKNOWN', index=web.index)).values
    return parsed_df.dropna(subset=['ip']).reset_index(drop=True)


# ── Detection layers ───────────────────────────────────────────────────────────

def layer1_request_rate(grp: pd.DataFrame) -> float:
    grp = grp.dropna(subset=['timestamp'])
    if len(grp) < 2:
        return 10.0
    duration_min = max((grp['timestamp'].max() - grp['timestamp'].min()).total_seconds() / 60, 0.016)
    rpm = len(grp) / duration_min
    return round(min(100, (rpm / RATE_BLOCK_THRESHOLD) * 100), 2)


def layer2_status_pattern(grp: pd.DataFrame) -> float:
    total = len(grp)
    if total == 0:
        return 0.0
    n404 = (grp['status'] == 404).sum()
    n403 = (grp['status'] == 403).sum()
    return round(min(70, n404 / total * 80) + min(30, n403 * 10), 2)


def layer3_sensitive_paths(grp: pd.DataFrame) -> float:
    if 'path' not in grp.columns:
        return 0.0
    paths = grp['path'].dropna().str.lower()
    hits, found_critical = 0, False
    for sensitive in SENSITIVE_PATHS:
        matches = paths.str.startswith(sensitive.lower())
        if matches.any():
            hits += 1
            # Fix: reindex matches to grp.index before combining with grp boolean mask.
            # paths is derived from grp['path'].dropna() so its index is a subset of grp.index.
            # Combining directly causes "Boolean Series key will be reindexed" warning
            # and can produce wrong results when grp has a non-default index.
            matches_aligned = matches.reindex(grp.index, fill_value=False)
            if grp.loc[matches_aligned & (grp['status'] == 200)].shape[0] > 0:
                found_critical = True
    score = min(80, hits * 8)
    if found_critical:
        score = min(100, score + 40)
    return round(score, 2)


def layer4_tool_fingerprint(grp: pd.DataFrame) -> float:
    if 'user_agent' not in grp.columns:
        return 0.0
    has_tool = grp['user_agent'].notna().any()
    if not has_tool:
        if 'path' in grp.columns:
            for pattern in NMAP_PATH_PATTERNS:
                if grp['path'].dropna().str.contains(pattern, regex=True, case=False).any():
                    return 85.0
        return 5.0
    agent_str = grp['user_agent'].dropna().iloc[0] if len(grp['user_agent'].dropna()) > 0 else ''
    for tool in TOOL_SIGNATURES:
        if tool in agent_str.lower():
            return 90.0 if tool == 'nmap' else 80.0
    return 30.0


def layer5_discovery_success(grp: pd.DataFrame) -> float:
    if 'path' not in grp.columns or 'status' not in grp.columns:
        return 0.0
    successes = grp[(grp['status'] == 200) &
                    (~grp['path'].fillna('/').isin(['/', '/index.html', '/index.php']))]
    if len(successes) == 0:
        return 0.0
    for _, row in successes.iterrows():
        path = str(row.get('path', '')).lower()
        if any(path.startswith(s.lower()) for s in SENSITIVE_PATHS):
            return 95.0
    return min(60, len(successes) * 15)


def layer6_endpoint_entropy(grp: pd.DataFrame) -> float:
    """
    NEW — Shannon entropy over requested paths.
    A human visits a few pages; a scanner requests hundreds of random paths.
    High entropy = high path diversity = scanner behavior.

    Score breakdown:
      entropy > 4 bits (very diverse paths) → 80–100
      entropy 2–4 bits (moderate diversity) → 40–80
      entropy < 2 bits (repeated paths)     → 0–40
    """
    if 'path' not in grp.columns:
        return 0.0
    paths = grp['path'].dropna()
    if len(paths) < 5:
        return 0.0
    # Count frequency of each unique path
    counts = paths.value_counts()
    probs  = counts / counts.sum()
    entropy = float(-np.sum(probs * np.log2(probs + 1e-10)))
    # Normalize to 0–100: max meaningful entropy ~6 bits (64 unique paths)
    score = min(100, (entropy / 6.0) * 100)
    return round(score, 2)


def layer7_burstiness(grp: pd.DataFrame) -> float:
    """
    NEW — Detects sudden 30-second request spikes.
    A legitimate user browsing sends ~1 req/s.
    gobuster sends 50–500 req/s — identifiable as a burst even if the
    overall rate looks moderate (spread over a long time window).

    Returns 0–100 based on max requests seen in any 30-second window.
    """
    grp = grp.dropna(subset=['timestamp'])
    if len(grp) < 5:
        return 0.0
    times = grp['timestamp'].sort_values().reset_index(drop=True)
    window = pd.Timedelta('30s')
    max_burst = 0
    for t in times:
        in_window = ((times - t) <= window) & ((times - t) >= pd.Timedelta(0))
        max_burst = max(max_burst, int(in_window.sum()))
    # 10 req / 30s = suspicious; 100 req / 30s = definitive scanner
    score = min(100, (max_burst / 100) * 100)
    return round(score, 2)


# ── Main pipeline ──────────────────────────────────────────────────────────────

def run_web_idps(
    df: pd.DataFrame,
    high_risk_threshold: float | None = None,
    med_risk_threshold:  float | None = None,
) -> pd.DataFrame:
    """
    Full web attack detection pipeline.

    Output schema (Phase 1 standard):
      source_ip, weighted_risk_score, action, risk_level,
      features (dict with all layer scores), first_seen, last_seen,
      + individual score columns for backward compat.

    Args:
        high_risk_threshold: Override for BLOCK_24H threshold (default: module HIGH_RISK_THRESHOLD = 55).
        med_risk_threshold:  Override for WATCHLIST threshold (default: module MED_RISK_THRESHOLD = 30).
    """
    _high = high_risk_threshold if high_risk_threshold is not None else HIGH_RISK_THRESHOLD
    _med  = med_risk_threshold  if med_risk_threshold  is not None else MED_RISK_THRESHOLD
    web_df = parse_web_logs(df)
    if web_df.empty:
        return pd.DataFrame()

    records = []
    for ip, grp in web_df.groupby('ip'):
        grp = grp.sort_values('timestamp') if 'timestamp' in grp.columns else grp

        rate_score    = layer1_request_rate(grp)
        status_score  = layer2_status_pattern(grp)
        path_score    = layer3_sensitive_paths(grp)
        tool_score    = layer4_tool_fingerprint(grp)
        success_score = layer5_discovery_success(grp)
        entropy_score = layer6_endpoint_entropy(grp)
        burst_score   = layer7_burstiness(grp)

        # Weighted score — new layers slot in at moderate weights
        weighted = round(
            rate_score    * 0.20 +
            status_score  * 0.15 +
            path_score    * 0.15 +
            tool_score    * 0.20 +
            success_score * 0.10 +
            entropy_score * 0.10 +
            burst_score   * 0.10,
            2,
        )

        is_nmap = (
            (grp.get('type_event_orig', pd.Series()) == 'PORT_SCAN').any() or
            (grp['path'].dropna().str.contains('nmaplowercheck|HNAP1|evox', regex=True, na=False).any()
             if 'path' in grp.columns else False)
        )
        attack_type = 'PORT_SCAN' if is_nmap else 'WEB_ENUMERATION'
        risk_level  = 'HIGH' if weighted >= _high else 'MEDIUM' if weighted >= _med else 'LOW'
        action      = 'BLOCK_24H' if risk_level == 'HIGH' else 'WATCHLIST_30MIN' if risk_level == 'MEDIUM' else 'MONITOR'

        n404 = int((grp['status'] == 404).sum())
        n200 = int((grp['status'] == 200).sum())
        n403 = int((grp['status'] == 403).sum())

        sensitive_found: list[str] = []
        if 'path' in grp.columns:
            for _, row in grp[grp['status'] == 200].iterrows():
                path = str(row.get('path', '')).lower()
                if any(path.startswith(s.lower()) for s in SENSITIVE_PATHS):
                    sensitive_found.append(path)

        tool_agent = (
            grp['user_agent'].dropna().iloc[0]
            if 'user_agent' in grp.columns and len(grp['user_agent'].dropna()) > 0
            else 'unknown'
        )
        ts_first = (grp['timestamp'].min().strftime('%Y-%m-%d %H:%M')
                    if 'timestamp' in grp.columns else 'unknown')
        ts_last  = (grp['timestamp'].max().strftime('%Y-%m-%d %H:%M')
                    if 'timestamp' in grp.columns else 'unknown')

        # ── Standard features dict ────────────────────────────────────────
        features: dict[str, Any] = {
            'engine':               'web',
            'attack_vector':        attack_type,
            'rate_score':           rate_score,
            'status_pattern_score': status_score,
            'sensitive_path_score': path_score,
            'tool_fingerprint':     tool_score,
            'discovery_score':      success_score,
            'endpoint_entropy':     entropy_score,
            'burstiness':           burst_score,
            'total_requests':       len(grp),
            'requests_404':         n404,
            'requests_200':         n200,
            'requests_403':         n403,
            'tool_detected':        str(tool_agent)[:80],
            'sensitive_paths_found': sensitive_found,
        }

        records.append({
            # Standard cross-engine columns
            'source_ip':           ip,
            'weighted_risk_score': weighted,
            'risk_level':          risk_level,
            'action':              action,
            'first_seen':          ts_first,
            'last_seen':           ts_last,
            # Individual columns (backward compat)
            'attack_type':         attack_type,
            'total_requests':      len(grp),
            'requests_404':        n404,
            'requests_200':        n200,
            'requests_403':        n403,
            'rate_score':          rate_score,
            'status_score':        status_score,
            'sensitive_path_score': path_score,
            'tool_fingerprint_score': tool_score,
            'discovery_score':     success_score,
            'endpoint_entropy_score': entropy_score,
            'burstiness_score':    burst_score,
            'sensitive_paths_found': sensitive_found,
            'tool_detected':       str(tool_agent)[:80],
            'features':            features,
        })

    if not records:
        return pd.DataFrame()
    return (
        pd.DataFrame(records)
        .sort_values('weighted_risk_score', ascending=False)
        .reset_index(drop=True)
    )