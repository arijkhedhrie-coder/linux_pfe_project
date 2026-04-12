"""
session_engine.py — v3 (Phase 1 Standardized + UBA)
══════════════════════════════════════════════════════════════════════════════
Session anomaly detection with User Behavior Analytics.

CHANGES vs v2:
  - Standard output schema: 'features' dict added to top-level return dict
  - Features dict consolidates all layer scores for bridge correlation
  - Preserved all UBA / behavioral baseline logic from v2

Five detection layers:
  L1 — Post-breach login (success after brute force)
  L2 — Privilege escalation (suspicious sudo)
  L3 — Root session abuse (interactive root at odd hours)
  L4 — Behavioral deviation (UBA: new IP + unusual hour)
  L5 — Combined risk (L4 deviation + L1 post-attack timing)
══════════════════════════════════════════════════════════════════════════════
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

import pandas as pd


# ── Config ─────────────────────────────────────────────────────────────────────
SUSPICIOUS_SUDO_COMMANDS = [
    'nmap', 'gobuster', 'hydra', 'metasploit', 'msfconsole',
    'nc', 'netcat', 'bash', 'sh', 'python', 'perl', 'ruby',
    'curl', 'wget', 'chmod 777', 'useradd', 'usermod',
    'iptables', 'crontab', 'at ', 'poweroff', 'reboot', 'shutdown',
]
INTERNAL_IP_PREFIXES = [
    '192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.',
    '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
    '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.', '127.',
]
HIGH_RISK_THRESHOLD    = 50
MED_RISK_THRESHOLD     = 25
POST_ATTACK_WINDOW_HRS = 2
MIN_BASELINE_SAMPLES   = 3
NEW_IP_BASE_SCORE      = 25
UNUSUAL_HOUR_SCORE     = 20
IMPOSSIBLE_TRAVEL_SCORE = 60


# ── Behavioral baseline ────────────────────────────────────────────────────────

@dataclass
class UserBaseline:
    user: str
    known_ips: set = field(default_factory=set)
    login_hours: list = field(default_factory=list)
    first_seen: datetime | None = None
    last_seen:  datetime | None = None
    total_logins: int = 0
    last_login_ip:   str | None = None
    last_login_time: datetime | None = None

    def add_login(self, ip: str, ts: datetime) -> None:
        self.known_ips.add(ip)
        if hasattr(ts, 'hour'):
            self.login_hours.append(ts.hour)
        self.first_seen = self.first_seen or ts
        self.last_seen  = ts
        self.last_login_ip   = ip
        self.last_login_time = ts
        self.total_logins   += 1

    def is_established(self) -> bool:
        return self.total_logins >= MIN_BASELINE_SAMPLES

    def typical_hours(self) -> tuple[int, int]:
        if not self.login_hours:
            return 0, 23
        h = sorted(self.login_hours)
        return h[int(len(h) * 0.1)], h[min(int(len(h) * 0.9), len(h) - 1)]

    def is_unusual_hour(self, hour: int) -> bool:
        if not self.is_established():
            return False
        lo, hi = self.typical_hours()
        return (hour < lo or hour > hi) if lo <= hi else (hi < hour < lo)

    def check_impossible_travel(self, new_ip: str, new_time: datetime) -> tuple[bool, str]:
        if not self.last_login_ip or not self.last_login_time:
            return False, ''
        diff_h = (new_time - self.last_login_time).total_seconds() / 3600
        if diff_h < 1 and new_ip != self.last_login_ip:
            old_prefix = '.'.join(self.last_login_ip.split('.')[:3])
            new_prefix = '.'.join(new_ip.split('.')[:3])
            if old_prefix != new_prefix:
                return True, (
                    f"From {self.last_login_ip} at {self.last_login_time} "
                    f"to {new_ip} at {new_time} ({diff_h:.1f}h apart)"
                )
        return False, ''


class BehaviorBaselineManager:
    def __init__(self):
        self._baselines: dict[str, UserBaseline] = {}

    def _get(self, user: str) -> UserBaseline:
        if user not in self._baselines:
            self._baselines[user] = UserBaseline(user=user)
        return self._baselines[user]

    def record_login(self, user: str, ip: str, ts: datetime) -> None:
        self._get(user).add_login(ip, ts)

    def analyze_login(self, user: str, ip: str, ts: datetime) -> dict:
        bl = self._get(user)
        result: dict[str, Any] = {
            'user': user, 'ip': ip, 'timestamp': ts,
            'is_new_ip': False, 'is_unusual_time': False,
            'is_impossible_travel': False,
            'baseline_established': bl.is_established(),
            'risk_score': 0.0, 'signals': [],
        }
        if not bl.is_established():
            result['reason'] = 'Insufficient baseline data'
            return result
        score, signals = 0.0, []
        if not bl.known_ips or ip not in bl.known_ips:
            result['is_new_ip'] = True
            signals.append(f"New IP: {ip} (known: {len(bl.known_ips)})")
            score += NEW_IP_BASE_SCORE
        if hasattr(ts, 'hour') and bl.is_unusual_hour(ts.hour):
            result['is_unusual_time'] = True
            lo, hi = bl.typical_hours()
            signals.append(f"Unusual hour: {ts.hour}:00 (typical {lo}:00–{hi}:00)")
            score += UNUSUAL_HOUR_SCORE
        imp, reason = bl.check_impossible_travel(ip, ts)
        if imp:
            result['is_impossible_travel'] = True
            signals.append(f"Impossible travel: {reason}")
            score += IMPOSSIBLE_TRAVEL_SCORE
        result['risk_score'] = min(100.0, score)
        result['signals']    = signals
        result['reason']     = '; '.join(signals) if signals else 'Normal'
        return result

    def summary(self) -> dict:
        return {
            'total_users':            len(self._baselines),
            'users_with_baseline':    sum(1 for b in self._baselines.values() if b.is_established()),
            'baseline_details': {
                u: {
                    'total_logins':         b.total_logins,
                    'known_ips':            len(b.known_ips),
                    'typical_hours':        b.typical_hours(),
                    'baseline_established': b.is_established(),
                }
                for u, b in self._baselines.items()
            },
        }


# ── Parsing ────────────────────────────────────────────────────────────────────

def _extract_user(detail: str) -> str:
    m = re.search(r'user\s+(\w+)', str(detail), re.I)
    return m.group(1) if m else 'unknown'


def _extract_ip(detail: str):
    m = re.search(r'from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', str(detail))
    return m.group(1) if m else None


def _extract_sudo_command(detail: str) -> str:
    m = re.search(r'COMMAND=(.+?)$', str(detail).strip())
    return m.group(1).strip() if m else ''


def _is_internal(ip: str) -> bool:
    return not ip or any(str(ip).startswith(p) for p in INTERNAL_IP_PREFIXES)


def parse_session_logs(df: pd.DataFrame) -> pd.DataFrame:
    text_col = next((c for c in ['Content', 'detail'] if c in df.columns), None)
    if text_col is None:
        return pd.DataFrame()
    auth_mask = (
        (df.get('source_log', pd.Series(dtype=str)) == 'auth.log') |
        df[text_col].str.contains('sshd|pam_unix|sudo|session|login', case=False, na=False)
    ) & ~df[text_col].str.contains('HTTP/', na=False)
    auth = df[auth_mask].copy()
    if auth.empty:
        return pd.DataFrame()
    rows = []
    for _, row in auth.iterrows():
        detail = str(row[text_col])
        ts     = row.get('timestamp')
        if pd.isna(ts):
            continue
        if re.search(r'Accepted password|Accepted publickey', detail):
            etype = 'SSH_SUCCESS'
        elif re.search(r'Failed password|Invalid user|authentication failure', detail, re.I):
            etype = 'SSH_FAILED'
        elif re.search(r'session opened', detail):
            etype = 'SESSION_OPEN'
        elif re.search(r'session closed', detail):
            etype = 'SESSION_CLOSE'
        elif 'sudo' in detail.lower() and 'COMMAND' in detail:
            etype = 'SUDO'
        elif 'sudo' in detail.lower():
            etype = 'SUDO_AUTH'
        else:
            etype = 'OTHER'
        rows.append({
            'timestamp':    ts,
            'event_type':   etype,
            'user':         _extract_user(detail),
            'source_ip':    _extract_ip(detail) or row.get('source_ip'),
            'sudo_command': _extract_sudo_command(detail) if etype == 'SUDO' else '',
            'detail':       detail[:200],
        })
    if not rows:
        return pd.DataFrame()
    return pd.DataFrame(rows).sort_values('timestamp').reset_index(drop=True)


# ── Detection layers ───────────────────────────────────────────────────────────

def layer1_post_attack_login(session_df: pd.DataFrame) -> tuple[float, dict]:
    failures  = session_df[session_df['event_type'] == 'SSH_FAILED'].copy()
    successes = session_df[session_df['event_type'] == 'SSH_SUCCESS'].copy()
    if failures.empty or successes.empty:
        return 0.0, {}
    for col in ('timestamp',):
        failures[col]  = pd.to_datetime(failures[col],  errors='coerce')
        successes[col] = pd.to_datetime(successes[col], errors='coerce')
    failures  = failures.dropna(subset=['timestamp']).sort_values('timestamp')
    successes = successes.dropna(subset=['timestamp'])
    if failures.empty:
        return 0.0, {}
    bf_end, bf_start, bf_count = None, None, 0
    for _, row in failures.iterrows():
        window = failures[
            (failures['timestamp'] >= row['timestamp']) &
            (failures['timestamp'] <= row['timestamp'] + timedelta(minutes=10))
        ]
        if len(window) >= 5:
            bf_start = window['timestamp'].min()
            bf_end   = window['timestamp'].max()
            bf_count = len(window)
    if bf_end is None:
        return 0.0, {}
    post = successes[successes['timestamp'] > bf_end - timedelta(hours=POST_ATTACK_WINDOW_HRS)]
    if post.empty:
        return 0.0, {}
    closest     = post.iloc[0]
    delay_hours = (closest['timestamp'] - bf_end).total_seconds() / 3600
    score       = max(0, 100 - delay_hours * 20)
    return round(score, 2), {
        'bf_attempt_count':    bf_count,
        'bf_start':            str(bf_start),
        'bf_end':              str(bf_end),
        'first_success_after': str(closest['timestamp']),
        'success_user':        closest.get('user', 'unknown'),
        'success_ip':          closest.get('source_ip', 'unknown'),
        'delay_minutes':       round(delay_hours * 60, 1),
    }


def layer2_privilege_escalation(session_df: pd.DataFrame) -> tuple[float, list]:
    sudo_rows = session_df[session_df['event_type'] == 'SUDO'].copy()
    if sudo_rows.empty:
        return 0.0, []
    suspicious_found, odd_hour_count = [], 0
    for _, row in sudo_rows.iterrows():
        cmd = str(row.get('sudo_command', '')).lower()
        ts  = row.get('timestamp')
        for sc in SUSPICIOUS_SUDO_COMMANDS:
            if sc in cmd:
                suspicious_found.append({
                    'command':    row['sudo_command'][:100],
                    'user':       row.get('user', 'unknown'),
                    'timestamp':  str(ts),
                    'flagged_for': sc,
                })
                break
        if hasattr(ts, 'hour') and (ts.hour < 6 or ts.hour >= 22):
            odd_hour_count += 1
    score = min(100,
        min(80, len(suspicious_found) * 30) +
        min(40, odd_hour_count * 15) * 0.3 +
        min(20, len(sudo_rows) * 2) * 0.2
    )
    return round(score, 2), suspicious_found


def layer3_root_session_abuse(session_df: pd.DataFrame) -> tuple[float, dict]:
    sessions     = session_df[session_df['event_type'] == 'SESSION_OPEN'].copy()
    root_sessions = sessions[sessions['user'] == 'root']
    if root_sessions.empty:
        return 0.0, {}
    non_cron = root_sessions[~root_sessions['detail'].str.contains('CRON|cron', na=False)]
    if non_cron.empty:
        return 0.0, {}
    night = [
        {'timestamp': str(r['timestamp']), 'detail': r.get('detail', '')[:100]}
        for _, r in non_cron.iterrows()
        if hasattr(r.get('timestamp'), 'hour') and 0 <= r['timestamp'].hour <= 5
    ]
    score = min(60, len(non_cron) * 10)
    if night:
        score = min(100, score + len(night) * 20)
    return round(score, 2), {
        'total_root_sessions': len(non_cron),
        'night_sessions':      len(night),
        'night_details':       night[:5],
    }


def layer4_behavioral_deviation(
    session_df: pd.DataFrame,
    baseline_manager: BehaviorBaselineManager,
) -> tuple[float, list]:
    successes = session_df[session_df['event_type'].isin(['SSH_SUCCESS', 'SESSION_OPEN'])].copy()
    if successes.empty:
        return 0.0, []
    cutoff        = int(len(successes) * 0.6)
    baseline_data = successes.iloc[:cutoff]
    analysis_data = successes.iloc[cutoff:]
    for _, row in baseline_data.iterrows():
        ts = row.get('timestamp')
        if ts and not pd.isna(ts):
            baseline_manager.record_login(
                row.get('user', 'unknown'),
                row.get('source_ip', '0.0.0.0'),
                pd.to_datetime(ts),
            )
    deviations = []
    for _, row in analysis_data.iterrows():
        ts = row.get('timestamp')
        if ts is None or pd.isna(ts):
            continue
        ts  = pd.to_datetime(ts)
        ip  = row.get('source_ip', '0.0.0.0')
        result = baseline_manager.analyze_login(row.get('user', 'unknown'), ip, ts)
        if result['risk_score'] > 0:
            deviations.append({
                'user':                 row.get('user', 'unknown'),
                'ip':                   ip,
                'timestamp':            str(ts),
                'risk_score':           result['risk_score'],
                'signals':              result['signals'],
                'is_new_ip':            result['is_new_ip'],
                'is_unusual_time':      result['is_unusual_time'],
                'is_impossible_travel': result['is_impossible_travel'],
                'is_internal_ip':       _is_internal(ip),
            })
    if not deviations:
        return 0.0, []
    total = sum(d['risk_score'] for d in deviations)
    score = (total / (len(deviations) * 100)) * 100
    return round(score, 2), deviations


def layer5_combined_risk(
    post_breach_details: dict,
    behavioral_deviations: list,
) -> tuple[float, list]:
    combined: list[dict] = []
    if not behavioral_deviations or not post_breach_details:
        return 0.0, combined
    bf_end_str = post_breach_details.get('bf_end')
    if not bf_end_str:
        return 0.0, combined
    try:
        bf_end = pd.to_datetime(bf_end_str)
    except Exception:
        return 0.0, combined
    for dev in behavioral_deviations:
        try:
            login_time = pd.to_datetime(dev['timestamp'])
            diff_h     = (login_time - bf_end).total_seconds() / 3600
            if 0 < diff_h < POST_ATTACK_WINDOW_HRS:
                factors, compound = [], 0
                factors.append(f"Login {diff_h:.1f}h after brute force")
                compound += 30
                if dev.get('is_new_ip'):
                    factors.append("Previously unseen IP")
                    compound += 25
                if dev.get('is_unusual_time'):
                    factors.append("Unusual login hour")
                    compound += 20
                if not dev.get('is_internal_ip'):
                    factors.append("External IP")
                    compound += 15
                compound = min(100, compound)
                combined.append({
                    'user':           dev['user'],
                    'ip':             dev['ip'],
                    'timestamp':      dev['timestamp'],
                    'compound_score': compound,
                    'risk_factors':   factors,
                    'severite':       'CRITIQUE' if compound >= 60 else 'AVERTISSEMENT',
                    'message': (
                        f"🚨 COMPOUND RISK — {dev['user']} from new IP {dev['ip']} "
                        f"{diff_h:.1f}h after brute force. Likely account compromise."
                    ),
                })
        except Exception:
            continue
    if not combined:
        return 0.0, combined
    avg = sum(c['compound_score'] for c in combined) / len(combined)
    return round(avg, 2), combined


# ── Main pipeline ──────────────────────────────────────────────────────────────

def run_session_idps(
    df: pd.DataFrame,
    high_risk_threshold: float | None = None,
    med_risk_threshold:  float | None = None,
) -> dict[str, Any]:
    """
    Full session anomaly detection pipeline with UBA.

    Output schema (Phase 1 standard):
      status, overall_score, layer_scores,
      features (dict consolidating all signals for bridge correlation),
      alarms (list), behavioral_deviations, combined_risk_alerts,
      baseline_summary

    Args:
        high_risk_threshold: Override for CRITIQUE status threshold (default: module HIGH_RISK_THRESHOLD = 50).
        med_risk_threshold:  Override for AVERTISSEMENT threshold (default: module MED_RISK_THRESHOLD = 25).

    Note: Layer-specific alarm cutoffs (l1 >= 60, l2 >= 40, l4 >= 30) are intentionally
    fixed — they are behavioural detection thresholds, not severity classification thresholds,
    and are not exposed to the agent layer.
    """
    _high = high_risk_threshold if high_risk_threshold is not None else HIGH_RISK_THRESHOLD
    _med  = med_risk_threshold  if med_risk_threshold  is not None else MED_RISK_THRESHOLD
    baseline_manager = BehaviorBaselineManager()
    session_df       = parse_session_logs(df)

    empty: dict[str, Any] = {
        'status':         'no_session_data',
        'overall_score':  0.0,
        'layer_scores':   {},
        'alarms':         [],
        'features': {
            'engine':                'session',
            'attack_vector':         'NONE',
            'post_breach_score':     0.0,
            'privesc_score':         0.0,
            'root_abuse_score':      0.0,
            'behavioral_score':      0.0,
            'combined_risk_score':   0.0,
            'total_events':          0,
            'sudo_events':           0,
            'success_events':        0,
        },
        'baseline_summary': baseline_manager.summary(),
    }
    if session_df.empty:
        return empty

    l1_score, l1_details   = layer1_post_attack_login(session_df)
    l2_score, l2_details   = layer2_privilege_escalation(session_df)
    l3_score, l3_details   = layer3_root_session_abuse(session_df)
    l4_score, l4_deviations = layer4_behavioral_deviation(session_df, baseline_manager)
    l5_score, l5_combined   = layer5_combined_risk(l1_details, l4_deviations)

    overall = round(
        l1_score * 0.30 + l2_score * 0.20 + l3_score * 0.10 +
        l4_score * 0.20 + l5_score * 0.20, 2,
    )

    alarms: list[dict] = []
    if l1_score >= 60:
        alarms.append({
            'type':     'POST_BREACH_LOGIN',
            'severite': 'CRITIQUE',
            'score':    l1_score,
            'ip':       l1_details.get('success_ip', 'unknown'),
            'message': (
                f"🔴 BREACH CONFIRMED | User: {l1_details.get('success_user')} | "
                f"IP: {l1_details.get('success_ip')} | "
                f"Delay: {l1_details.get('delay_minutes', '?')} min | "
                f"After {l1_details.get('bf_attempt_count')} failures"
            ),
            'details': l1_details,
        })
    if l2_score >= 40:
        cmds = [d['command'] for d in l2_details[:3]]
        alarms.append({
            'type':     'PRIVILEGE_ESCALATION',
            'severite': 'CRITIQUE' if l2_score >= 70 else 'AVERTISSEMENT',
            'score':    l2_score,
            'ip':       'local',
            'message':  (
                f"🟠 PRIVILEGE ESCALATION | Commands: {', '.join(cmds[:2])} | "
                f"Score: {l2_score}/100"
            ),
            'details': l2_details,
        })
    if l4_score >= 30:
        high_dev = [d for d in l4_deviations if d['risk_score'] >= 50]
        if high_dev:
            alarms.append({
                'type':     'BEHAVIORAL_ANOMALY',
                'severite': 'CRITIQUE' if l4_score >= 60 else 'AVERTISSEMENT',
                'score':    l4_score,
                'ip':       high_dev[0].get('ip', 'unknown'),
                'message': (
                    f"🟡 BEHAVIORAL ANOMALY | {len(set(d['user'] for d in high_dev))} user(s) | "
                    f"Score: {l4_score}/100"
                ),
                'details': high_dev[:5],
            })
    for alert in l5_combined:
        alarms.append({
            'type':     'COMPOUND_RISK',
            'severite': alert['severite'],
            'score':    alert['compound_score'],
            'ip':       alert['ip'],
            'message':  alert['message'],
            'details':  alert,
        })

    sev_order = {'CRITIQUE': 0, 'AVERTISSEMENT': 1}
    alarms.sort(key=lambda x: (sev_order.get(x['severite'], 99), -x['score']))

    # ── Standard features dict ─────────────────────────────────────────────
    features: dict[str, Any] = {
        'engine':              'session',
        'attack_vector':       'POST_BREACH' if l1_score >= 60 else 'BEHAVIORAL',
        'post_breach_score':   l1_score,
        'privesc_score':       l2_score,
        'root_abuse_score':    l3_score,
        'behavioral_score':    l4_score,
        'combined_risk_score': l5_score,
        'overall_score':       overall,
        'total_events':        len(session_df),
        'sudo_events':         int((session_df['event_type'] == 'SUDO').sum()),
        'success_events':      int((session_df['event_type'] == 'SSH_SUCCESS').sum()),
        'n_behavioral_deviations': len(l4_deviations),
        'n_compound_alerts':   len(l5_combined),
        'n_suspicious_commands': len(l2_details),
    }

    return {
        'status':            ('CRITIQUE'      if overall >= _high else
                              'AVERTISSEMENT' if overall >= _med  else 'NORMAL'),
        'overall_score':     overall,
        'layer_scores': {
            'post_breach':           l1_score,
            'privilege_escalation':  l2_score,
            'root_abuse':            l3_score,
            'behavioral_deviation':  l4_score,
            'combined_risk':         l5_score,
        },
        'total_events':      len(session_df),
        'sudo_events':       features['sudo_events'],
        'success_events':    features['success_events'],
        'alarms':            alarms,
        'post_breach_details':   l1_details,
        'suspicious_commands':   l2_details,
        'behavioral_deviations': l4_deviations,
        'combined_risk_alerts':  l5_combined,
        'baseline_summary':      baseline_manager.summary(),
        'features':              features,
    }