"""
ftp_engine.py — v3 (Phase 1 Standardized + Feature Engineering)
═══════════════════════════════════════════════════════════════════
Detects FTP brute-force, webshell uploads, and data exfiltration.

CHANGES vs v2:
  - Standard output schema: source_ip, weighted_risk_score, action,
    features (dict), first_seen, last_seen
  - Added transfer_ratio: RETR-heavy sessions = data exfil signal
  - Added burst_transfer: large file spike in short window
  - Added upload_diversity: many different uploaded filenames = tooling
  - All layer scores consolidated in 'features' dict

Layers:
  L1 — Fail rate (failures / total events + raw count bonus)
  L2 — User spray (unique usernames targeted)
  L3 — Anonymous login
  L4 — Post-fail success (brute-force cracked)
  L5 — Sensitive file upload (.php, .sh, webshell)
  L6 — Transfer ratio (RETR >> STOR = exfiltration) NEW
  L7 — Burst transfer (sudden spike in file size/count) NEW
═══════════════════════════════════════════════════════════════════
"""
from __future__ import annotations

import re
from datetime import timedelta
from typing import Any

import pandas as pd


# ── Config ─────────────────────────────────────────────────────────────────────
HIGH_RISK_THRESHOLD = 55.0
MED_RISK_THRESHOLD  = 30.0

_FAIL_PAT = re.compile(
    r'530 |login incorrect|authentication failed|failed|refused|'
    r'vsftpd.*fail|proftpd.*fail|530\s+not logged in',
    re.I,
)
_OK_PAT = re.compile(
    r'230 |logged in|login successful|is now logged in|^\s*ok\s+login',
    re.I,
)
_ANON_PAT    = re.compile(r'anonymous|ftp@|anonymous@', re.I)
_SENSITIVE_PAT = re.compile(
    r'\.(php|phtml|jsp|asp|aspx|sh|cgi)\b|webshell|cmd\.exe',
    re.I,
)
_RETR_PAT = re.compile(r'\bRETR\b|download|file\s+download', re.I)
_STOR_PAT = re.compile(r'\bSTOR\b|upload|file\s+upload', re.I)
_SIZE_PAT = re.compile(r'\b(\d{6,})\b')   # bytes: any 6+ digit number


# ── Helpers ────────────────────────────────────────────────────────────────────

def _extract_ip(text: str):
    m = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', str(text))
    if not m:
        return None
    ip = m.group(1)
    parts = ip.split('.')
    return ip if all(0 <= int(p) <= 255 for p in parts) else None


def _extract_ftp_user(text: str) -> str:
    t = str(text)
    for pat in (
        r'USER\s+(\S+)',
        r'user\s+(\S+)\s+from',
        r'Login failed.*user\s+(\S+)',
        r'Failed login.*\b(\w+)\b',
    ):
        m = re.search(pat, t, re.I)
        if m:
            return m.group(1).strip("'\"")[:64]
    return 'unknown'


def _classify_line(row: pd.Series) -> str:
    te = str(row.get('type_event', '')).upper()
    if te in ('FTP_AUTH_FAIL', 'FTP_BRUTE_FORCE'):
        return 'FAIL'
    if te in ('FTP_AUTH_OK', 'FTP_CONNECTION'):
        if _OK_PAT.search(str(row.get('Content', ''))):
            return 'OK'
    c  = str(row.get('Content', '')).lower()
    sl = str(row.get('source_log', '')).lower()
    if 'ftp' not in sl and not any(x in c for x in ('ftpd', 'vsftpd', 'proftpd', 'pure-ftpd')):
        return 'SKIP'
    if _FAIL_PAT.search(c):
        return 'FAIL'
    if _OK_PAT.search(c):
        return 'OK'
    if 'stor' in c or 'upload' in c or 'retr' in c:
        return 'TRANSFER'
    return 'OTHER'


def parse_ftp_logs(df: pd.DataFrame) -> pd.DataFrame:
    if df is None or df.empty:
        return pd.DataFrame()
    text_col = 'Content' if 'Content' in df.columns else None
    if text_col is None:
        return pd.DataFrame()
    mask = (
        df.get('source_log', pd.Series(dtype=str)).astype(str).str.contains('ftp', case=False, na=False) |
        df[text_col].astype(str).str.contains(r'vsftpd|proftpd|pure-ftpd|ftpd|FTP:', case=False, na=False, regex=True)
    )
    sub = df.loc[mask].copy()
    if sub.empty:
        return pd.DataFrame()
    sub['ts'] = pd.to_datetime(sub['timestamp'], errors='coerce')
    sub = sub.dropna(subset=['ts'])
    if sub.empty:
        return pd.DataFrame()
    sub['_kind']             = sub.apply(_classify_line, axis=1)
    sub = sub[sub['_kind'] != 'SKIP']
    if sub.empty:
        return pd.DataFrame()
    sub['ip']                = sub['source_ip'].where(sub['source_ip'].notna(), sub[text_col].apply(_extract_ip))
    sub = sub.dropna(subset=['ip'])
    sub['ftp_user']          = sub[text_col].apply(_extract_ftp_user)
    sub['anon']              = sub[text_col].astype(str).apply(lambda x: bool(_ANON_PAT.search(x)))
    sub['sensitive_transfer']= sub[text_col].astype(str).apply(lambda x: bool(_SENSITIVE_PAT.search(x)))
    sub['is_retr']           = sub[text_col].astype(str).apply(lambda x: bool(_RETR_PAT.search(x)))
    sub['is_stor']           = sub[text_col].astype(str).apply(lambda x: bool(_STOR_PAT.search(x)))
    # Extract transfer size in bytes when present
    sub['transfer_bytes']    = sub[text_col].astype(str).apply(
        lambda x: int(_SIZE_PAT.search(x).group(1)) if _SIZE_PAT.search(x) else 0
    )
    return sub.reset_index(drop=True)


# ── Detection layers ───────────────────────────────────────────────────────────

def _layer_fail_rate(grp: pd.DataFrame) -> float:
    fails = (grp['_kind'] == 'FAIL').sum()
    n     = len(grp)
    if n == 0:
        return 0.0
    return min(100.0, (fails / n) * 100.0 + fails * 3.0)


def _layer_user_spray(grp: pd.DataFrame) -> float:
    users = grp[grp['_kind'] == 'FAIL']['ftp_user'].dropna().unique()
    return min(100.0, len(users) * 12.0)


def _layer_anon(grp: pd.DataFrame) -> float:
    return 45.0 if grp['anon'].any() else 0.0


def _layer_post_fail_success(grp: pd.DataFrame) -> float:
    grp   = grp.sort_values('ts')
    fails = grp[grp['_kind'] == 'FAIL']
    oks   = grp[grp['_kind'] == 'OK']
    if fails.empty or oks.empty:
        return 0.0
    last_fail = fails['ts'].max()
    ok_after  = oks[oks['ts'] > last_fail]
    if ok_after.empty:
        return 0.0
    first_ok = ok_after['ts'].min()
    if (first_ok - last_fail) <= timedelta(minutes=30):
        return min(100.0, 40.0 + len(fails) * 2.0)
    return 0.0


def _layer_sensitive(grp: pd.DataFrame) -> float:
    return 90.0 if grp['sensitive_transfer'].any() else 0.0


def _layer_transfer_ratio(grp: pd.DataFrame) -> float:
    """
    NEW — Detects data exfiltration via download-heavy FTP behavior.

    RETR (download) >> STOR (upload) when an attacker is exfiltrating data.
    A legitimate backup user uploads more than they download.

    Score:
      RETR / total_transfers >= 0.8 → 70–100 (strong exfil signal)
      RETR / total_transfers >= 0.6 → 40–70
      balanced or upload-heavy     → 0–20
    """
    transfers = grp[grp['_kind'] == 'TRANSFER']
    if len(transfers) < 3:
        return 0.0
    retr_n = int(grp['is_retr'].sum())
    stor_n = int(grp['is_stor'].sum())
    total  = retr_n + stor_n
    if total == 0:
        return 0.0
    retr_ratio = retr_n / total
    if retr_ratio >= 0.8 and retr_n >= 3:
        return min(100.0, 70.0 + retr_n * 2.0)
    if retr_ratio >= 0.6:
        return min(70.0, 40.0 + retr_n * 2.0)
    return round(retr_ratio * 20.0, 2)


def _layer_burst_transfer(grp: pd.DataFrame) -> float:
    """
    NEW — Detects sudden high-volume transfer bursts.

    An attacker who gained FTP access will dump files quickly.
    We detect: total bytes transferred in any 5-minute window.

    Score based on peak 5-minute byte volume:
      > 50 MB in 5 min → 80–100
      > 10 MB in 5 min → 50–80
      < 10 MB          → 0–50
    """
    transfer_rows = grp[grp['_kind'] == 'TRANSFER'].copy()
    if len(transfer_rows) < 2 or 'transfer_bytes' not in transfer_rows.columns:
        return 0.0
    transfer_rows = transfer_rows.sort_values('ts')
    window        = pd.Timedelta('5min')
    max_bytes     = 0
    for t in transfer_rows['ts']:
        in_window = transfer_rows[
            (transfer_rows['ts'] >= t) &
            (transfer_rows['ts'] <= t + window)
        ]
        max_bytes = max(max_bytes, int(in_window['transfer_bytes'].sum()))
    if max_bytes == 0:
        return 0.0
    mb = max_bytes / (1024 * 1024)
    if mb >= 50:
        return min(100.0, 80.0 + mb / 10.0)
    if mb >= 10:
        return min(80.0, 50.0 + mb)
    return min(50.0, mb * 5.0)


# ── Main pipeline ──────────────────────────────────────────────────────────────

def run_ftp_idps(
    df: pd.DataFrame,
    high_risk_threshold: float | None = None,
    med_risk_threshold:  float | None = None,
) -> pd.DataFrame:
    """
    Full FTP attack detection pipeline.

    Output schema (Phase 1 standard):
      source_ip, weighted_risk_score, action, risk_level,
      features (dict), first_seen, last_seen,
      + individual score columns for backward compat.

    Args:
        high_risk_threshold: Override for BLOCK_24H threshold (default: module HIGH_RISK_THRESHOLD = 55).
        med_risk_threshold:  Override for WATCHLIST threshold (default: module MED_RISK_THRESHOLD = 30).
    """
    _high = high_risk_threshold if high_risk_threshold is not None else HIGH_RISK_THRESHOLD
    _med  = med_risk_threshold  if med_risk_threshold  is not None else MED_RISK_THRESHOLD
    ftp_df = parse_ftp_logs(df)
    if ftp_df.empty:
        return pd.DataFrame()

    records = []
    for ip, grp in ftp_df.groupby('ip'):
        fail_n = int((grp['_kind'] == 'FAIL').sum())
        if fail_n == 0 and not grp['sensitive_transfer'].any() and not grp['anon'].any():
            continue

        s1 = _layer_fail_rate(grp)
        s2 = _layer_user_spray(grp)
        s3 = _layer_anon(grp)
        s4 = _layer_post_fail_success(grp)
        s5 = _layer_sensitive(grp)
        s6 = _layer_transfer_ratio(grp)
        s7 = _layer_burst_transfer(grp)

        # Revised weights to accommodate new layers
        weighted = round(
            s1 * 0.25 + s2 * 0.20 + s3 * 0.08 +
            s4 * 0.20 + s5 * 0.10 + s6 * 0.10 + s7 * 0.07,
            2,
        )

        risk_level  = ('HIGH'   if weighted >= _high else
                       'MEDIUM' if weighted >= _med  else 'LOW')
        action      = ('BLOCK_24H'       if risk_level == 'HIGH'   else
                       'WATCHLIST_30MIN' if risk_level == 'MEDIUM' else 'MONITOR')

        # Determine most prominent attack type
        if s5 >= 50:
            attack_type = 'FTP_WEBSHELL_UPLOAD'
        elif s6 >= 50 or s7 >= 50:
            attack_type = 'FTP_DATA_EXFIL'
        else:
            attack_type = 'FTP_BRUTE_FORCE'

        ts_first = grp['ts'].min().strftime('%Y-%m-%d %H:%M')
        ts_last  = grp['ts'].max().strftime('%Y-%m-%d %H:%M')

        # ── Standard features dict ────────────────────────────────────────
        features: dict[str, Any] = {
            'engine':                'ftp',
            'attack_vector':         attack_type,
            'fail_rate_score':       s1,
            'user_spray_score':      s2,
            'anon_score':            s3,
            'post_fail_success':     s4,
            'sensitive_transfer':    s5,
            'transfer_ratio':        s6,
            'burst_transfer':        s7,
            'total_failures':        fail_n,
            'unique_users_targeted': int(grp[grp['_kind'] == 'FAIL']['ftp_user'].nunique()),
            'retr_events':           int(grp['is_retr'].sum()),
            'stor_events':           int(grp['is_stor'].sum()),
            'total_bytes_est':       int(grp['transfer_bytes'].sum()),
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
            'attack_type':               attack_type,
            'total_failures':            fail_n,
            'unique_users_targeted':     features['unique_users_targeted'],
            'fail_rate_score':           s1,
            'user_spray_score':          s2,
            'anon_score':                s3,
            'post_fail_success_score':   s4,
            'sensitive_transfer_score':  s5,
            'transfer_ratio_score':      s6,
            'burst_transfer_score':      s7,
            'features':                  features,
        })

    if not records:
        return pd.DataFrame()
    return (
        pd.DataFrame(records)
        .sort_values('weighted_risk_score', ascending=False)
        .reset_index(drop=True)
    )