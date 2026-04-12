"""
adapter.py — Universal Log Dataset Adapter
═══════════════════════════════════════════════════════════════════
Detects which dataset format is being used and normalizes it to
the standard internal format that ml_engine.py understands.

Supported formats
─────────────────
Format A — Original structured CSV (Linux_2k_log_structured.csv)
  Columns : LineId, Month, Date, Time, Level, Component,
            PID, Content, EventId, EventTemplate
  Timestamps : split across Month / Date / Time columns

Format B — Friend's collected dataset (latest_logs.csv)
  Columns : timestamp, source_ip, type_event, statut, detail, source_log
  Timestamps : broken (all same) — real ones buried inside 'detail'

Format C — Any future raw log file with at least a text column
  Fallback: tries to extract IP + timestamp from any text column

Output (always the same regardless of input format)
────────────────────────────────────────────────────
  timestamp  : datetime64  — real event time
  source_ip  : str         — attacker IP
  Content    : str         — full raw log line (for regex-based layers)
  type_event : str         — SSH_BRUTE_FORCE / WEB_ENUMERATION / etc.
  source_log : str         — auth.log / apache2_access.log / etc.
═══════════════════════════════════════════════════════════════════
"""

import re
import pandas as pd
from datetime import datetime


# ── Timestamp extraction helpers ─────────────────────────────────────────────

def _extract_ts_iso(text: str):
    """Extract ISO8601 timestamp from text: 2026-03-09T06:54:46..."""
    m = re.search(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})', str(text))
    return m.group(1) if m else None


def _extract_ts_apache(text: str):
    """Extract Apache timestamp: [09/Mar/2026:07:13:57 +0000]"""
    m = re.search(r'\[(\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2})', str(text))
    if m:
        try:
            return datetime.strptime(m.group(1), '%d/%b/%Y:%H:%M:%S').strftime('%Y-%m-%d %H:%M:%S')
        except ValueError:
            return None
    return None


def _extract_ip_from_text(text: str):
    """Extract first public-looking IPv4 from any text string."""
    matches = re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', str(text))
    for ip in matches:
        parts = ip.split('.')
        if all(0 <= int(p) <= 255 for p in parts):
            return ip
    return None


# ── Format detection ─────────────────────────────────────────────────────────

def detect_format(df: pd.DataFrame) -> str:
    """
    Returns 'A', 'B', or 'C' based on column signatures.
    A = original Linux_2k structured CSV
    B = friend's collected dataset (latest_logs.csv)
    C = unknown / fallback
    """
    cols = set(df.columns.str.lower().str.strip())

    # Format A: has Month + Time + Content columns
    if {'month', 'time', 'content'}.issubset(cols):
        return 'A'

    # Format B: has type_event + statut + detail + source_log
    if {'type_event', 'statut', 'detail', 'source_log'}.issubset(cols):
        return 'B'

    # Format D: output of friend's transformer() — has Date, Message, IP_Source, Etat
    if {'message', 'ip_source', 'etat', 'service'}.issubset(cols):
        return 'D'

    return 'C'


# ── Format A normalizer ───────────────────────────────────────────────────────

def _normalize_format_a(df: pd.DataFrame) -> pd.DataFrame:
    """
    Normalize Linux_2k_log_structured.csv format.
    Reconstructs proper datetime from Month/Date/Time columns.
    """
    df = df.copy()

    # Fix column name quirk
    df.rename(columns={'EventTemplate;;': 'EventTemplate'}, inplace=True)
    df['Date'] = df['Date'].fillna(0).astype(int)

    df['timestamp'] = pd.to_datetime(
        df['Month'].fillna('Jun').astype(str) + ' ' +
        df['Date'].astype(str) + ' 2024 ' +
        df['Time'].fillna('00:00:00').astype(str),
        format='%b %d %Y %H:%M:%S',
        errors='coerce'
    )

    # Extract IP from Content
    df['source_ip'] = df['Content'].apply(_extract_ip_from_text)

    # Map component → source_log
    def guess_source(comp):
        c = str(comp).lower()
        if 'ftp' in c:   return 'ftp.log'
        if 'sshd' in c or 'pam' in c: return 'auth.log'
        if 'kernel' in c: return 'syslog'
        return 'syslog'

    df['source_log'] = df['Component'].apply(guess_source)

    # Map EventId / Content → type_event
    def guess_event(row):
        c = str(row.get('Content', '')).lower()
        if 'authentication failure' in c or 'check pass' in c or 'failed password' in c:
            return 'SSH_BRUTE_FORCE'
        if 'session opened' in c:
            return 'SSH_SUCCESS'
        if 'connection from' in c and ('ftp' in c or 'ftpd' in c or 'vsftpd' in c or 'proftpd' in c):
            return 'FTP_CONNECTION'
        if 'connection from' in c:
            return 'FTP_CONNECTION'
        if '530 ' in c or 'login incorrect' in c or ('vsftpd' in c and 'fail' in c):
            return 'FTP_AUTH_FAIL'
        if '230 ' in c and ('logged in' in c or 'login ok' in c or 'successful' in c):
            return 'FTP_AUTH_OK'
        if 'alert' in c:
            return 'ALERT'
        return 'SSH_OTHER'

    df['type_event'] = df.apply(guess_event, axis=1)

    return df[['timestamp', 'source_ip', 'Content', 'type_event', 'source_log']]


# ── Format B normalizer ───────────────────────────────────────────────────────

def _normalize_format_b(df: pd.DataFrame) -> pd.DataFrame:
    """
    Normalize friend's collected dataset format.

    Key fix: the 'timestamp' column has a single wrong value (script launch time).
    Real timestamps live inside the 'detail' column — we extract them here.
    """
    df = df.copy()

    def fix_timestamp(row):
        detail = str(row['detail'])
        source = str(row['source_log'])

        # auth.log → ISO8601 format inside detail
        if source == 'auth.log':
            ts = _extract_ts_iso(detail)
            if ts:
                return ts

        # apache2 → Apache CLF format inside detail
        elif 'apache' in source:
            ts = _extract_ts_apache(detail)
            if ts:
                return ts

        # Fallback: try both patterns
        ts = _extract_ts_iso(detail) or _extract_ts_apache(detail)
        return ts  # may be None → will be dropped downstream

    df['timestamp'] = df.apply(fix_timestamp, axis=1)
    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')

    # Use existing source_ip, but fill from detail when NaN
    df['source_ip'] = df['source_ip'].where(
        df['source_ip'].notna(),
        df['detail'].apply(_extract_ip_from_text)
    )

    # Rename detail → Content so ml_engine can regex-parse it
    df.rename(columns={'detail': 'Content'}, inplace=True)

    return df[['timestamp', 'source_ip', 'Content', 'type_event', 'source_log']]


# ── Format C fallback ─────────────────────────────────────────────────────────

def _normalize_format_d(df: pd.DataFrame) -> pd.DataFrame:
    """
    Normalize output of friend's transformer() function.
    Columns: Date, Serveur, Service, Message, EventId, Etat, IP_Source
    This is what df_multi looks like after transformer() + concat in main.py.
    """
    df = df.copy()

    df['timestamp'] = pd.to_datetime(df['Date'], errors='coerce')
    df['source_ip'] = df['IP_Source']
    df['Content']   = df['Message']

    def guess_event(row):
        etat = str(row.get('Etat', '')).lower()
        msg  = str(row.get('Message', '')).lower()
        if 'error' in etat or 'failed password' in msg or 'authentication failure' in msg:
            return 'SSH_BRUTE_FORCE'
        if 'accepted' in msg or 'session opened' in msg:
            return 'SSH_SUCCESS'
        if 'connection from' in msg:
            return 'FTP_CONNECTION'
        return 'SSH_OTHER'

    def guess_source(service):
        s = str(service).lower()
        if 'ftp' in s:    return 'ftp.log'
        if 'kernel' in s: return 'syslog'
        return 'auth.log'

    df['type_event'] = df.apply(guess_event, axis=1)
    df['source_log'] = df['Service'].apply(guess_source)

    return df[['timestamp', 'source_ip', 'Content', 'type_event', 'source_log']]


def _normalize_format_c(df: pd.DataFrame) -> pd.DataFrame:
    """
    Best-effort normalization for unknown formats.
    Tries to find a text column and extract timestamp + IP from it.
    """
    df = df.copy()

    # Find the text column (longest average string length)
    text_col = max(
        df.select_dtypes(include='object').columns,
        key=lambda c: df[c].dropna().astype(str).str.len().mean(),
        default=None
    )
    if text_col is None:
        raise ValueError(
            f"adapter.py: Cannot find a text column in dataset.\n"
            f"Columns available: {df.columns.tolist()}"
        )

    df['Content'] = df[text_col]

    # Try to find an existing timestamp column
    ts_col = next(
        (c for c in df.columns if 'time' in c.lower() or 'date' in c.lower()),
        None
    )
    if ts_col:
        df['timestamp'] = pd.to_datetime(df[ts_col], errors='coerce')
        # If all same value → broken, extract from content instead
        if df['timestamp'].nunique() <= 1:
            df['timestamp'] = df['Content'].apply(
                lambda x: _extract_ts_iso(x) or _extract_ts_apache(x)
            )
            df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    else:
        df['timestamp'] = df['Content'].apply(
            lambda x: _extract_ts_iso(x) or _extract_ts_apache(x)
        )
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')

    # IP
    ip_col = next((c for c in df.columns if 'ip' in c.lower()), None)
    if ip_col:
        df['source_ip'] = df[ip_col].where(
            df[ip_col].notna(),
            df['Content'].apply(_extract_ip_from_text)
        )
    else:
        df['source_ip'] = df['Content'].apply(_extract_ip_from_text)

    df['type_event'] = 'UNKNOWN'
    df['source_log'] = 'unknown'

    return df[['timestamp', 'source_ip', 'Content', 'type_event', 'source_log']]


# ── Public API ────────────────────────────────────────────────────────────────

def normalize(df: pd.DataFrame, verbose: bool = True) -> pd.DataFrame:
    """
    Main entry point. Auto-detects format and returns normalized DataFrame.

    Args:
        df      : Raw DataFrame from pd.read_csv() — any supported format
        verbose : Print detection info

    Returns:
        Normalized DataFrame with columns:
          timestamp, source_ip, Content, type_event, source_log

    Raises:
        ValueError if dataset cannot be parsed at all
    """
    fmt = detect_format(df)

    if verbose:
        print(f"[adapter] Detected format: {fmt}")
        print(f"[adapter] Input shape: {df.shape} | Columns: {df.columns.tolist()}")

    if fmt == 'A':
        result = _normalize_format_a(df)
    elif fmt == 'B':
        result = _normalize_format_b(df)
    elif fmt == 'D':
        result = _normalize_format_d(df)
    else:
        print(f"[adapter] WARNING — Unknown format, using fallback (Format C)")
        result = _normalize_format_c(df)

    if 'DatasetSource' in df.columns:
        result['DatasetSource'] = df['DatasetSource'].values

    # Drop rows with no timestamp at all (unusable for time-based detection)
    before = len(result)
    result = result.dropna(subset=['timestamp'])
    dropped = before - len(result)

    if verbose:
        print(f"[adapter] Output: {len(result)} rows ({dropped} dropped — no timestamp)")
        print(f"[adapter] Timestamp range: {result['timestamp'].min()} -> {result['timestamp'].max()}")
        print(f"[adapter] Unique IPs: {result['source_ip'].nunique()} "
              f"| Null IPs: {result['source_ip'].isna().sum()}")
        if 'type_event' in result.columns:
            print(f"[adapter] Event types: {result['type_event'].value_counts().to_dict()}")

    return result.reset_index(drop=True)


def load_and_normalize(path: str, verbose: bool = True) -> pd.DataFrame:
    """
    Convenience function: read CSV from path and normalize in one call.

    Usage:
        from adapter import load_and_normalize
        df = load_and_normalize("data/latest_logs.csv")
    """
    df_raw = pd.read_csv(path, on_bad_lines='skip')
    return normalize(df_raw, verbose=verbose)
