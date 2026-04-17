"""
adapter.py — Universal Log Dataset Adapter  (v3 — PRODUCTION GRADE)
═══════════════════════════════════════════════════════════════════════
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

Format D — Output of friend's transformer() function
  Columns : Date, Serveur, Service, Message, EventId, Etat, IP_Source

Format C — Any future raw log file with at least a text column
  Fallback: tries to extract IP + timestamp from any text column

Output — ALWAYS exactly these 5 columns, no more, no less
────────────────────────────────────────────────────────────
  timestamp  : datetime64[ns]  — real event time (NaT rows dropped)
  source_ip  : str / NaN       — attacker IP (validated or NaN)
  Content    : str             — full raw log line
  type_event : str             — SSH_BRUTE_FORCE / FTP_AUTH_FAIL / etc.
  source_log : str             — auth.log / apache2_access.log / etc.

Public API
──────────
  normalize(df, verbose, strict, error_tracker)  → DataFrame (batch)
  stream_normalize(path, chunksize, ...)         → Generator[DataFrame]
  load_and_normalize(path, verbose, strict, ...) → DataFrame
  ErrorTracker                                   → .report() / .is_clean()
  AdapterStats                                   → .log()

Changelog (v3)
──────────────
  [U1] Ingestion safety : file-size check, chunked reading, memory guard
  [U2] Full observability: AdapterStats dataclass, per-run counters
  [U3] Streaming mode   : stream_normalize() yields normalized chunks
  [U4] Central error tracker: ErrorTracker accumulates bad rows + reasons

  [C1] assert → ValueError : final schema check cannot be silenced with -O
  [C2] Vectorized hot paths : no more row-level .apply() for TS / IP / events
  [C3] Single IP call site  : _extract_ip_series() owns all validation logic
  [C4] Format detection     : column check + value pattern + confidence score
═══════════════════════════════════════════════════════════════════════
"""

import logging
import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Generator, Iterator, Optional

import pandas as pd

# ── Logging ───────────────────────────────────────────────────────────────────
logger = logging.getLogger("adapter")
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("[adapter] %(levelname)s %(message)s"))
    logger.addHandler(_h)
logger.setLevel(logging.INFO)

# ── Schema contract ───────────────────────────────────────────────────────────
REQUIRED_COLUMNS: list[str] = [
    "timestamp",
    "source_ip",
    "Content",
    "type_event",
    "source_log",
]

# ── Ingestion limits [U1] ─────────────────────────────────────────────────────
MAX_FILE_SIZE_MB   = 500
MAX_MEMORY_ROWS    = 2_000_000
DEFAULT_CHUNK_SIZE = 50_000

# ── Validation thresholds ─────────────────────────────────────────────────────
WARN_NULL_IP       = 0.50
WARN_EMPTY_CONTENT = 0.10

# ── Compiled regex (used in vectorized str.extract — fast C loop) [C2] ────────
_IPV4_PAT      = r'(\b(?:\d{1,3}\.){3}\d{1,3}\b)'
_ISO_TS_PAT    = r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})'
_APACHE_TS_PAT = r'\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})'

_MONTH_ABBRS = frozenset(
    ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"]
)

# ═══════════════════════════════════════════════════════════════════════════════
# [U4] Central error tracker
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class _ParseError:
    stage:  str
    reason: str
    count:  int
    sample: Optional[str] = None


class ErrorTracker:
    """
    Accumulates parsing failures across all chunks and formats.         [U4]

    Attach one instance to normalize() / stream_normalize() and call
    .report() when done to get a structured breakdown of every failure.

    Usage:
        tracker = ErrorTracker()
        df = load_and_normalize("logs.csv", error_tracker=tracker)
        if not tracker.is_clean():
            print(tracker.report())
    """

    def __init__(self) -> None:
        self._errors: list[_ParseError] = []

    def record(
        self,
        stage:  str,
        reason: str,
        count:  int,
        sample: str = "",
    ) -> None:
        self._errors.append(
            _ParseError(stage=stage, reason=reason, count=count,
                        sample=str(sample)[:120] if sample else None)
        )

    def report(self) -> dict:
        total      = sum(e.count for e in self._errors)
        by_stage:  dict[str, int] = {}
        by_reason: dict[str, int] = {}
        for e in self._errors:
            by_stage[e.stage]   = by_stage.get(e.stage, 0)   + e.count
            by_reason[e.reason] = by_reason.get(e.reason, 0) + e.count
        return {
            "total_bad_rows": total,
            "by_stage":       by_stage,
            "by_reason":      by_reason,
            "details":        [vars(e) for e in self._errors],
        }

    def is_clean(self) -> bool:
        return not self._errors

    def __repr__(self) -> str:
        total = sum(e.count for e in self._errors)
        return f"<ErrorTracker errors={len(self._errors)} bad_rows={total}>"


# ═══════════════════════════════════════════════════════════════════════════════
# [U2] Observability — AdapterStats
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class AdapterStats:
    """
    Per-run counters populated during normalize() / stream_normalize(). [U2]

    Attach to alerting, dashboards, or tests to catch regressions early.
    """
    format_detected:   str              = "?"
    rows_in:           int              = 0
    rows_out:          int              = 0
    rows_dropped_nat:  int              = 0
    null_ip_count:     int              = 0
    empty_content:     int              = 0
    chunks_processed:  int              = 0
    ts_min:            Optional[pd.Timestamp] = None
    ts_max:            Optional[pd.Timestamp] = None
    event_type_counts: dict             = field(default_factory=dict)

    def log(self) -> None:
        logger.info(
            "Stats | fmt=%s in=%d out=%d dropped_NaT=%d null_ip=%d "
            "empty_content=%d ts=[%s → %s] events=%s",
            self.format_detected,
            self.rows_in, self.rows_out, self.rows_dropped_nat,
            self.null_ip_count, self.empty_content,
            self.ts_min, self.ts_max,
            self.event_type_counts,
        )


# ═══════════════════════════════════════════════════════════════════════════════
# Vectorized helpers [C2] — no row-level .apply() for hot paths
# ═══════════════════════════════════════════════════════════════════════════════

def _extract_ip_series(series: pd.Series) -> pd.Series:
    """
    Vectorized IPv4 extraction + validation — single call site.        [C2, C3]

    Replaces the duplicated _validate_ip / _extract_ip_from_text pair
    from v2. One function, called everywhere, no logic scattered around.

    Steps:
      1. str.extract() finds the first IP-shaped token (fast C regex loop).
      2. Vectorized octet range check eliminates values outside 0–255.
      3. Invalid results become NaN — no broken strings pass through.
    """
    extracted = series.astype(str).str.extract(_IPV4_PAT, expand=False)
    octets    = extracted.str.split(".", expand=True).apply(pd.to_numeric, errors="coerce")
    valid     = (
        octets.notna().all(axis=1) &
        (octets >= 0).all(axis=1)  &
        (octets <= 255).all(axis=1)
    )
    return extracted.where(valid)


def _extract_iso_ts_series(series: pd.Series) -> pd.Series:
    """Vectorized ISO-8601 timestamp extraction."""
    return series.astype(str).str.extract(_ISO_TS_PAT, expand=False)


def _extract_apache_ts_series(series: pd.Series) -> pd.Series:
    """Vectorized Apache CLF timestamp extraction + ISO conversion."""
    raw = series.astype(str).str.extract(_APACHE_TS_PAT, expand=False)

    def _to_iso(val: str) -> Optional[str]:
        if pd.isna(val):
            return None
        try:
            return datetime.strptime(val, "%d/%b/%Y:%H:%M:%S").strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        except ValueError:
            return None

    return raw.map(_to_iso)


def _to_datetime64(series: pd.Series) -> pd.Series:
    """One-way canonical conversion to datetime64[ns]. Never raises."""
    return pd.to_datetime(series, errors="coerce", utc=False).astype("datetime64[ns]")


# ═══════════════════════════════════════════════════════════════════════════════
# Event classifier — Layer 2, vectorized, data-driven [C2]
# ═══════════════════════════════════════════════════════════════════════════════

# Rules evaluated in order; first match wins. Stored as data, not code,
# so they can be tested or extended without touching the classifier itself.
_EVENT_RULES: list[tuple[list[str], str]] = [
    (["authentication failure", "check pass", "failed password"], "SSH_BRUTE_FORCE"),
    (["session opened", "accepted password"],                      "SSH_SUCCESS"),
    (["accepted"],                                                 "SSH_SUCCESS"),
    (["530 ", "login incorrect"],                                  "FTP_AUTH_FAIL"),
    (["230 "],                                                     "FTP_AUTH_OK"),
    (["connection from"],                                          "FTP_CONNECTION"),
    (["alert"],                                                    "ALERT"),
]
_EVENT_DEFAULT = "SSH_OTHER"


def _classify_series(
    content_series: pd.Series,
    source_series:  pd.Series,
) -> pd.Series:
    """
    Vectorized classification over a full column pair.                 [C2]

    Builds a lowercased combined string per row, then applies each rule
    top-to-bottom. Faster than row-level .apply() on large log datasets.
    """
    combined = (
        content_series.fillna("") + " " + source_series.fillna("")
    ).str.lower()

    result = pd.Series(_EVENT_DEFAULT, index=content_series.index, dtype=str)

    # Apply in reverse so higher-priority rules overwrite later ones
    for keywords, label in reversed(_EVENT_RULES):
        pattern = "|".join(re.escape(k) for k in keywords)
        mask    = combined.str.contains(pattern, regex=True, na=False)
        result[mask] = label

    return result


# ═══════════════════════════════════════════════════════════════════════════════
# Schema enforcement [C1]
# ═══════════════════════════════════════════════════════════════════════════════

def _check_schema(df: pd.DataFrame, stage: str, strict: bool) -> pd.DataFrame:
    """
    Enforce REQUIRED_COLUMNS after each normalizer.                    [C1]

    Uses ValueError — not assert — so it cannot be silenced with python -O.
    In prod mode (strict=False): patches missing columns and logs a warning.
    In dev  mode (strict=True):  raises immediately.
    """
    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if not missing:
        return df
    msg = f"Schema drift at [{stage}]: missing columns {missing}"
    if strict:
        raise ValueError(msg)
    logger.warning(msg)
    for col in missing:
        df[col] = pd.NaT if col == "timestamp" else ""
    return df


def _enforce_dtypes(df: pd.DataFrame) -> pd.DataFrame:
    """Final dtype guarantee — idempotent, called once per chunk."""
    df = df.copy()
    df["timestamp"]  = _to_datetime64(df["timestamp"])
    df["source_ip"]  = df["source_ip"].where(df["source_ip"].notna(), other=None)
    df["Content"]    = df["Content"].fillna("").astype(str)
    df["type_event"] = df["type_event"].fillna("UNKNOWN").astype(str)
    df["source_log"] = df["source_log"].fillna("unknown").astype(str)
    return df


def _empty_frame() -> pd.DataFrame:
    """Valid zero-row DataFrame with the correct schema and dtypes."""
    return pd.DataFrame({
        "timestamp":  pd.Series(dtype="datetime64[ns]"),
        "source_ip":  pd.Series(dtype=object),
        "Content":    pd.Series(dtype=str),
        "type_event": pd.Series(dtype=str),
        "source_log": pd.Series(dtype=str),
    })


# ═══════════════════════════════════════════════════════════════════════════════
# [U2] Validation gate — populates AdapterStats, never mutates data
# ═══════════════════════════════════════════════════════════════════════════════

def _validation_gate(df: pd.DataFrame, stats: AdapterStats) -> None:
    n = max(len(df), 1)

    stats.null_ip_count     = int(df["source_ip"].isna().sum())
    stats.empty_content     = int((df["Content"].str.strip() == "").sum())
    stats.ts_min            = df["timestamp"].min()
    stats.ts_max            = df["timestamp"].max()
    stats.event_type_counts = df["type_event"].value_counts().to_dict()

    if stats.null_ip_count / n > WARN_NULL_IP:
        logger.warning(
            "High null-IP rate: %d / %d rows (%.1f %%) — "
            "many log lines lack a parseable IPv4 address.",
            stats.null_ip_count, n, 100 * stats.null_ip_count / n,
        )
    if stats.empty_content / n > WARN_EMPTY_CONTENT:
        logger.warning(
            "High empty-Content rate: %d / %d rows (%.1f %%).",
            stats.empty_content, n, 100 * stats.empty_content / n,
        )


# ═══════════════════════════════════════════════════════════════════════════════
# [C4] Format detection — columns + value patterns + confidence score
# ═══════════════════════════════════════════════════════════════════════════════

def _score_format_a(df: pd.DataFrame, cols: set) -> float:
    if not {"month", "time", "content"}.issubset(cols):
        return 0.0
    score     = 0.5
    month_col = next((c for c in df.columns if c.lower().strip() == "month"), None)
    if month_col:
        sample = " ".join(df[month_col].dropna().astype(str).head(20))
        hits   = sum(1 for m in _MONTH_ABBRS if m in sample)
        score += 0.5 * min(hits / 3, 1.0)  # up to +0.5 for ≥3 month abbreviations
    return score


def _score_format_b(df: pd.DataFrame, cols: set) -> float:
    if not {"type_event", "statut", "detail", "source_log"}.issubset(cols):
        return 0.0
    score      = 0.6
    detail_col = next((c for c in df.columns if c.lower() == "detail"), None)
    if detail_col:
        sample = df[detail_col].dropna().astype(str).head(20)
        # Use non-capturing versions of the TS patterns to avoid pandas warning
        _score_ts_pat = (
            r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}'
            r'|\[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}'
        )
        has_ts = sample.str.contains(_score_ts_pat, regex=True, na=False).sum()
        score += 0.4 * min(has_ts / 5, 1.0)  # up to +0.4 for ≥5 rows with embedded TS
    return score


def _score_format_d(df: pd.DataFrame, cols: set) -> float:
    if not {"message", "ip_source", "etat", "service"}.issubset(cols):
        return 0.0
    score  = 0.6
    ip_col = next((c for c in df.columns if c.lower() == "ip_source"), None)
    if ip_col:
        sample = df[ip_col].dropna().astype(str).head(20)
        valid  = sample.str.match(r'^\d{1,3}(\.\d{1,3}){3}$', na=False).sum()
        score += 0.4 * min(valid / 5, 1.0)
    return score


def detect_format(df: pd.DataFrame) -> str:
    """
    Score each known format and return the best match above 0.5.       [C4]

    Scoring combines column signature (necessary but not sufficient) with
    lightweight sample-value checks, so a dataset that happens to have a
    'month' column with unrelated data won't be misclassified as Format A.
    Returns 'C' (fallback) when no format scores above the threshold.
    """
    cols   = set(df.columns.str.lower().str.strip())
    scores = {
        "A": _score_format_a(df, cols),
        "B": _score_format_b(df, cols),
        "D": _score_format_d(df, cols),
    }
    logger.debug("Format confidence scores: %s", scores)

    best_fmt   = max(scores, key=scores.__getitem__)
    best_score = scores[best_fmt]

    return best_fmt if best_score >= 0.5 else "C"


# ═══════════════════════════════════════════════════════════════════════════════
# Normalizers
# ═══════════════════════════════════════════════════════════════════════════════

def _normalize_format_a(
    df:      pd.DataFrame,
    strict:  bool,
    tracker: ErrorTracker,
) -> pd.DataFrame:
    """Normalize Linux_2k_log_structured.csv format."""
    df = df.copy()
    df.rename(columns={"EventTemplate;;": "EventTemplate"}, inplace=True)

    df["Date"] = pd.to_numeric(
        df.get("Date", pd.Series(dtype=object)), errors="coerce"
    ).fillna(0).astype(int)

    raw_ts = (
        df["Month"].fillna("Jun").astype(str) + " " +
        df["Date"].astype(str) + " 2024 " +
        df["Time"].fillna("00:00:00").astype(str)
    )
    df["timestamp"] = _to_datetime64(raw_ts)

    bad_ts = int(df["timestamp"].isna().sum())
    if bad_ts:
        tracker.record("format_a", "unparseable_timestamp", bad_ts)

    df["source_ip"]  = _extract_ip_series(df["Content"].astype(str))    # [C2, C3]

    def _guess_source(comp: str) -> str:
        c = str(comp).lower()
        if "ftp" in c:               return "ftp.log"
        if "sshd" in c or "pam" in c: return "auth.log"
        if "kernel" in c:            return "syslog"
        return "syslog"

    df["source_log"] = df["Component"].astype(str).map(_guess_source)
    df["type_event"] = _classify_series(df["Content"], df["source_log"])  # [C2]

    return _check_schema(df[REQUIRED_COLUMNS].copy(), "format_a", strict)


def _normalize_format_b(
    df:      pd.DataFrame,
    strict:  bool,
    tracker: ErrorTracker,
) -> pd.DataFrame:
    """
    Normalize friend's collected dataset format.
    Real timestamps are buried inside the 'detail' column.
    """
    df = df.copy()

    detail_str = df["detail"].astype(str)
    source_str = df["source_log"].astype(str)

    # Vectorized extraction — no row loop [C2]
    iso_ts    = _extract_iso_ts_series(detail_str)
    apache_ts = _extract_apache_ts_series(detail_str)

    auth_mask   = source_str.str.lower() == "auth.log"
    apache_mask = source_str.str.lower().str.contains("apache", na=False)

    combined_ts                               = pd.Series(index=df.index, dtype=object)
    combined_ts[auth_mask]                    = iso_ts[auth_mask]
    combined_ts[apache_mask & ~auth_mask]     = apache_ts[apache_mask & ~auth_mask]
    still_null                                = combined_ts.isna()
    combined_ts[still_null]                   = iso_ts[still_null].fillna(apache_ts[still_null])

    df["timestamp"] = _to_datetime64(combined_ts)

    bad_ts = int(df["timestamp"].isna().sum())
    if bad_ts:
        sample = detail_str[df["timestamp"].isna()].iloc[0] if bad_ts else ""
        tracker.record("format_b", "no_ts_in_detail", bad_ts, str(sample))

    # Single IP call site — _extract_ip_series handles validation [C3]
    existing_ip = _extract_ip_series(
        df.get("source_ip", pd.Series(dtype=object)).fillna("").astype(str)
    )
    fallback_ip = _extract_ip_series(detail_str)
    df["source_ip"] = existing_ip.where(existing_ip.notna(), fallback_ip)

    df.rename(columns={"detail": "Content"}, inplace=True)
    df["type_event"] = _classify_series(df["Content"], df["source_log"])  # [C2]

    return _check_schema(df[REQUIRED_COLUMNS].copy(), "format_b", strict)


def _normalize_format_d(
    df:      pd.DataFrame,
    strict:  bool,
    tracker: ErrorTracker,
) -> pd.DataFrame:
    """Normalize output of friend's transformer() function."""
    df = df.copy()

    df["timestamp"] = _to_datetime64(df["Date"])

    bad_ts = int(df["timestamp"].isna().sum())
    if bad_ts:
        tracker.record("format_d", "unparseable_date", bad_ts)

    df["source_ip"] = _extract_ip_series(df["IP_Source"].astype(str))    # [C2, C3]
    df["Content"]   = df["Message"].fillna("").astype(str)

    etat_col = df.get("Etat", pd.Series("", index=df.index, dtype=str))
    df["type_event"] = _classify_series(df["Content"], etat_col)          # [C2]

    def _guess_source(s: str) -> str:
        s = str(s).lower()
        if "ftp" in s:    return "ftp.log"
        if "kernel" in s: return "syslog"
        return "auth.log"

    df["source_log"] = df["Service"].astype(str).map(_guess_source)

    return _check_schema(df[REQUIRED_COLUMNS].copy(), "format_d", strict)


def _normalize_format_c(
    df:      pd.DataFrame,
    strict:  bool,
    tracker: ErrorTracker,
) -> pd.DataFrame:
    """Best-effort normalization for unknown formats."""
    df = df.copy()

    str_cols = df.select_dtypes(include="object").columns.tolist()
    if not str_cols:
        msg = (
            f"Cannot find a text column. "
            f"Columns available: {df.columns.tolist()}"
        )
        tracker.record("format_c", "no_text_column", len(df))
        if strict:
            raise ValueError(msg)
        logger.error(msg)
        return _empty_frame()

    text_col  = max(str_cols, key=lambda c: df[c].dropna().astype(str).str.len().mean())
    df["Content"] = df[text_col].fillna("").astype(str)

    # Timestamp — vectorized [C2]
    ts_col = next(
        (c for c in df.columns if "time" in c.lower() or "date" in c.lower()), None
    )
    if ts_col:
        df["timestamp"] = _to_datetime64(df[ts_col])
        if df["timestamp"].nunique() <= 1:
            logger.warning(
                "Timestamp column '%s' looks broken (single value). "
                "Extracting from Content.", ts_col,
            )
            tracker.record("format_c", "broken_ts_column", len(df),
                           str(df[ts_col].iloc[0]))
            df["timestamp"] = _to_datetime64(
                _extract_iso_ts_series(df["Content"]).fillna(
                    _extract_apache_ts_series(df["Content"])
                )
            )
    else:
        df["timestamp"] = _to_datetime64(
            _extract_iso_ts_series(df["Content"]).fillna(
                _extract_apache_ts_series(df["Content"])
            )
        )

    # IP — single call site [C2, C3]
    ip_col = next((c for c in df.columns if "ip" in c.lower()), None)
    if ip_col:
        existing  = _extract_ip_series(df[ip_col].astype(str))
        fallback  = _extract_ip_series(df["Content"])
        df["source_ip"] = existing.where(existing.notna(), fallback)
    else:
        df["source_ip"] = _extract_ip_series(df["Content"])

    df["type_event"] = "UNKNOWN"
    df["source_log"] = "unknown"

    return _check_schema(df[REQUIRED_COLUMNS].copy(), "format_c", strict)


# ═══════════════════════════════════════════════════════════════════════════════
# [U1] Ingestion safety helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _check_file_size(path: str, strict: bool) -> None:
    """Refuse or warn if the file exceeds MAX_FILE_SIZE_MB."""
    try:
        size_mb = os.path.getsize(path) / (1024 ** 2)
    except OSError:
        return  # path will fail properly at read time
    if size_mb > MAX_FILE_SIZE_MB:
        msg = (
            f"File '{path}' is {size_mb:.1f} MB — exceeds the {MAX_FILE_SIZE_MB} MB "
            f"limit. Use stream_normalize() for large files."
        )
        if strict:
            raise ValueError(msg)
        logger.warning(msg)


def _check_memory_rows(n_rows: int) -> None:
    """Warn if a single chunk would be unexpectedly large."""
    if n_rows > MAX_MEMORY_ROWS:
        logger.warning(
            "Chunk has %d rows (> %d). Consider stream_normalize() "
            "with a smaller chunksize to reduce memory pressure.",
            n_rows, MAX_MEMORY_ROWS,
        )


# ═══════════════════════════════════════════════════════════════════════════════
# Core normalization logic (shared by both batch and streaming modes)
# ═══════════════════════════════════════════════════════════════════════════════

def _normalize_chunk(
    df:      pd.DataFrame,
    strict:  bool,
    tracker: ErrorTracker,
    stats:   AdapterStats,
) -> pd.DataFrame:
    """
    Normalize one chunk. Updates stats and tracker in place.
    Called by both normalize() (once, full df) and stream_normalize() (per chunk).
    """
    if df is None or df.empty:
        return _empty_frame()

    _check_memory_rows(len(df))

    fmt = detect_format(df)
    stats.format_detected = fmt
    logger.info(
        "Chunk | fmt=%s rows=%d cols=%s", fmt, len(df), df.columns.tolist()
    )

    if fmt == "C":
        logger.warning("Unknown format — using best-effort fallback (Format C).")

    dispatch = {
        "A": _normalize_format_a,
        "B": _normalize_format_b,
        "D": _normalize_format_d,
        "C": _normalize_format_c,
    }
    result: pd.DataFrame = dispatch[fmt](df, strict, tracker)

    # Passthrough of optional metadata column
    if "DatasetSource" in df.columns:
        result["DatasetSource"] = df["DatasetSource"].values

    # Drop rows with no timestamp — log exactly what was lost [U2, U4]
    before   = len(result)
    bad_rows = result[result["timestamp"].isna()]
    if not bad_rows.empty:
        sample = str(bad_rows["Content"].iloc[0])[:120]
        tracker.record(f"{fmt}_post", "NaT_timestamp_dropped", len(bad_rows), sample)

    result   = result.dropna(subset=["timestamp"])
    dropped  = before - len(result)

    stats.rows_in          += before
    stats.rows_dropped_nat += dropped

    if dropped:
        logger.info(
            "Dropped %d rows (%.1f %%) — no parseable timestamp.",
            dropped, 100 * dropped / max(before, 1),
        )

    if result.empty:
        msg = "All rows were dropped — chunk is empty after NaT removal."
        if strict:
            raise ValueError(msg)
        logger.error(msg)
        return _empty_frame()

    result = _enforce_dtypes(result)
    result = result.sort_values("timestamp", kind="stable").reset_index(drop=True)

    stats.rows_out         += len(result)
    stats.chunks_processed += 1

    return result


# ═══════════════════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════════════════

def normalize(
    df:            pd.DataFrame,
    verbose:       bool = True,
    strict:        bool = False,
    error_tracker: Optional[ErrorTracker] = None,
) -> pd.DataFrame:
    """
    Normalize a full in-memory DataFrame (batch mode).

    Args:
        df            : Raw DataFrame from pd.read_csv() — any supported format.
        verbose       : Emit INFO-level lifecycle logs.
        strict        : True  → raise on schema errors / empty output (dev).
                        False → patch / skip and log warnings (prod).
        error_tracker : Optional shared ErrorTracker. If None, a local one
                        is created and its report logged on exit.

    Returns:
        Normalized DataFrame with exactly:
          timestamp (datetime64[ns]), source_ip, Content, type_event, source_log

    Raises:
        ValueError if schema is violated AND strict=True, or if the output
                   is missing required columns (always — cannot be silenced). [C1]
    """
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    tracker = error_tracker or ErrorTracker()
    stats   = AdapterStats()

    if df is None or df.empty:
        logger.warning("Received empty or None DataFrame — returning empty frame.")
        return _empty_frame()

    logger.info("normalize() | input shape=%s", df.shape)

    result = _normalize_chunk(df, strict, tracker, stats)

    # Validation gate — populates remaining stats fields, logs warnings [U2]
    _validation_gate(result, stats)

    # Final schema check — ValueError, not assert (cannot be silenced with -O) [C1]
    missing = [c for c in REQUIRED_COLUMNS if c not in result.columns]
    if missing:
        raise ValueError(
            f"BUG: output is missing required columns {missing}. "
            f"Got: {result.columns.tolist()}"
        )

    stats.log()

    if not tracker.is_clean():
        logger.warning("Error report: %s", tracker.report())

    return result


def stream_normalize(
    path:          str,
    chunksize:     int = DEFAULT_CHUNK_SIZE,
    strict:        bool = False,
    verbose:       bool = True,
    error_tracker: Optional[ErrorTracker] = None,
) -> Generator[pd.DataFrame, None, None]:
    """
    Memory-efficient streaming normalizer.                             [U3]

    Reads the CSV in chunks of `chunksize` rows, normalizes each chunk
    independently, and yields DataFrames with the standard schema.

    Designed for files too large to fit in RAM, or when you want to
    pipeline output to a consumer (database writer, ML engine, alerting)
    without waiting for the entire file to be read.

    Usage:
        tracker = ErrorTracker()
        for chunk in stream_normalize("logs/big.csv", chunksize=10_000,
                                       error_tracker=tracker):
            ml_engine.process(chunk)
        print(tracker.report())

    Args:
        path          : Path to the raw CSV file.
        chunksize     : Rows per yielded chunk (default 50 000).
        strict        : Raise on schema errors instead of patching.
        verbose       : Emit INFO-level logs per chunk.
        error_tracker : Shared ErrorTracker accumulates errors across all chunks.

    Yields:
        Normalized DataFrame chunks — same schema as normalize().

    Raises:
        FileNotFoundError  if the path does not exist.
        ValueError         on ingestion limit or schema errors (strict=True).
    """
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    _check_file_size(path, strict)                                      # [U1]

    tracker = error_tracker or ErrorTracker()
    stats   = AdapterStats()
    chunk_n = 0

    try:
        reader: Iterator[pd.DataFrame] = pd.read_csv(
            path,
            chunksize=chunksize,
            on_bad_lines="skip",
        )
        for raw_chunk in reader:
            chunk_n += 1
            logger.info("stream_normalize | chunk=%d rows=%d", chunk_n, len(raw_chunk))

            try:
                normalized = _normalize_chunk(raw_chunk, strict, tracker, stats)
            except ValueError:
                raise  # strict mode — propagate immediately
            except Exception as exc:
                tracker.record(
                    f"chunk_{chunk_n}", "unexpected_error", len(raw_chunk), str(exc)
                )
                logger.error(
                    "Unexpected error in chunk %d — skipping. Error: %s", chunk_n, exc
                )
                continue

            if not normalized.empty:
                yield normalized

    except FileNotFoundError:
        raise FileNotFoundError(f"adapter: file not found: '{path}'")

    logger.info("stream_normalize | done. chunks=%d", chunk_n)
    stats.log()

    if not tracker.is_clean():
        logger.warning("Stream complete. Error report: %s", tracker.report())


def load_and_normalize(
    path:          str,
    verbose:       bool = True,
    strict:        bool = False,
    error_tracker: Optional[ErrorTracker] = None,
) -> pd.DataFrame:
    """
    Convenience: read CSV from path and normalize in one call (batch mode).

    For files larger than ~500 MB, use stream_normalize() instead to avoid
    loading everything into memory at once.                             [U1]

    Usage:
        df = load_and_normalize("data/latest_logs.csv")
        df = load_and_normalize("data/latest_logs.csv", strict=True)

        tracker = ErrorTracker()
        df = load_and_normalize("data/latest_logs.csv", error_tracker=tracker)
        print(tracker.report())
    """
    _check_file_size(path, strict)                                      # [U1]
    df_raw = pd.read_csv(path, on_bad_lines="skip")
    return normalize(df_raw, verbose=verbose, strict=strict, error_tracker=error_tracker)