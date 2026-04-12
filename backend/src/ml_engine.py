"""
ml_engine.py — FINAL v6 (Phase 1 Standardized Output)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SSH Intrusion Detection System — 10-Layer IDPS Pipeline

CHANGE vs v5:
  Every row in the output DataFrame now includes a 'features' column
  (JSON dict) matching the standard cross-engine schema:
    source_ip, weighted_risk_score, action, features, first_seen, last_seen

  This makes correlation with web/ftp/kernel/session engines trivial
  — the bridge just reads 'features' without knowing which engine wrote it.

Layer 1  — Multi-Window Rate Detection      (weight 25%)
Layer 2  — Account Targeting Analysis       (weight 15%)
Layer 3  — Jitter-Aware Timing Detection    (weight 12%)
Layer 4  — IP Persistence / Reputation      (weight  8%)
Layer 5  — Daily Cycle Detection            (weight  5%)
Layer 6  — Server-Wide Botnet Aggregation   (weight  8%)
Layer 7  — Distributed Swarm Detection      (weight  8%)
Layer 8  — IP Reputation Intelligence       (weight  8%)
Layer 9  — ASN / Network Block Clustering   (weight  6%)
Layer 10 — Geo + Time Behavior Analysis     (weight  5%)
+ Isolation Forest (200 estimators)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
from __future__ import annotations

import re
import json
import numpy as np
import pandas as pd

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import MinMaxScaler
    _SKLEARN_AVAILABLE = True
except Exception:
    IsolationForest = None
    MinMaxScaler = None
    _SKLEARN_AVAILABLE = False


# ── Config ─────────────────────────────────────────────────────────────────────
WHITELIST           = ['127.0.0.1', '10.0.0.1', '192.168.1.1']
HIGH_RISK_THRESHOLD = 38
MED_RISK_THRESHOLD  = 22
MIN_FAILURES_LAYER4 = 3

KNOWN_BAD_PREFIXES = [
    '150.183', '207.243', '220.117', '218.188',
    '218.22',  '61.53',   '211.9',   '202.181',
]
HOSTING_PROVIDERS = {
    'DigitalOcean': ['45.55','104.131','138.68','159.65','165.227','167.172','178.62'],
    'OVH':          ['51.75','51.77','51.79','51.81','54.36','137.74','142.4'],
    'Hetzner':      ['5.9','5.161','23.88','65.108','78.46','88.99','95.216'],
    'Vultr':        ['45.32','45.63','45.76','108.61','149.28','207.246'],
    'Linode':       ['45.33','45.56','45.79','66.175','72.14','96.126','139.162'],
    'M247':         ['31.14','37.120','185.220'],
}
ABUSEIPDB_API_KEY = ""

GEO_MAP = {
    'China':   [(58,62),(101,106),(110,120),(121,130),(175,180),(202,203),(210,222)],
    'Korea':   [(58,58),(211,212),(220,222)],
    'Taiwan':  [(59,60),(111,112),(163,164),(202,203),(210,211),(220,221)],
    'Russia':  [(37,38),(46,46),(77,78),(82,83),(85,86),(91,92),(176,178),(185,185),(193,195)],
    'Europe':  [(62,62),(77,80),(82,82),(83,85),(86,86),(87,88),(188,195),(212,213),(217,217)],
    'USA':     [(24,24),(63,68),(69,70),(71,72),(98,99),(107,109),(142,142),(162,162),(192,192),(204,209)],
    'Brazil':  [(177,177),(179,179),(186,187),(189,189),(200,201)],
    'Vietnam': [(113,116),(203,203)],
}
HIGH_RISK_COUNTRIES = {'China', 'Korea', 'Russia', 'Vietnam', 'Brazil', 'Taiwan'}


# ── Extraction helpers ─────────────────────────────────────────────────────────

def extract_ip(content: str):
    m = re.search(r'(\b(?:\d{1,3}\.){3}\d{1,3}\b)', str(content))
    return m.group(1) if m else None


def extract_username(content: str) -> str:
    c = str(content)
    m = re.search(r'\buser=(\w+)', c)
    if m and m.group(1) not in ('unknown', '0'):
        return m.group(1)
    m = re.search(r'for\s+(?:invalid\s+)?user\s+(\w+)', c, re.I)
    if m:
        return m.group(1)
    if 'user=root' in c:
        return 'root'
    return 'unknown'


# ── Layer 1 ────────────────────────────────────────────────────────────────────

def layer1_rate(grp: pd.DataFrame):
    times = grp['timestamp'].sort_values()
    windows = {
        '1min': pd.Timedelta('1min'),
        '5min': pd.Timedelta('5min'),
        '1h':   pd.Timedelta('60min'),
        '24h':  pd.Timedelta('1440min'),
    }
    max_counts = {}
    for name, td in windows.items():
        mx = 0
        for t in times:
            count = ((times - t).abs() <= td).sum()
            mx = max(mx, count)
        max_counts[name] = int(mx)

    score = min(100,
        (max_counts['1min']  / 10)  * 35 +
        (max_counts['5min']  / 30)  * 30 +
        (max_counts['1h']    / 60)  * 20 +
        (max_counts['24h']   / 100) * 15
    )
    return round(score, 2), max_counts


# ── Layer 2 ────────────────────────────────────────────────────────────────────

def layer2_accounts(grp: pd.DataFrame, all_ssh: pd.DataFrame):
    unique_users = grp['Content'].str.extract(r'user[=\s]+(\w+)')[0].nunique()
    targeted     = grp['Content'].str.extract(r'user[=\s]+(\w+)')[0].dropna().unique()
    cross_ip = 0
    for acc in targeted:
        ips_for_acc = all_ssh[all_ssh['Content'].str.contains(acc, na=False)]['source_ip'].nunique()
        cross_ip = max(cross_ip, ips_for_acc)
    score = min(100, unique_users * 15 + cross_ip * 10)
    return round(score, 2)


# ── Layer 3 ────────────────────────────────────────────────────────────────────

def layer3_timing(grp: pd.DataFrame):
    times = grp['timestamp'].sort_values()
    if len(times) < 3:
        return 20.0
    intervals = times.diff().dt.total_seconds().dropna()
    mean_i = intervals.mean()
    std_i  = intervals.std()
    cv     = std_i / mean_i if mean_i > 0 else 1
    regularity = min(100, max(0, (1 - cv) * 100)) if cv < 2 else 0
    interval_range = intervals.max() - intervals.min()
    jitter = min(100, max(0, 100 - (interval_range / 60) * 10))
    try:
        hist, _ = np.histogram(intervals, bins=min(10, len(intervals)))
        hist    = hist[hist > 0] / hist.sum()
        entropy = -np.sum(hist * np.log2(hist))
        entropy_score = min(100, max(0, (1 - entropy / 3.32) * 100))
    except Exception:
        entropy_score = 20.0
    hour_mode_pct = int(times.dt.hour.value_counts().max() / len(times) * 100)
    score = regularity * 0.35 + jitter * 0.25 + entropy_score * 0.25 + hour_mode_pct * 0.15
    return round(score, 2)


# ── Layer 4 ────────────────────────────────────────────────────────────────────

def layer4_reputation(grp: pd.DataFrame):
    times = grp['timestamp'].sort_values()
    total = len(grp)
    days  = max(1, (times.max() - times.min()).days + 1)
    if total < MIN_FAILURES_LAYER4:
        return min(20, total * 5)
    daily_rate        = total / days
    persistence_bonus = days * 3 if daily_rate >= 2 else days * 1
    score             = min(100, daily_rate * 5 + persistence_bonus)
    return round(score, 2)


# ── Layer 5 ────────────────────────────────────────────────────────────────────

def layer5_cycle(grp: pd.DataFrame):
    times       = grp['timestamp'].sort_values()
    days_active = times.dt.date.nunique()
    if days_active < 2 or len(times) < 4:
        return 0.0
    hour_by_day = times.groupby(times.dt.date).apply(lambda x: x.dt.hour.mode().iloc[0])
    hour_std    = hour_by_day.std() if len(hour_by_day) > 1 else 12
    consistency = min(100, max(0, (1 - hour_std / 12) * 100))
    multi_day   = min(100, days_active * 15)
    return round(consistency * 0.6 + multi_day * 0.4, 2)


# ── Layer 6 ────────────────────────────────────────────────────────────────────

def build_server_context(df_ssh: pd.DataFrame) -> pd.DataFrame:
    df = df_ssh.copy()
    df['hour']   = df['timestamp'].dt.floor('h')
    df['subnet'] = df['source_ip'].apply(lambda x: '.'.join(str(x).split('.')[:3]) if x else 'unknown')
    hourly = df.groupby('hour').agg(
        unique_ips_per_hour     = ('source_ip', 'nunique'),
        total_failures_per_hour = ('source_ip', 'count'),
        unique_subnets_per_hour = ('subnet', 'nunique'),
    ).reset_index()
    hourly['avg_failures_per_ip'] = (hourly['total_failures_per_hour'] / hourly['unique_ips_per_hour']).round(2)
    hourly['is_botnet_hour'] = (
        (hourly['unique_ips_per_hour']    >= 3) &
        (hourly['avg_failures_per_ip']    <= 5) &
        (hourly['unique_subnets_per_hour']>= 2)
    ).astype(int)
    return hourly


def layer6_botnet_score(ip: str, grp: pd.DataFrame, server_ctx: pd.DataFrame) -> float:
    grp = grp.copy()
    grp['hour'] = grp['timestamp'].dt.floor('h')
    merged = grp.merge(server_ctx, on='hour', how='left').fillna(0)
    if len(merged) == 0:
        return 0.0
    max_concurrent      = merged['unique_ips_per_hour'].max()
    concurrent_score    = min(100, (max_concurrent / 10) * 100)
    botnet_hours        = merged['is_botnet_hour'].sum()
    botnet_participation = min(100, botnet_hours * 25)
    avg_subnet_diversity = merged['unique_subnets_per_hour'].mean()
    subnet_score        = min(100, (avg_subnet_diversity / 5) * 100)
    own_avg             = len(grp) / max(1, grp['hour'].nunique())
    low_rate_bot_score  = min(100, max(0, (1 - own_avg / 10) * 100)) if own_avg < 5 else 0
    score = (concurrent_score * 0.35 + botnet_participation * 0.30 +
             subnet_score * 0.20 + low_rate_bot_score * 0.15)
    return round(score, 2)


# ── Layer 7 ────────────────────────────────────────────────────────────────────

def build_swarm_context(df_ssh: pd.DataFrame) -> dict:
    df = df_ssh.copy()
    df['w10'] = df['timestamp'].dt.floor('10min')
    df['w1h'] = df['timestamp'].dt.floor('h')
    swarm_10min = df.groupby(['w10', 'username']).agg(
        unique_ips_10min=('source_ip', 'nunique'),
        total_10min=('source_ip', 'count'),
    ).reset_index()
    swarm_1h = df.groupby(['w1h', 'username']).agg(
        unique_ips_1h=('source_ip', 'nunique'),
    ).reset_index()
    density = df.groupby('w10').agg(
        global_failures=('source_ip', 'count'),
        global_unique_ips=('source_ip', 'nunique'),
        usernames_hit=('username', 'nunique'),
    ).reset_index()
    baseline = max(density['global_failures'].median(), 1)
    density['density_ratio']    = (density['global_failures'] / baseline).round(2)
    density['is_density_spike'] = (density['density_ratio'] >= 3).astype(int)
    username_global = df.groupby('username').agg(
        global_unique_ips=('source_ip', 'nunique'),
        global_total=('source_ip', 'count'),
    ).reset_index()
    return {
        'swarm_10min':     swarm_10min,
        'swarm_1h':        swarm_1h,
        'density':         density,
        'username_global': username_global,
        'baseline':        baseline,
    }


def layer7_swarm_score(ip: str, grp: pd.DataFrame, swarm_ctx: dict) -> float:
    grp = grp.copy()
    grp['w10'] = grp['timestamp'].dt.floor('10min')
    grp['w1h'] = grp['timestamp'].dt.floor('h')
    swarm_10min = swarm_ctx['swarm_10min']
    swarm_1h    = swarm_ctx['swarm_1h']
    density     = swarm_ctx['density']
    ug          = swarm_ctx['username_global']
    merged_10   = grp[['w10', 'username']].drop_duplicates().merge(swarm_10min, on=['w10', 'username'], how='left').fillna(0)
    max_concurrent_10 = merged_10['unique_ips_10min'].max()
    swarm_10_score    = min(100, (max_concurrent_10 / 5) * 100)
    merged_1h = grp[['w1h', 'username']].drop_duplicates().merge(swarm_1h, on=['w1h', 'username'], how='left').fillna(0)
    max_concurrent_1h = merged_1h['unique_ips_1h'].max()
    swarm_1h_score    = min(100, (max_concurrent_1h / 10) * 100)
    merged_density    = grp[['w10']].drop_duplicates().merge(density, on='w10', how='left').fillna(0)
    max_density_ratio = merged_density['density_ratio'].max()
    spike_score       = min(100, (max_density_ratio / 3) * 100)
    target_username   = grp['username'].mode().iloc[0] if len(grp) > 0 else 'unknown'
    user_row          = ug[ug['username'] == target_username]
    global_ips        = int(user_row['global_unique_ips'].values[0]) if len(user_row) > 0 else 1
    username_conc_score = min(100, (global_ips / 10) * 100)
    avg_density       = merged_density['density_ratio'].mean()
    abnormality_score = min(100, (avg_density / 2) * 100)
    score = (swarm_10_score * 0.30 + swarm_1h_score * 0.25 + spike_score * 0.20 +
             username_conc_score * 0.15 + abnormality_score * 0.10)
    return round(score, 2)


# ── Layer 8 ────────────────────────────────────────────────────────────────────

def layer8_reputation_score(ip: str) -> tuple:
    score = 15
    for prefix in KNOWN_BAD_PREFIXES:
        if ip.startswith(prefix):
            return max(score, 75), 'KNOWN_BAD'
    for provider, prefixes in HOSTING_PROVIDERS.items():
        for p in prefixes:
            if ip.startswith(p):
                return 65.0, f'HOSTING:{provider}'
    if ABUSEIPDB_API_KEY:
        try:
            import urllib.request
            url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
            req = urllib.request.Request(url, headers={'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'})
            resp = json.loads(urllib.request.urlopen(req, timeout=3).read())
            abuse_score = resp['data']['abuseConfidenceScore']
            if abuse_score > 0:
                return min(100, 15 + abuse_score * 0.85), 'ABUSEIPDB'
        except Exception:
            pass
    return score, 'CLEAN'


# ── Layer 9 ────────────────────────────────────────────────────────────────────

def build_asn_context(df_ssh: pd.DataFrame) -> tuple:
    df = df_ssh.copy()
    df['asn_block'] = df['source_ip'].apply(lambda ip: '.'.join(str(ip).split('.')[:2]))
    df['w1h']       = df['timestamp'].dt.floor('h')
    asn_global  = df.groupby('asn_block').agg(
        unique_ips_in_block   = ('source_ip', 'nunique'),
        total_failures_block  = ('source_ip', 'count'),
    ).reset_index()
    asn_hourly  = df.groupby(['w1h', 'asn_block']).agg(
        ips_per_block_per_hour = ('source_ip', 'nunique'),
    ).reset_index()
    return asn_global, asn_hourly


def layer9_asn_score(ip: str, grp: pd.DataFrame,
                     asn_global: pd.DataFrame, asn_hourly: pd.DataFrame) -> float:
    block     = '.'.join(ip.split('.')[:2])
    row       = asn_global[asn_global['asn_block'] == block]
    global_ips = int(row['unique_ips_in_block'].values[0]) if len(row) > 0 else 1
    global_score = min(100, (global_ips / 3) * 100)
    grp2      = grp.copy()
    grp2['w1h'] = grp2['timestamp'].dt.floor('h')
    merged    = grp2[['w1h']].merge(asn_hourly[asn_hourly['asn_block'] == block], on='w1h', how='left').fillna(0)
    max_hourly = merged['ips_per_block_per_hour'].max()
    hourly_score = min(100, (max_hourly / 5) * 100)
    return round(global_score * 0.6 + hourly_score * 0.4, 2)


# ── Layer 10 ───────────────────────────────────────────────────────────────────

def classify_geo(ip: str) -> str:
    try:
        first = int(ip.split('.')[0])
    except Exception:
        return 'Unknown'
    for country, ranges in GEO_MAP.items():
        for lo, hi in ranges:
            if lo <= first <= hi:
                return country
    return 'Unknown'


def build_geo_context(df_ssh: pd.DataFrame) -> tuple:
    df = df_ssh.copy()
    df['country'] = df['source_ip'].apply(classify_geo)
    df['w1h']     = df['timestamp'].dt.floor('h')
    ip_country    = df[['source_ip', 'country']].drop_duplicates()
    geo_hourly    = df.groupby('w1h').agg(
        unique_countries = ('country', 'nunique'),
        unique_ips       = ('source_ip', 'nunique'),
    ).reset_index()
    return ip_country, geo_hourly


def layer10_geo_score(ip: str, grp: pd.DataFrame,
                      ip_country_df: pd.DataFrame, geo_hourly: pd.DataFrame) -> tuple:
    row     = ip_country_df[ip_country_df['source_ip'] == ip]
    country = row['country'].values[0] if len(row) > 0 else 'Unknown'
    country_score = 60 if country in HIGH_RISK_COUNTRIES else 20
    grp2    = grp.copy()
    grp2['w1h'] = grp2['timestamp'].dt.floor('h')
    merged  = grp2[['w1h']].merge(geo_hourly, on='w1h', how='left').fillna(0)
    max_countries   = merged['unique_countries'].max()
    diversity_score = min(100, (max_countries / 5) * 100)
    hours      = grp['timestamp'].dt.hour
    night_pct  = ((hours >= 0) & (hours <= 6)).mean() * 100
    night_score = min(100, night_pct)
    score = country_score * 0.4 + diversity_score * 0.4 + night_score * 0.2
    return round(score, 2), country


# ── Main IDPS Pipeline ─────────────────────────────────────────────────────────

def run_idps(
    df: pd.DataFrame,
    high_risk_threshold: float | None = None,
    med_risk_threshold:  float | None = None,
) -> pd.DataFrame:
    """
    Full 10-layer IDPS pipeline.
    Output schema (Phase 1 standard):
      source_ip, weighted_risk_score, action, risk_level,
      features (JSON dict), first_seen, last_seen,
      + all individual score columns for backward compatibility.

    Args:
        high_risk_threshold: Override for BLOCK_24H threshold (default: module HIGH_RISK_THRESHOLD = 38).
        med_risk_threshold:  Override for WATCHLIST threshold (default: module MED_RISK_THRESHOLD = 22).
    """
    _high = high_risk_threshold if high_risk_threshold is not None else HIGH_RISK_THRESHOLD
    _med  = med_risk_threshold  if med_risk_threshold  is not None else MED_RISK_THRESHOLD
    df_ssh = df[
        df['Content'].str.contains(
            'authentication failure|check pass', case=False, na=False
        )
    ].copy()
    df_ssh['source_ip'] = df_ssh['Content'].apply(extract_ip)
    df_ssh = df_ssh.dropna(subset=['timestamp', 'source_ip'])
    df_ssh = df_ssh.sort_values('timestamp').reset_index(drop=True)

    if df_ssh.empty:
        return pd.DataFrame()

    df_ssh['username'] = df_ssh['Content'].apply(extract_username)

    server_ctx              = build_server_context(df_ssh)
    swarm_ctx               = build_swarm_context(df_ssh)
    asn_global, asn_hourly  = build_asn_context(df_ssh)
    ip_country_df, geo_hourly = build_geo_context(df_ssh)

    records = []
    for ip, grp in df_ssh.groupby('source_ip'):
        grp = grp.sort_values('timestamp')

        rate_score, rate_windows = layer1_rate(grp)
        acc_score                = layer2_accounts(grp, df_ssh)
        time_score               = layer3_timing(grp)
        rep_score                = layer4_reputation(grp)
        cycle_score              = layer5_cycle(grp)
        botnet_score             = layer6_botnet_score(ip, grp, server_ctx)
        swarm_score              = layer7_swarm_score(ip, grp, swarm_ctx)
        rep8_score, rep8_label   = layer8_reputation_score(ip)
        asn_score                = layer9_asn_score(ip, grp, asn_global, asn_hourly)
        geo_score, country       = layer10_geo_score(ip, grp, ip_country_df, geo_hourly)

        weighted = round(
            rate_score   * 0.25 + acc_score    * 0.15 +
            time_score   * 0.12 + rep_score    * 0.08 +
            cycle_score  * 0.05 + botnet_score * 0.08 +
            swarm_score  * 0.08 + rep8_score   * 0.08 +
            asn_score    * 0.06 + geo_score    * 0.05, 2
        )

        risk_level = ('HIGH'   if weighted >= _high else
                      'MEDIUM' if weighted >= _med  else 'LOW')

        # ── Standard features dict (Phase 1) ─────────────────────────────
        features = {
            'engine':                'ssh_ml',
            'attack_vector':         'SSH',
            'rate':                  rate_score,
            'username_targeting':    acc_score,
            'timing_pattern':        time_score,
            'ip_persistence':        rep_score,
            'daily_cycle':           cycle_score,
            'botnet_aggregation':    botnet_score,
            'swarm_detection':       swarm_score,
            'ip_reputation_l8':      rep8_score,
            'ip_reputation_label':   rep8_label,
            'asn_cluster':           asn_score,
            'geo_risk':              geo_score,
            'country':               country,
            'total_failures':        len(grp),
            'max_per_1min':          rate_windows['1min'],
            'max_per_5min':          rate_windows['5min'],
            'max_per_1h':            rate_windows['1h'],
            'max_per_24h':           rate_windows['24h'],
            'iso_anomaly_flag':      0,   # filled in post-loop
            'iso_anomaly_score':     0.0,
        }

        records.append({
            # ── Standard cross-engine columns ─────────────────────────────
            'source_ip':             ip,
            'weighted_risk_score':   weighted,
            'risk_level':            risk_level,
            'action':                'WHITELISTED',  # placeholder; overwritten below
            'first_seen':            grp['timestamp'].min().strftime('%Y-%m-%d %H:%M'),
            'last_seen':             grp['timestamp'].max().strftime('%Y-%m-%d %H:%M'),
            # ── Individual scores (backward compat) ───────────────────────
            'total_failures':        len(grp),
            'max_per_1min':          rate_windows['1min'],
            'max_per_5min':          rate_windows['5min'],
            'max_per_1h':            rate_windows['1h'],
            'max_per_24h':           rate_windows['24h'],
            'failed_rate_score':          rate_score,
            'username_targeting_score':   acc_score,
            'timing_pattern_score':       time_score,
            'ip_reputation_score':        rep_score,
            'cycle_detection_score':      cycle_score,
            'botnet_aggregation_score':   botnet_score,
            'swarm_detection_score':      swarm_score,
            'ip_reputation_score_l8':     rep8_score,
            'ip_reputation_label':        rep8_label,
            'asn_cluster_score':          asn_score,
            'geo_risk_score':             geo_score,
            'country':                    country,
            'features':                   features,
        })

    feat_df = pd.DataFrame(records).sort_values('weighted_risk_score', ascending=False).reset_index(drop=True)

    # ── Isolation Forest ───────────────────────────────────────────────────────
    ml_cols = [
        'failed_rate_score', 'username_targeting_score', 'timing_pattern_score',
        'ip_reputation_score', 'cycle_detection_score', 'botnet_aggregation_score',
        'swarm_detection_score', 'ip_reputation_score_l8', 'asn_cluster_score',
        'geo_risk_score', 'total_failures',
    ]
    if len(feat_df) >= 5 and _SKLEARN_AVAILABLE:
        X        = feat_df[ml_cols].fillna(0)
        X_scaled = MinMaxScaler().fit_transform(X)
        iso      = IsolationForest(contamination=0.2, random_state=42, n_estimators=200)
        iso_flags  = (iso.fit_predict(X_scaled) == -1).astype(int)
        iso_scores = iso.decision_function(X_scaled).round(4)
        feat_df['iso_anomaly_flag']  = iso_flags
        feat_df['iso_anomaly_score'] = iso_scores
        # Back-fill into features dict
        for i, row in feat_df.iterrows():
            row['features']['iso_anomaly_flag']  = int(iso_flags[i])
            row['features']['iso_anomaly_score']  = float(iso_scores[i])
    else:
        feat_df['iso_anomaly_flag']  = 0
        feat_df['iso_anomaly_score'] = 0.0

    # ── Decision engine ────────────────────────────────────────────────────────
    def decide(row):
        if row['source_ip'] in WHITELIST:
            return 'WHITELISTED'
        if row['weighted_risk_score'] >= _high:
            return 'BLOCK_24H'
        if row['weighted_risk_score'] >= _med:
            return 'WATCHLIST_30MIN'
        return 'MONITOR'

    feat_df['action'] = feat_df.apply(decide, axis=1)
    return feat_df


# ── Model performance ──────────────────────────────────────────────────────────

def get_model_performance(feat_df: pd.DataFrame) -> dict:
    if len(feat_df) < 2:
        return {}
    gt   = ((feat_df['total_failures'] >= 10) | (feat_df['max_per_1min'] >= 5) | (feat_df['max_per_24h'] >= 15)).astype(int)
    pred = (feat_df['weighted_risk_score'] >= HIGH_RISK_THRESHOLD).astype(int)
    tp = int(((pred == 1) & (gt == 1)).sum())
    tn = int(((pred == 0) & (gt == 0)).sum())
    fp = int(((pred == 1) & (gt == 0)).sum())
    fn = int(((pred == 0) & (gt == 1)).sum())
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    fpr       = fp / (fp + tn) if (fp + tn) > 0 else 0
    accuracy  = (tp + tn) / len(feat_df) if len(feat_df) > 0 else 0
    return {
        'total_ips':            len(feat_df),
        'confirmed_attacks':    int(gt.sum()),
        'true_positives':       tp, 'true_negatives': tn,
        'false_positives':      fp, 'false_negatives': fn,
        'precision':            round(precision * 100, 1),
        'recall':               round(recall    * 100, 1),
        'f1_score':             round(f1        * 100, 1),
        'false_positive_rate':  round(fpr       * 100, 1),
        'accuracy':             round(accuracy  * 100, 1),
        'blocked_ips':          int((feat_df['action'] == 'BLOCK_24H').sum()),
        'watchlisted_ips':      int((feat_df['action'] == 'WATCHLIST_30MIN').sum()),
        'iso_anomalies':        int(feat_df.get('iso_anomaly_flag', pd.Series([0])).sum()),
        'botnet_suspects':      int((feat_df['botnet_aggregation_score'] >= 30).sum()),
        'swarm_suspects':       int((feat_df['swarm_detection_score'] >= 40).sum()),
        'known_bad_ips':        int((feat_df['ip_reputation_label'] == 'KNOWN_BAD').sum()),
        'hosting_provider_ips': int(feat_df['ip_reputation_label'].str.startswith('HOSTING').sum()),
        'high_risk_countries':  int((feat_df['country'].isin(HIGH_RISK_COUNTRIES)).sum()),
    }