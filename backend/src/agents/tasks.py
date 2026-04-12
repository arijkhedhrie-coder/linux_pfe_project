# src/agents/tasks.py — FINAL (token-minimized + conditional detection/correction)

from crewai import Task
from src.agents.agents import (
    collector_agent, analyst_agent, detector_agent,
    corrector_agent, orchestrator_agent, reporter_agent,
)

# ════════════════════════════════════════════════════════════════════════════
# TASK 0 — DYNAMIC CONFIG (point fort: JSON strict + utile pour Pass 2)
# ════════════════════════════════════════════════════════════════════════════
tache_dynamic_config = Task(
    description=(
        "IDPS orchestrator. Pass 1 done. Decide if Pass 2 needs changes.\n"
        "STATS: anomalies={nb_anomalies} top_ip={ip_principale} chains={chain_incidents} corr={corr_incidents}\n"
        "ALARMS: {alarmes_resumees}\n"
        "METRICS: health={health_score}% status={alert_status} pattern={attack_pattern} "
        "entropy={ip_entropy} ips={unique_attacking_ips} velocity={attack_velocity} "
        "spike={is_velocity_spike} night={night_ratio}\n"
        "HISTORY: {historical_context}\n\n"
        "RULES (only when clearly needed):\n"
        "- ssh_high_risk_threshold=28 if health<50 AND spike=True\n"
        "- ftp_high_risk_threshold=40 if WEB alarms but no FTP\n"
        "- escalate_ips=[ip] if ip just below BLOCK threshold\n"
        "- rerun_engines=[\"session\"] if SSH alarms but no SESSION\n"
        "- Leave ALL null if nothing needs adjustment\n\n"
        'Respond with ONLY this JSON (no other text):\n'
        '{"ssh_high_risk_threshold":null,"ssh_med_risk_threshold":null,'
        '"web_high_risk_threshold":null,"ftp_high_risk_threshold":null,'
        '"ftp_med_risk_threshold":null,"kernel_high_risk_threshold":null,'
        '"correlation_window_min":null,"escalate_ips":[],"suppress_ips":[],'
        '"rerun_engines":[],"threat_level":"NORMAL","reasoning":"one sentence","confidence":0.9}'
    ),
    expected_output="JSON only. Threshold fields are floats or null.",
    agent=orchestrator_agent,
)

# ════════════════════════════════════════════════════════════════════════════
# TASK 1 — COLLECT (point fort: sortie ultra courte)
# ════════════════════════════════════════════════════════════════════════════
tache_collecte = Task(
    description="Server: {serveur_nom}. Call lister_logs_s3 with prefix=\"processed/\".",
    expected_output=(
        "3 lines:\n"
        "COUNT:<n>\n"
        "TOP3:<file1>|<file2>|<file3>\n"
        "TREND:<one sentence about error trend>"
    ),
    agent=collector_agent,
)

# ════════════════════════════════════════════════════════════════════════════
# TASK 2 — ANALYSE (point fort: 4 lignes max)
# ════════════════════════════════════════════════════════════════════════════
tache_analyse = Task(
    description=(
        "Interpret detection results.\n"
        "health={health_score}% status={alert_status} pattern={attack_pattern} "
        "entropy={ip_entropy} ips={unique_attacking_ips} velocity={attack_velocity} "
        "spike={is_velocity_spike} night={night_ratio}\n"
        "alarms={alarmes_resumees} pass2={pass2_ran} config={dynamic_config_summary}\n\n"
        "Write 4 lines:\n"
        "1. Main threat type and confidence\n"
        "2. Automated or human-driven? Evidence?\n"
        "3. Did Pass 2 change detection vs Pass 1?\n"
        "4. Top 2 risks next 2 hours"
    ),
    expected_output="4 lines.",
    agent=analyst_agent,
)

# ════════════════════════════════════════════════════════════════════════════
# TASK 3 — DETECT (fix binôme: conditionnel pour éviter faux positifs)
# - On garde ton format Groq-safe (tool call dans description, texte dans expected_output)
# - On fournit une factory à utiliser dans main.py pour injecter nb_anomalies/ip réels
# ════════════════════════════════════════════════════════════════════════════
def _ip_valide(ip: str) -> bool:
    ip = (ip or "").strip()
    return bool(ip) and ip.lower() not in {"n/a", "none", "nan", "multiple"} and "." in ip


def creer_tache_detection(nb_anomalies: int, ip_principale: str, alarmes_resumees: str) -> Task:
    ip_ok = _ip_valide(ip_principale)

    if nb_anomalies > 0 and ip_ok:
        desc = (
            "Confirmed threats. anomalies={nb_anomalies} ip={ip_principale}\n"
            "alarms={alarmes_resumees}\n\n"
            "Call declencher_alarme with alarmes_json={alarmes_resumees}."
        )
        expected = (
            "4 lines after tool call:\n"
            "1. CRITIQUE vs AVERTISSEMENT counts\n"
            "2. Most urgent alarm\n"
            "3. Security score 0-100\n"
            "4. BLOCK / WATCHLIST / MONITOR"
        )
    elif nb_anomalies > 0 and not ip_ok:
        # anomalies réelles mais IP pas exploitable -> on reste en avertissement/monitoring
        desc = (
            "Suspicious activity but no usable IP.\n"
            "anomalies={nb_anomalies} ip={ip_principale} alarms={alarmes_resumees}\n\n"
            "Call declencher_alarme with alarmes_json={alarmes_resumees}."
        )
        expected = (
            "3 lines after tool call:\n"
            "1. AVERTISSEMENT count\n"
            "2. Security score 0-100\n"
            "3. MONITOR"
        )
    else:
        # cas normal: ne pas induire une attaque
        desc = (
            "No critical anomaly. nb_anomalies=0.\n"
            "Call declencher_alarme with alarmes_json=\"Aucune alarme critique\"."
        )
        expected = (
            "3 lines after tool call:\n"
            "1. anomalies=0\n"
            "2. security=100\n"
            "3. NORMAL"
        )

    return Task(description=desc, expected_output=expected, agent=detector_agent)


# Fallback statique (si ton code n'appelle pas encore creer_tache_detection)
tache_detection = Task(
    description=(
        "Triage threats.\n"
        "anomalies={nb_anomalies} ip={ip_principale} alarms={alarmes_resumees}\n\n"
        "If nb_anomalies==0: Call declencher_alarme with alarmes_json=\"Aucune alarme critique\".\n"
        "Else: Call declencher_alarme with alarmes_json={alarmes_resumees}."
    ),
    expected_output=(
        "3-4 lines after tool call:\n"
        "counts, urgent alarm (if any), security 0-100, action"
    ),
    agent=detector_agent,
)

# ════════════════════════════════════════════════════════════════════════════
# TASK 4 — CORRECT (fix binôme: conditionnel, en gardant Groq-safe)
# ════════════════════════════════════════════════════════════════════════════
def creer_tache_correction(nb_anomalies: int, ip_principale: str) -> Task:
    ip_ok = _ip_valide(ip_principale)

    if nb_anomalies > 0 and ip_ok:
        desc = (
            "Apply corrective action for the top threat.\n"
            "ip={ip_principale} anomalies={nb_anomalies}\n\n"
            "Call appliquer_action_corrective with:\n"
            "  anomalie_json=\"BLOCAGE IP {ip_principale} brute-force SSH critique\"\n"
            "Use the tool exactly once.\n"
            "Do not add any text before or after the tool call."
        )
    else:
        desc = (
            "No confirmed attack. Normal monitoring.\n\n"
            "Call appliquer_action_corrective with:\n"
            "  anomalie_json=\"SURVEILLANCE NORMALE - aucune action\"\n"
            "Use the tool exactly once.\n"
            "Do not add any text before or after the tool call."
        )

    return Task(description=desc, expected_output="Tool call only. No extra prose.", agent=corrector_agent)


# Fallback statique (rétro-compat)
tache_correction = Task(
    description=(
        "Apply corrective action for the top threat.\n"
        "ip={ip_principale} anomalies={nb_anomalies}\n\n"
        "Call appliquer_action_corrective with:\n"
        "  anomalie_json=\"BLOCAGE IP {ip_principale} brute-force SSH critique\"\n"
        "Use the tool exactly once.\n"
        "Do not add any text before or after the tool call."
    ),
    expected_output="Tool call only. No extra prose.",
    agent=corrector_agent,
)

# ════════════════════════════════════════════════════════════════════════════
# TASK 5 — REPORT (point fort: tool call only)
# ════════════════════════════════════════════════════════════════════════════
tache_rapport = Task(
    description=(
        "Save final report to S3.\n"
        "Call sauvegarder_rapport_s3 with:\n"
        "\"health={health_score}; anomalies={nb_anomalies}; pattern={attack_pattern}; "
        "ip={ip_principale}; chains={chain_incidents}; pass2={pass2_ran}; ts={date}\"\n"
        "Use the tool exactly once.\n"
        "Do not add any text before or after the tool call."
    ),
    expected_output="Tool call only. No extra prose.",
    agent=reporter_agent,
)