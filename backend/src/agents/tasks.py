# src/agents/tasks.py — FIXED v2
#
# Fix 1 — declencher_alarme Groq crash (tool_use_failed)
#   ROOT CAUSE: when ip_ok=False, the task passed {alarmes_resumees} directly
#   as alarmes_json. That expands to a large JSON string that Groq truncates
#   mid-token, breaking the tool call schema. The LLM then serializes it as
#   an array instead of a string → GroqException tool_use_failed.
#   FIX: never pass raw alarm JSON into declencher_alarme. Pass a short
#   human-readable summary string that the LLM can copy verbatim.
#
# Fix 2 — analyser_logs receiving the wrong input (TOTAL SUSPECTS: 0)
#   ROOT CAUSE: tache_analyse used {alarmes_resumees} which is a compact
#   agent-input string like "192.168.100.20(0.63,ANOMALIE)". The Analyste
#   passed THAT string to analyser_logs instead of using its own context.
#   FIX: tache_analyse no longer mentions analyser_logs at all. It receives
#   all real metrics directly as template variables and writes 4 lines of
#   analysis from those — no tool call needed.
#
# Fix 3 — tache_collecte looping (lister_logs_s3 called 4x)
#   ROOT CAUSE: agent hits max_iter=1 on the collect task because the task
#   description says "Call lister_logs_s3" which the agent interprets as a
#   multi-step loop. Added explicit "Call it ONCE. Stop after one call."
#   FIX: added hard stop instruction + max_iter guard note.

from crewai import Task
from src.agents.agents import (
    collector_agent, analyst_agent, detector_agent,
    corrector_agent, orchestrator_agent, reporter_agent,
)


# ════════════════════════════════════════════════════════════════════════════
# TASK 0 — DYNAMIC CONFIG
# ════════════════════════════════════════════════════════════════════════════
tache_dynamic_config = Task(
    description=(
        "IDPS orchestrator. Pass 1 done. Output JSON only.\n"
        "STATS: anomalies={nb_anomalies} ip={ip_principale} "
        "spike={is_velocity_spike} velocity={attack_velocity} "
        "pattern={attack_pattern} ips={unique_attacking_ips} "
        "health={health_score}% night={night_ratio}\n"
        "ALARMS: {alarmes_resumees}\n\n"
        "APPLY FIRST MATCHING RULE:\n"
        "R1: anomalies>0,spike=True,velocity>200 "
        "→ ssh_high=25,threat=CRITICAL\n"
        "R2: anomalies>0,pattern=concentrated_attacker,ips<=5 "
        "→ ssh_high=28,escalate=[{ip_principale}],threat=ELEVATED\n"
        "R3: anomalies>0,health<50,spike=True "
        "→ ssh_high=28,threat=ELEVATED\n"
        "R4: anomalies>0,night>0.5 "
        "→ rerun=[session],threat=ELEVATED\n"
        "R5: anomalies=0,spike=True,velocity>300 "
        "→ ssh_high=20,threat=ELEVATED\n"
        "R6: else → all null,threat=NORMAL\n\n"
        'OUTPUT THIS JSON AND NOTHING ELSE:\n'
        '{"ssh_high_risk_threshold":null,"ssh_med_risk_threshold":null,'
        '"web_high_risk_threshold":null,"ftp_high_risk_threshold":null,'
        '"ftp_med_risk_threshold":null,"kernel_high_risk_threshold":null,'
        '"correlation_window_min":null,"escalate_ips":[],"suppress_ips":[],'
        '"rerun_engines":[],"threat_level":"NORMAL",'
        '"reasoning":"one sentence","confidence":0.9}'
    ),
    expected_output="JSON only. No prose before or after.",
    agent=orchestrator_agent,
)


# ════════════════════════════════════════════════════════════════════════════
# TASK 1 — COLLECT
# FIX: "Call it ONCE" pour stopper la boucle 4x
# ════════════════════════════════════════════════════════════════════════════
tache_collecte = Task(
    description=(
        "Server: {serveur_nom}.\n"
        "Call lister_logs_s3 ONCE with prefix=\"processed/\".\n"
        "Do NOT call lire_logs_s3. Do NOT call any other tool.\n"
        "After you receive the file list, immediately write your final answer."
    ),
    expected_output=(
        "3 lines:\n"
        "COUNT:<n>\n"
        "TOP3:<file1>|<file2>|<file3>\n"
        "TREND:<one sentence about error trend>"
    ),
    agent=collector_agent,
)


# ════════════════════════════════════════════════════════════════════════════
# TASK 2 — ANALYSE
# FIX: pas d'appel outil, analyse directe depuis les métriques injectées
# ════════════════════════════════════════════════════════════════════════════
tache_analyse = Task(
    description=(
        "You are the log analyst. Interpret the detection results below.\n"
        "DO NOT call any tool. Write your analysis directly from these facts.\n\n"
        "DETECTION FACTS:\n"
        "  health={health_score}%  status={alert_status}  "
        "pattern={attack_pattern}\n"
        "  entropy={ip_entropy} bits  unique_ips={unique_attacking_ips}\n"
        "  velocity={attack_velocity}  velocity_spike={is_velocity_spike}\n"
        "  night_ratio={night_ratio}\n"
        "  alarms={alarmes_resumees}\n"
        "  pass2_ran={pass2_ran}  agent_config={dynamic_config_summary}\n\n"
        "DECISION RULES — apply these exactly, do not guess:\n"
        "  AUTOMATED if: velocity>100 OR (unique_ips<=5 AND entropy<1.0)\n"
        "  HUMAN if: velocity<20 AND unique_ips>10 AND entropy>2.0\n"
        "  MIXED otherwise\n"
        "  CRITICAL pattern if: spike=True AND velocity>200\n"
        "  CONCENTRATED if: unique_ips<=5 AND entropy<1.5\n"
        "  DISTRIBUTED if: unique_ips>20 OR entropy>3.0\n\n"
        "Write EXACTLY 4 lines, no headers, no bullet points:\n"
        "1. Main threat: state pattern name and whether CRITICAL/HIGH/NORMAL\n"
        "2. Attack origin: state AUTOMATED/HUMAN/MIXED and cite the exact metric values that decided it\n"
        "3. Pass 2: state yes/no and what changed, or 'did not run'\n"
        "4. Next 2h risks: name the top 2 specific risks based on the pattern"
    ),
    expected_output="Exactly 4 lines of analysis. No tool calls.",
    agent=analyst_agent,
)


# ════════════════════════════════════════════════════════════════════════════
# HELPERS — TASK 3
# ════════════════════════════════════════════════════════════════════════════
def _ip_valide(ip: str) -> bool:
    ip = (ip or "").strip()
    return (
        bool(ip)
        and ip.lower() not in {"n/a", "none", "nan", "multiple"}
        and "." in ip
    )


def _build_alarme_summary(
    nb_anomalies: int,
    ip_principale: str,
    alarmes_resumees: str,
) -> str:
    """
    Construit une string courte et sûre à passer comme alarmes_json.
    N'utilise JAMAIS alarmes_resumees directement (peut être un tableau
    JSON brut qui casse le schéma tool call de Groq).
    Max ~60 chars — sous la limite du schéma Groq.
    """
    ip_part = ip_principale if _ip_valide(ip_principale) else "unknown_ip"
    return f"ANOMALIE nb={nb_anomalies} ip={ip_part} severite=AVERTISSEMENT"


# ════════════════════════════════════════════════════════════════════════════
# TASK 3 — DETECT
# FIX: string courte via _build_alarme_summary au lieu de {alarmes_resumees}
# ════════════════════════════════════════════════════════════════════════════
def creer_tache_detection(
    nb_anomalies: int,
    ip_principale: str,
    alarmes_resumees: str,
) -> Task:
    ip_ok = _ip_valide(ip_principale)

    if nb_anomalies > 0 and ip_ok:
        alarme_str = _build_alarme_summary(
            nb_anomalies, ip_principale, alarmes_resumees
        )
        desc = (
            f"Confirmed threats detected. "
            f"anomalies={nb_anomalies} ip={ip_principale}\n"
            f"alarms={alarmes_resumees}\n\n"
            f"Call declencher_alarme ONCE with "
            f"alarmes_json=\"{alarme_str}\".\n"
            "Do not modify the string. Do not pass a JSON array."
        )
        expected = (
            "4 lines after tool call:\n"
            "1. CRITIQUE vs AVERTISSEMENT counts\n"
            "2. Most urgent alarm\n"
            "3. Security score 0-100\n"
            "4. BLOCK / WATCHLIST / MONITOR"
        )

    elif nb_anomalies > 0 and not ip_ok:
        alarme_str = _build_alarme_summary(
            nb_anomalies, ip_principale, alarmes_resumees
        )
        desc = (
            f"Suspicious activity detected but no usable IP address.\n"
            f"anomalies={nb_anomalies}\n\n"
            f"Call declencher_alarme ONCE with "
            f"alarmes_json=\"{alarme_str}\".\n"
            "Do not modify the string. Do not pass a JSON array."
        )
        expected = (
            "3 lines after tool call:\n"
            "1. AVERTISSEMENT count\n"
            "2. Security score 0-100\n"
            "3. MONITOR"
        )

    else:
        desc = (
            "No critical anomaly detected. nb_anomalies=0.\n\n"
            "Call declencher_alarme ONCE with "
            "alarmes_json=\"Aucune alarme critique\".\n"
            "Do not modify the string."
        )
        expected = (
            "3 lines after tool call:\n"
            "1. anomalies=0\n"
            "2. security=100\n"
            "3. NORMAL"
        )

    return Task(description=desc, expected_output=expected, agent=detector_agent)


# Fallback statique (rétro-compat)
tache_detection = Task(
    description=(
        "Triage threats.\n"
        "anomalies={nb_anomalies} ip={ip_principale}\n\n"
        "If nb_anomalies==0:\n"
        "  Call declencher_alarme ONCE with "
        "alarmes_json=\"Aucune alarme critique\".\n"
        "Else:\n"
        "  Call declencher_alarme ONCE with "
        "alarmes_json=\"ANOMALIE nb={nb_anomalies} ip={ip_principale}\".\n"
        "Do not pass a JSON array. Pass a plain string only."
    ),
    expected_output=(
        "3-4 lines after tool call:\n"
        "counts, urgent alarm (if any), security 0-100, action"
    ),
    agent=detector_agent,
)


# ════════════════════════════════════════════════════════════════════════════
# TASK 4 — CORRECT
# ════════════════════════════════════════════════════════════════════════════
def creer_tache_correction(nb_anomalies: int, ip_principale: str) -> Task:
    ip_ok = _ip_valide(ip_principale)

    if nb_anomalies > 0 and ip_ok:
        desc = (
            "Apply corrective action for the top threat.\n"
            "ip={ip_principale} anomalies={nb_anomalies}\n\n"
            "Call appliquer_action_corrective with:\n"
            "  anomalie_json=\"BLOCAGE IP {ip_principale} "
            "brute-force SSH critique\"\n"
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

    return Task(
        description=desc,
        expected_output="Tool call only. No extra prose.",
        agent=corrector_agent,
    )


# Fallback statique (rétro-compat)
tache_correction = Task(
    description=(
        "Apply corrective action for the top threat.\n"
        "ip={ip_principale} anomalies={nb_anomalies}\n\n"
        "Call appliquer_action_corrective with:\n"
        "  anomalie_json=\"BLOCAGE IP {ip_principale} "
        "brute-force SSH critique\"\n"
        "Use the tool exactly once.\n"
        "Do not add any text before or after the tool call."
    ),
    expected_output="Tool call only. No extra prose.",
    agent=corrector_agent,
)


# ════════════════════════════════════════════════════════════════════════════
# TASK 5 — REPORT
# ════════════════════════════════════════════════════════════════════════════
tache_rapport = Task(
    description=(
        "Save final report to S3.\n"
        "Call sauvegarder_rapport_s3 with:\n"
        "\"health={health_score}; anomalies={nb_anomalies}; "
        "pattern={attack_pattern}; "
        "ip={ip_principale}; chains={chain_incidents}; "
        "pass2={pass2_ran}; ts={date}\"\n"
        "Use the tool exactly once.\n"
        "Do not add any text before or after the tool call."
    ),
    expected_output="Tool call only. No extra prose.",
    agent=reporter_agent,
)